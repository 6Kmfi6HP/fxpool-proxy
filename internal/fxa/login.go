package fxa

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FxA errno values used by the auth server.
const (
	errnoUnknownAccount     = 102 // account does not exist
	errnoIncorrectPass      = 103 // password wrong
	errnoThrottled          = 114 // too many attempts
	errnoIncorrectEmailCase = 120 // email case mismatch / primary changed
	errnoRequestBlocked     = 125 // request blocked
	errnoTOTPRequired       = 138 // two-factor code required
)

// Session is a successfully authenticated FxA account.
type Session struct {
	Email        string
	UID          string
	SessionToken string // 64-hex, long-lived renewal root
}

// authMeta describes how the account's password verifier is stretched.
type authMeta struct {
	VerifierVersion int
	Salt            string // full quick-stretch salt string
}

// accountStatusResponse is the /account/credentials/status response.
//
// Two shapes are in use. Legacy deployments return verifierVersion with a bare
// clientSalt. The live server returns currentVersion plus a clientSalt that
// already carries the quickStretchV2 namespace:
//
//	{"currentVersion":"v2","clientSalt":"identity.mozilla.com/picl/v1/quickStretchV2:...","upgradeNeeded":false}
type accountStatusResponse struct {
	Email             string `json:"email"`
	CurrentVersion    string `json:"currentVersion"`
	VerifierVersion   int    `json:"verifierVersion"`
	ClientSalt        string `json:"clientSalt"`
	CurrentClientSalt string `json:"currentClientSalt"`
	UpgradeNeeded     bool   `json:"upgradeNeeded"`
}

// accountLoginResponse is the /account/login response.
type accountLoginResponse struct {
	Email              string `json:"email"`
	UID                string `json:"uid"`
	SessionToken       string `json:"sessionToken"`
	Verified           bool   `json:"verified"`
	VerificationMethod string `json:"verificationMethod"`
}

// Login authenticates email+password with the FxA auth server and returns a
// verified session token. It negotiates the v1/v2 key stretch, handles an
// email-case correction, and completes TOTP 2FA when the account requires it.
func (c *Client) Login(ctx context.Context, email, password string) (*Session, error) {
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return nil, errors.New("invalid email address")
	}
	if password == "" {
		return nil, errors.New("password must not be empty")
	}

	// 1. Discover the account's verifier version and salt.
	meta, err := c.accountStatus(ctx, email)
	if err != nil {
		return nil, err
	}

	// 2. Derive authPW and log in. Retry once with the server-corrected email
	//    on an email-case mismatch (errno 120).
	loginEmail := email
	salt, v := meta.Salt, meta.VerifierVersion
	for attempt := 0; ; attempt++ {
		authPW, err := DeriveAuthPW(password, salt, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.loginAttempt(ctx, loginEmail, authPW)
		if err != nil {
			if attempt == 0 && errnoOf(err) == errnoIncorrectEmailCase {
				var e *errnoError
				if errors.As(err, &e) {
					corrected := strings.TrimSpace(e.canonicalEmail())
					if corrected != "" && corrected != loginEmail {
						loginEmail = corrected
						// v1 uses the original signup email for the salt; a
						// corrected primary implies the salt should track it.
						if v == 1 {
							salt = quickStretchSalt(1, corrected)
						}
						continue
					}
				}
			}
			return nil, c.cleanErr(err)
		}

		// 3. TOTP 2FA: verify with a one-time code before the token is usable.
		totpDone := false
		if resp.VerificationMethod == "totp-2fa" {
			if c.TOTPPrompt == nil {
				return nil, errors.New("account requires a two-factor code, but no TOTP input is available")
			}
			code, err := c.TOTPPrompt()
			if err != nil {
				return nil, err
			}
			if err := c.verifyTOTP(ctx, code, resp.SessionToken); err != nil {
				return nil, c.cleanErr(err)
			}
			totpDone = true
		}
		if !resp.Verified && !totpDone {
			return nil, errors.New("account is not verified; complete verification in the browser first")
		}
		if !validSession(resp) {
			return nil, errors.New("FxA login returned an invalid session token")
		}
		return &Session{Email: resp.Email, UID: resp.UID, SessionToken: strings.ToLower(resp.SessionToken)}, nil
	}
}

func (c *Client) accountStatus(ctx context.Context, email string) (authMeta, error) {
	var resp accountStatusResponse
	if err := c.postJSON(ctx, "/account/credentials/status", map[string]string{"email": email}, &resp); err != nil {
		return authMeta{}, c.cleanErr(err)
	}
	return resolveAuthMeta(resp, email)
}

// resolveAuthMeta maps a credentials/status response to the quick-stretch
// parameters used for authPW derivation.
//
// The live v2 response has no verifierVersion field at all, and its clientSalt
// already includes the quickStretchV2 namespace, so the salt must be used
// verbatim rather than prefixed a second time. Legacy responses carrying
// verifierVersion and a bare clientSalt are still accepted; v1 keeps using the
// email as the salt.
func resolveAuthMeta(resp accountStatusResponse, email string) (authMeta, error) {
	version := resp.VerifierVersion
	if version == 0 {
		// No explicit verifierVersion: the live server reports currentVersion.
		// An absent currentVersion keeps the historical v1 fallback.
		switch strings.ToLower(strings.TrimSpace(resp.CurrentVersion)) {
		case "v2":
			version = 2
		case "v1", "":
			version = 1
		default:
			return authMeta{}, fmt.Errorf("unsupported FxA verifier version %q", resp.CurrentVersion)
		}
	}

	salt := resp.CurrentClientSalt
	if salt == "" {
		salt = resp.ClientSalt
	}

	switch version {
	case 2:
		if salt == "" {
			return authMeta{}, errors.New("FxA account requires v2 key stretch but no clientSalt was returned")
		}
		switch {
		case strings.HasPrefix(salt, quickStretchV2Prefix):
			// Already namespaced by the server: use it exactly as returned.
			return authMeta{VerifierVersion: 2, Salt: salt}, nil
		case strings.HasPrefix(salt, quickStretchV1Prefix):
			return authMeta{}, errors.New("invalid v2 clientSalt: v1 quickStretch prefix")
		default:
			return authMeta{VerifierVersion: 2, Salt: quickStretchV2Prefix + salt}, nil
		}
	case 1:
		return authMeta{VerifierVersion: 1, Salt: quickStretchSalt(1, email)}, nil
	default:
		return authMeta{}, fmt.Errorf("unsupported FxA verifier version %d", version)
	}
}

func (c *Client) loginAttempt(ctx context.Context, email string, authPW []byte) (accountLoginResponse, error) {
	var resp accountLoginResponse
	payload := map[string]string{
		"email":  email,
		"authPW": hex.EncodeToString(authPW),
	}
	if err := c.postJSON(ctx, "/account/login", payload, &resp); err != nil {
		return accountLoginResponse{}, err
	}
	resp.Email = email
	return resp, nil
}

func (c *Client) verifyTOTP(ctx context.Context, code, sessionToken string) error {
	if len(code) != 6 {
		return errors.New("TOTP code must be 6 digits")
	}
	return c.postJSON(ctx, "/session/verify/totp", map[string]string{
		"code":         code,
		"sessionToken": sessionToken,
	}, nil)
}

func validSession(resp accountLoginResponse) bool {
	return resp.SessionToken != "" && len(resp.SessionToken) == 64 && resp.UID != ""
}

// cleanErr maps FxA errno to a human-readable message.
func (c *Client) cleanErr(err error) error {
	var e *errnoError
	if !errors.As(err, &e) {
		return err
	}
	// The Fastly WAF rejects POST /account/login (and /account/create) with a
	// bodyless 406. Check the status before the errno switch: the empty body
	// yields errno 0, which would otherwise fall through to the generic error.
	if e.status == 406 {
		return fmt.Errorf("%w: password login is not possible from this network; create the account "+
			"with the register machine and run: fxpool-proxy import-credentials <bundle>", ErrWAFBlocked)
	}
	switch e.errno {
	case errnoUnknownAccount:
		return errors.New("no Firefox Account exists for that email")
	case errnoIncorrectPass:
		return errors.New("incorrect email or password")
	case errnoThrottled:
		if e.retry > 0 {
			return fmt.Errorf("too many login attempts; try again in %s", e.retry.Round(time.Second))
		}
		return errors.New("too many login attempts; try again later")
	case errnoTOTPRequired:
		return errors.New("a two-factor code is required")
	case errnoRequestBlocked:
		return errors.New("request blocked by FxA")
	default:
		return err
	}
}
