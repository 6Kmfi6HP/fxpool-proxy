package fxa

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// NAMESPACE is the FxA key-derivation namespace prefix. All HKDF/PBKDF2
// "info" and "salt" strings are namespaced under identity.mozilla.com/picl/v1/.
const NAMESPACE = "identity.mozilla.com/picl/v1/"

const (
	// quickStretchV1 iterates the raw password 1000 times (onepw protocol).
	quickStretchV1 = 1000
	// quickStretchV2 iterates the raw password 650000 times.
	quickStretchV2 = 650000

	// quickStretchV1Prefix and quickStretchV2Prefix are the namespaced salt
	// prefixes. The live credentials/status endpoint returns v2 clientSalt
	// values that already carry quickStretchV2Prefix.
	quickStretchV1Prefix = NAMESPACE + "quickStretch:"
	quickStretchV2Prefix = NAMESPACE + "quickStretchV2:"
)

// authPW derives the password verifier sent to /account/login.
//
// v1 salt: identity.mozilla.com/picl/v1/quickStretch:<original email>
// v2 salt: identity.mozilla.com/picl/v1/quickStretchV2:<client salt>
//
// Both derive a quick-stretched key with PBKDF2-HMAC-SHA256, then HKDF it
// with info "authPW". This mirrors fxa-auth-client lib/crypto.ts
// getCredentials / getCredentialsV2.
func DeriveAuthPW(password, salt string, verifierVersion int) ([]byte, error) {
	iter := quickStretchV1
	if verifierVersion == 2 {
		iter = quickStretchV2
	}
	if verifierVersion != 1 && verifierVersion != 2 {
		return nil, errors.New("unsupported verifierVersion")
	}
	if password == "" || !strings.Contains(salt, ":") {
		return nil, errors.New("invalid password or salt")
	}
	quick := pbkdf2.Key([]byte(password), []byte(salt), iter, 32, sha256.New)
	return hkdf(quick, "authPW", 32), nil
}

// hkdf extracts n bytes from secret with info under NAMESPACE and an empty
// salt, mirroring the onepw HKDF construction in fxa-auth-client.
func hkdf(secret []byte, info string, n int) []byte {
	extract := hmac.New(sha256.New, nil)
	extract.Write(secret)
	prk := extract.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write([]byte(NAMESPACE + info))
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// quickStretchSalt builds the v1 or v2 PBKDF2 salt string.
//
// A value that already carries the matching namespace prefix is returned
// verbatim: the live /account/credentials/status endpoint returns v2 clientSalt
// values in fully namespaced form, and prefixing them again would derive a
// wrong authPW.
func quickStretchSalt(verifierVersion int, emailOrSalt string) string {
	if verifierVersion == 2 {
		if strings.HasPrefix(emailOrSalt, quickStretchV2Prefix) {
			return emailOrSalt
		}
		return quickStretchV2Prefix + emailOrSalt
	}
	if strings.HasPrefix(emailOrSalt, quickStretchV1Prefix) {
		return emailOrSalt
	}
	return quickStretchV1Prefix + emailOrSalt
}
