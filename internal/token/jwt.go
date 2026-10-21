package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Claims struct {
	Subject   string  `json:"sub"`
	Audience  any     `json:"aud"`
	IssuedAt  float64 `json:"iat"`
	NotBefore float64 `json:"nbf"`
	Expires   float64 `json:"exp"`
	Issuer    string  `json:"iss"`
}

func DecodeAndValidateJWT(raw, guardian string, now time.Time, minTTL time.Duration) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, errors.New("not a JWT")
	}
	decode := func(part string, dst any) error {
		b, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, dst)
	}
	var header map[string]any
	var c Claims
	if err := decode(parts[0], &header); err != nil {
		return c, errors.New("malformed JWT header")
	}
	if err := decode(parts[1], &c); err != nil {
		return c, errors.New("malformed JWT claims")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return c, errors.New("malformed JWT signature")
	}
	alg, _ := header["alg"].(string)
	if alg == "" || strings.EqualFold(alg, "none") {
		return c, errors.New("invalid JWT algorithm")
	}
	if c.Subject == "" || c.Issuer == "" || c.Audience == nil || c.IssuedAt == 0 || c.NotBefore == 0 || c.Expires == 0 {
		return c, errors.New("missing JWT claims")
	}
	if c.Expires <= c.NotBefore || c.IssuedAt > c.Expires {
		return c, errors.New("invalid JWT timestamps")
	}
	n := float64(now.Unix())
	if c.NotBefore > n+30 || c.IssuedAt > n+300 {
		return c, errors.New("JWT is not yet valid")
	}
	if c.Expires-n < minTTL.Seconds() {
		return c, errors.New("JWT has insufficient lifetime")
	}
	g, err := url.Parse(guardian)
	if err != nil {
		return c, err
	}
	issuerHost := ""
	if issuer, parseErr := url.Parse(c.Issuer); parseErr == nil && issuer != nil {
		issuerHost = issuer.Hostname()
	}
	if issuerHost == "" {
		issuerHost = strings.TrimSuffix(strings.ToLower(c.Issuer), "/")
	}
	if !strings.EqualFold(g.Hostname(), issuerHost) {
		return c, fmt.Errorf("unexpected JWT issuer")
	}
	matchAud := false
	switch a := c.Audience.(type) {
	case string:
		matchAud = audienceMatches(a, guardian)
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && audienceMatches(s, guardian) {
				matchAud = true
			}
		}
	}
	if !matchAud {
		return c, errors.New("unexpected JWT audience")
	}
	return c, nil
}

func audienceMatches(a, guardian string) bool {
	au, e1 := url.Parse(a)
	gu, e2 := url.Parse(guardian)
	audience := au.Hostname()
	if audience == "" {
		audience = strings.TrimSuffix(strings.ToLower(a), "/")
	}
	return e1 == nil && e2 == nil && strings.EqualFold(audience, gu.Hostname())
}
