package token

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func jwtPart(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func TestJWTValidation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	raw := jwtPart(`{"alg":"RS256"}`) + "." + jwtPart(`{"sub":"u","aud":"https://vpn.mozilla.org","iat":1699999990,"nbf":1699999990,"exp":1700000300,"iss":"https://vpn.mozilla.org"}`) + "." + jwtPart("sig")
	if _, e := DecodeAndValidateJWT(raw, "https://vpn.mozilla.org", now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	rawHostIssuer := jwtPart(`{"alg":"RS256"}`) + "." + jwtPart(`{"sub":"u","aud":"vpn.mozilla.org","iat":1699999990,"nbf":1699999990,"exp":1700000300,"iss":"vpn.mozilla.org"}`) + "." + jwtPart("sig")
	if _, e := DecodeAndValidateJWT(rawHostIssuer, "https://vpn.mozilla.org", now, 0); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeAndValidateJWT(raw, "https://other.invalid", now, 0); e == nil {
		t.Fatal("accepted wrong audience")
	}
}

func jwtAt(iat, nbf, exp float64) string {
	return jwtPart(`{"alg":"RS256"}`) + "." + jwtPart(`{"sub":"u","aud":"https://vpn.mozilla.org","iat":`+formatFloat(iat)+`,"nbf":`+formatFloat(nbf)+`,"exp":`+formatFloat(exp)+`,"iss":"https://vpn.mozilla.org"}`) + "." + jwtPart("sig")
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func TestJWTBoundedClockTolerance(t *testing.T) {
	now := time.Unix(1700000000, 0)
	n := float64(now.Unix())
	// nbf tolerance: exactly 30s ahead is accepted, beyond it is not.
	if _, e := DecodeAndValidateJWT(jwtAt(n, n+30, n+3600), "https://vpn.mozilla.org", now, 0); e != nil {
		t.Fatalf("nbf at tolerance rejected: %v", e)
	}
	if _, e := DecodeAndValidateJWT(jwtAt(n, n+31, n+3600), "https://vpn.mozilla.org", now, 0); e == nil {
		t.Fatal("nbf beyond tolerance accepted")
	}
	// iat tolerance: exactly 300s ahead is accepted, beyond it is not.
	if _, e := DecodeAndValidateJWT(jwtAt(n+300, n, n+3600), "https://vpn.mozilla.org", now, 0); e != nil {
		t.Fatalf("iat at tolerance rejected: %v", e)
	}
	if _, e := DecodeAndValidateJWT(jwtAt(n+301, n, n+3600), "https://vpn.mozilla.org", now, 0); e == nil {
		t.Fatal("iat beyond tolerance accepted")
	}
	// Slow local clock: an hour of skew must still fail, not silently pass.
	if _, e := DecodeAndValidateJWT(jwtAt(n+3600, n+3600, n+7200), "https://vpn.mozilla.org", now, 0); e == nil {
		t.Fatal("one-hour future token accepted")
	}
}

func TestJWTMinTTLBoundaryAndExpUnchanged(t *testing.T) {
	now := time.Unix(1700000000, 0)
	n := float64(now.Unix())
	c, e := DecodeAndValidateJWT(jwtAt(n, n, n+120), "https://vpn.mozilla.org", now, 120*time.Second)
	if e != nil {
		t.Fatalf("exact minTTL rejected: %v", e)
	}
	if c.Expires != n+120 {
		t.Fatalf("exp was changed: %v", c.Expires)
	}
	if _, e := DecodeAndValidateJWT(jwtAt(n, n, n+119), "https://vpn.mozilla.org", now, 120*time.Second); e == nil {
		t.Fatal("token below minTTL accepted")
	}
}
