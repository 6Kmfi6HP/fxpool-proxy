package token

import (
	"encoding/base64"
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
