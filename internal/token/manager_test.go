package token

import (
	"encoding/hex"
	"testing"
)

func TestHKDFMatchesPyFxA082(t *testing.T) {
	got := hex.EncodeToString(hkdf(make([]byte, 32), "sessionToken", 96))
	want := "cb339b3ae38e8ca7ce73414765fcf866ec6fd00faa48932575b407d1836c6e0106b3bea873cc43aac3506d36baf945399d76539493a48607047f8d210e4aae4029340093ac49debdc559ecaf404674529be06b5106294023aedc1b2362aeb4a6"
	if got != want {
		t.Fatalf("HKDF mismatch\n%s", got)
	}
}
