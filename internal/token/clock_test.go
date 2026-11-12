package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerDateOffset(t *testing.T) {
	want := time.Now().Add(42 * time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", want.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	got, e := ServerDateOffset(context.Background(), srv.Client(), srv.URL)
	if e != nil {
		t.Fatal(e)
	}
	if got < 41*time.Second || got > 43*time.Second {
		t.Fatalf("offset = %s, want about 42s", got)
	}
}

func TestServerDateOffsetMissingDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if _, e := ServerDateOffset(context.Background(), srv.Client(), srv.URL); e == nil {
		t.Fatal("accepted a response without Date")
	}
}
