package token

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ServerDateOffset measures the offset between a trusted HTTPS server's Date
// header and this machine's clock. Positive means the server is ahead.
//
// The HTTP Date header has one-second resolution, so the result is rounded to
// whole seconds and carries up to about one second of measurement error. This
// is an observation only: it must not be used to extend a signed JWT's exp.
func ServerDateOffset(ctx context.Context, client *http.Client, rawurl string) (time.Duration, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawurl, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	mid := start.Add(time.Since(start) / 2)
	v := resp.Header.Get("Date")
	if v == "" {
		return 0, errors.New("response has no Date header")
	}
	server, err := http.ParseTime(v)
	if err != nil {
		return 0, errors.New("invalid Date header")
	}
	return server.Sub(mid).Round(time.Second), nil
}
