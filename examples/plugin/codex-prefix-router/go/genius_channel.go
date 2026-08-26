package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const geniusMaxAttempts = 6

type geniusPreparedRequest struct {
	URL                string
	Headers            http.Header
	Body               []byte
	HostCallbackID     string
	SessionFingerprint string
}

type geniusTransport interface {
	Open(context.Context, geniusPreparedRequest) (*http.Response, error)
}

type geniusPermit struct {
	probe bool
	epoch uint64
}

type geniusRateChannel struct {
	mu            sync.Mutex
	cooldownUntil time.Time
	probeActive   bool
	probeDone     chan struct{}
	rateEpoch     uint64
}

type geniusRateLimitError struct {
	Attempts int
}

func (e *geniusRateLimitError) Error() string {
	return fmt.Sprintf("genius_modelhub_rate_limited after %d attempts", e.Attempts)
}

var sharedGeniusChannel = &geniusRateChannel{}

func (c *geniusRateChannel) Open(ctx context.Context, prepared geniusPreparedRequest, transport geniusTransport, logRetry bool) (*http.Response, error) {
	if transport == nil {
		return nil, fmt.Errorf("Genius ModelHub transport is unavailable")
	}
	for attempt := 1; attempt <= geniusMaxAttempts; attempt++ {
		permit, errAcquire := c.acquire(ctx)
		if errAcquire != nil {
			return nil, errAcquire
		}
		resp, errOpen := transport.Open(ctx, prepared)
		if errOpen != nil {
			c.complete(permit)
			return nil, errOpen
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			c.complete(permit)
			return resp, nil
		}

		delay, retryAfter := geniusRetryDelay(resp.Header, attempt)
		c.rateLimited(permit, delay)
		if logRetry {
			logGeniusRateLimit(prepared, resp.Header, attempt, delay, retryAfter, attempt == geniusMaxAttempts)
		}
		if errClose := resp.Body.Close(); errClose != nil {
			return nil, fmt.Errorf("close rate-limited Genius ModelHub response: %w", errClose)
		}
		if attempt == geniusMaxAttempts {
			return nil, &geniusRateLimitError{Attempts: geniusMaxAttempts}
		}
	}
	return nil, &geniusRateLimitError{Attempts: geniusMaxAttempts}
}

func (c *geniusRateChannel) acquire(ctx context.Context) (geniusPermit, error) {
	for {
		c.mu.Lock()
		now := time.Now()
		if c.cooldownUntil.IsZero() {
			permit := geniusPermit{epoch: c.rateEpoch}
			c.mu.Unlock()
			return permit, nil
		}
		if now.Before(c.cooldownUntil) {
			wait := time.Until(c.cooldownUntil)
			c.mu.Unlock()
			if errWait := waitGeniusCooldown(ctx, wait); errWait != nil {
				return geniusPermit{}, errWait
			}
			continue
		}
		if !c.probeActive {
			c.probeActive = true
			c.probeDone = make(chan struct{})
			permit := geniusPermit{probe: true, epoch: c.rateEpoch}
			c.mu.Unlock()
			return permit, nil
		}
		done := c.probeDone
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return geniusPermit{}, ctx.Err()
		case <-done:
		}
	}
}

func (c *geniusRateChannel) complete(permit geniusPermit) {
	if !permit.probe {
		return
	}
	c.mu.Lock()
	if c.rateEpoch == permit.epoch {
		c.cooldownUntil = time.Time{}
	}
	c.releaseProbeLocked()
	c.mu.Unlock()
}

func (c *geniusRateChannel) rateLimited(permit geniusPermit, delay time.Duration) {
	c.mu.Lock()
	c.rateEpoch++
	until := time.Now().Add(delay)
	if until.After(c.cooldownUntil) {
		c.cooldownUntil = until
	}
	if permit.probe {
		c.releaseProbeLocked()
	}
	c.mu.Unlock()
}

func (c *geniusRateChannel) releaseProbeLocked() {
	if c.probeActive && c.probeDone != nil {
		close(c.probeDone)
	}
	c.probeActive = false
	c.probeDone = nil
}

func waitGeniusCooldown(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func geniusRetryDelay(headers http.Header, attempt int) (time.Duration, string) {
	raw := strings.TrimSpace(headers.Get("Retry-After"))
	if raw != "" {
		if seconds, errParse := strconv.ParseInt(raw, 10, 64); errParse == nil && seconds >= 0 {
			return time.Duration(seconds) * time.Second, raw
		}
		if retryAt, errParse := http.ParseTime(raw); errParse == nil {
			return max(retryAt.Sub(time.Now()), 0), raw
		}
	}
	shift := min(max(attempt-1, 0), 4)
	base := time.Second * time.Duration(1<<shift)
	jitter := time.Duration(rand.Int63n(int64(base/4) + 1))
	return base + jitter, raw
}

type directGeniusTransport struct {
	client *http.Client
}

func (t directGeniusTransport) Open(ctx context.Context, prepared geniusPreparedRequest) (*http.Response, error) {
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, prepared.URL, bytes.NewReader(prepared.Body))
	if errRequest != nil {
		return nil, fmt.Errorf("create Genius ModelHub request: %w", errRequest)
	}
	req.Header = prepared.Headers.Clone()
	client := t.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("call Genius ModelHub upstream: %w", errDo)
	}
	return resp, nil
}

type hostGeniusTransport struct {
	stream bool
}

type rpcHostHTTPRequest struct {
	HostCallbackID string      `json:"host_callback_id,omitempty"`
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	Headers        http.Header `json:"headers,omitempty"`
	Body           []byte      `json:"body,omitempty"`
}

type rpcHostHTTPStreamResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	StreamID   string      `json:"stream_id"`
}

func (t hostGeniusTransport) Open(_ context.Context, prepared geniusPreparedRequest) (*http.Response, error) {
	req := rpcHostHTTPRequest{
		HostCallbackID: prepared.HostCallbackID,
		Method:         http.MethodPost,
		URL:            prepared.URL,
		Headers:        prepared.Headers,
		Body:           prepared.Body,
	}
	if !t.stream {
		raw, errCall := callHost(pluginabi.MethodHostHTTPDo, req)
		if errCall != nil {
			return nil, fmt.Errorf("call Genius ModelHub through host: %w", errCall)
		}
		var resp pluginapi.HTTPResponse
		if errDecode := json.Unmarshal(raw, &resp); errDecode != nil {
			return nil, fmt.Errorf("decode Genius ModelHub host response: %w", errDecode)
		}
		return &http.Response{StatusCode: resp.StatusCode, Header: resp.Headers.Clone(), Body: io.NopCloser(bytes.NewReader(resp.Body))}, nil
	}
	raw, errCall := callHost(pluginabi.MethodHostHTTPDoStream, req)
	if errCall != nil {
		return nil, fmt.Errorf("open Genius ModelHub host stream: %w", errCall)
	}
	var resp rpcHostHTTPStreamResponse
	if errDecode := json.Unmarshal(raw, &resp); errDecode != nil {
		return nil, fmt.Errorf("decode Genius ModelHub host stream: %w", errDecode)
	}
	if strings.TrimSpace(resp.StreamID) == "" {
		return nil, fmt.Errorf("Genius ModelHub host stream id is unavailable")
	}
	return &http.Response{StatusCode: resp.StatusCode, Header: resp.Headers.Clone(), Body: &hostHTTPStreamBody{streamID: resp.StreamID}}, nil
}
