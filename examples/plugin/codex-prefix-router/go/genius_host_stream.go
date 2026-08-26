package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

type rpcHostHTTPStreamReadRequest struct {
	StreamID string `json:"stream_id"`
}

type rpcHostHTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

type rpcHostHTTPStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
}

type rpcHostLogRequest struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Level          string         `json:"level"`
	Message        string         `json:"message"`
	Fields         map[string]any `json:"fields,omitempty"`
}

type hostHTTPStreamBody struct {
	mu       sync.Mutex
	streamID string
	pending  []byte
	done     bool
	closed   bool
}

func (b *hostHTTPStreamBody) Read(dst []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(dst) == 0 {
		return 0, nil
	}
	for len(b.pending) == 0 && !b.done {
		raw, errCall := callHost(pluginabi.MethodHostHTTPStreamRead, rpcHostHTTPStreamReadRequest{StreamID: b.streamID})
		if errCall != nil {
			return 0, fmt.Errorf("read Genius ModelHub host stream: %w", errCall)
		}
		var resp rpcHostHTTPStreamReadResponse
		if errDecode := json.Unmarshal(raw, &resp); errDecode != nil {
			return 0, fmt.Errorf("decode Genius ModelHub host stream chunk: %w", errDecode)
		}
		if strings.TrimSpace(resp.Error) != "" {
			b.done = true
			return 0, fmt.Errorf("Genius ModelHub host stream: %s", resp.Error)
		}
		b.pending = append(b.pending, resp.Payload...)
		b.done = resp.Done
	}
	if len(b.pending) == 0 && b.done {
		return 0, io.EOF
	}
	n := copy(dst, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *hostHTTPStreamBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	_, errCall := callHost(pluginabi.MethodHostHTTPStreamClose, rpcHostHTTPStreamCloseRequest{StreamID: b.streamID})
	if errCall != nil {
		return fmt.Errorf("close Genius ModelHub host stream: %w", errCall)
	}
	return nil
}

func logGeniusRateLimit(prepared geniusPreparedRequest, headers http.Header, attempt int, delay time.Duration, retryAfter string, exhausted bool) {
	fields := map[string]any{
		"provider":            "genius_modelhub",
		"status":              http.StatusTooManyRequests,
		"attempt":             attempt,
		"max_attempts":        geniusMaxAttempts,
		"delay_ms":            delay.Milliseconds(),
		"retry_after":         retryAfter,
		"session_fingerprint": prepared.SessionFingerprint,
	}
	if requestID := geniusRequestID(headers); requestID != "" {
		fields["upstream_request_id"] = requestID
	}
	message := "Genius ModelHub rate limited; scheduling retry"
	if exhausted {
		message = "Genius ModelHub rate limit retry budget exhausted"
	}
	_, _ = callHost(pluginabi.MethodHostLog, rpcHostLogRequest{
		HostCallbackID: prepared.HostCallbackID,
		Level:          "warn",
		Message:        message,
		Fields:         fields,
	})
}

func geniusRequestID(headers http.Header) string {
	for _, key := range []string{"X-Request-Id", "X-Tt-Logid", "X-Bd-Request-Id"} {
		if value := strings.TrimSpace(headers.Get(key)); value != "" {
			return value
		}
	}
	return ""
}
