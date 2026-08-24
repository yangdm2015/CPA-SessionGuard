package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const warmSessionBindingTTL = 10 * time.Minute

type warmSessionBinding struct {
	responseID string
	expiresAt  time.Time
}

type warmSessionBindings struct {
	mu      sync.Mutex
	entries map[string]warmSessionBinding
}

func newWarmSessionBindings() *warmSessionBindings {
	return &warmSessionBindings{entries: make(map[string]warmSessionBinding)}
}

func (b *warmSessionBindings) prepare(req pluginapi.ExecutorRequest) (pluginapi.ExecutorRequest, string, error) {
	sessionKey := warmSessionKey(req)
	if sessionKey == "" {
		return req, "", nil
	}
	body := req.OriginalRequest
	if len(body) == 0 {
		body = req.Payload
	}
	if len(body) == 0 {
		return req, sessionKey, nil
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return req, sessionKey, errUnmarshal
	}
	if strings.TrimSpace(stringValue(payload["previous_response_id"])) != "" {
		return req, sessionKey, nil
	}
	previousResponseID := b.latest(sessionKey)
	if previousResponseID == "" {
		return req, sessionKey, nil
	}
	payload["previous_response_id"] = previousResponseID
	preparedBody, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return req, sessionKey, errMarshal
	}
	req.OriginalRequest = preparedBody
	req.Payload = preparedBody
	return req, sessionKey, nil
}

func (b *warmSessionBindings) latest(sessionKey string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	binding, ok := b.entries[sessionKey]
	if !ok {
		return ""
	}
	if time.Now().After(binding.expiresAt) {
		delete(b.entries, sessionKey)
		return ""
	}
	return binding.responseID
}

func (b *warmSessionBindings) recordResponse(sessionKey string, body []byte) {
	var payload struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return
	}
	b.recordID(sessionKey, payload.ID)
}

func (b *warmSessionBindings) recordID(sessionKey, responseID string) {
	sessionKey = strings.TrimSpace(sessionKey)
	responseID = strings.TrimSpace(responseID)
	if sessionKey == "" || responseID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if len(b.entries) >= 1024 {
		for key, binding := range b.entries {
			if now.After(binding.expiresAt) {
				delete(b.entries, key)
			}
		}
	}
	b.entries[sessionKey] = warmSessionBinding{
		responseID: responseID,
		expiresAt:  now.Add(warmSessionBindingTTL),
	}
}

func warmSessionKey(req pluginapi.ExecutorRequest) string {
	for _, name := range []string{"X-Claude-Code-Session-Id", "Session-Id", "Session_id", "X-Session-ID"} {
		if value := headerValue(req.Headers, name); value != "" {
			return "header:" + value
		}
	}
	for _, name := range []string{"execution_session_id", "derived_session_id"} {
		if value := strings.TrimSpace(stringValue(req.Metadata[name])); value != "" {
			return "metadata:" + value
		}
	}
	body := req.OriginalRequest
	if len(body) == 0 {
		body = req.Payload
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	for _, name := range []string{"session_id", "sessionId", "conversation_id", "prompt_cache_key"} {
		if value := strings.TrimSpace(stringValue(payload[name])); value != "" {
			return "body:" + value
		}
	}
	if conversation, ok := payload["conversation"].(map[string]any); ok {
		if value := strings.TrimSpace(stringValue(conversation["id"])); value != "" {
			return "body:" + value
		}
	}
	return ""
}

func headerValue(headers http.Header, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

type warmStreamIDCollector struct {
	pending bytes.Buffer
	id      string
}

func (c *warmStreamIDCollector) consume(chunk []byte) {
	_, _ = c.pending.Write(chunk)
	for {
		line, errRead := c.pending.ReadString('\n')
		if errRead != nil {
			_, _ = c.pending.WriteString(line)
			return
		}
		c.consumeLine(line)
	}
}

func (c *warmStreamIDCollector) responseID() string {
	if c.pending.Len() > 0 {
		c.consumeLine(c.pending.String())
		c.pending.Reset()
	}
	return strings.TrimSpace(c.id)
}

func (c *warmStreamIDCollector) consumeLine(line string) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "data:") {
		return
	}
	var event struct {
		Response struct {
			ID string `json:"id"`
		} `json:"response"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event) == nil && strings.TrimSpace(event.Response.ID) != "" {
		c.id = event.Response.ID
	}
}
