package auth

import (
	"bytes"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const maxSessionAffinityResponseBuffer = 1 << 20

type sessionAffinityResponseTracker struct {
	pending    []byte
	responseID string
}

func (t *sessionAffinityResponseTracker) Observe(payload []byte) string {
	if t == nil || len(payload) == 0 {
		return ""
	}
	if t.responseID != "" {
		return ""
	}
	combined := payload
	if len(t.pending) > 0 {
		combined = make([]byte, 0, len(t.pending)+len(payload))
		combined = append(combined, t.pending...)
		combined = append(combined, payload...)
		t.pending = nil
	}
	if responseID := observedStreamResponseID(combined); responseID != "" {
		t.responseID = responseID
		return responseID
	}
	tail := incompleteSessionAffinityTail(combined)
	if len(tail) > 0 && len(tail) <= maxSessionAffinityResponseBuffer {
		t.pending = bytes.Clone(tail)
	}
	return ""
}

func observedStreamResponseID(payload []byte) string {
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(line[len("data:"):])
		}
		if !gjson.ValidBytes(line) {
			continue
		}
		if responseID := normalizedSessionCandidate(gjson.GetBytes(line, "response.id").String()); responseID != "" {
			return responseID
		}
		eventType := strings.TrimSpace(gjson.GetBytes(line, "type").String())
		if eventType == "response.created" || eventType == "response.completed" {
			if responseID := normalizedSessionCandidate(gjson.GetBytes(line, "id").String()); responseID != "" {
				return responseID
			}
		}
	}
	return ""
}

func incompleteSessionAffinityTail(payload []byte) []byte {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || validSessionAffinityJSONLine(trimmed) {
		return nil
	}
	if newline := bytes.LastIndexByte(payload, '\n'); newline >= 0 {
		tail := bytes.TrimSpace(payload[newline+1:])
		if len(tail) == 0 || validSessionAffinityJSONLine(tail) {
			return nil
		}
		return tail
	}
	return trimmed
}

func validSessionAffinityJSONLine(line []byte) bool {
	line = bytes.TrimSpace(line)
	if bytes.HasPrefix(line, []byte("data:")) {
		line = bytes.TrimSpace(line[len("data:"):])
	}
	return gjson.ValidBytes(line)
}

func recordSessionAffinityResponseID(opts *cliproxyexecutor.Options, payload []byte, stream bool) {
	if opts == nil {
		return
	}
	responseID := sessionAffinityResponseID(payload, stream)
	if responseID == "" {
		return
	}
	opts.EnsureMetadata()[cliproxyexecutor.SessionAffinityResponseIDMetadataKey] = responseID
}

func sessionAffinityResponseID(payload []byte, stream bool) string {
	if len(payload) == 0 {
		return ""
	}
	if !stream {
		if responseID := responseIDFromJSON(payload, false); responseID != "" {
			return responseID
		}
	}
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(line[len("data:"):])
		}
		if responseID := responseIDFromJSON(line, true); responseID != "" {
			return responseID
		}
	}
	return responseIDFromJSON(bytes.TrimSpace(payload), true)
}

func responseIDFromJSON(payload []byte, requireCompleted bool) string {
	if !gjson.ValidBytes(payload) {
		return ""
	}
	eventType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
	status := strings.TrimSpace(gjson.GetBytes(payload, "status").String())
	responseStatus := strings.TrimSpace(gjson.GetBytes(payload, "response.status").String())
	if requireCompleted && eventType != "response.completed" && status != "completed" && responseStatus != "completed" {
		return ""
	}
	responseID := strings.TrimSpace(gjson.GetBytes(payload, "response.id").String())
	if responseID == "" {
		responseID = strings.TrimSpace(gjson.GetBytes(payload, "id").String())
	}
	return normalizedSessionCandidate(responseID)
}
