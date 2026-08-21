package auth

import (
	"bytes"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

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
