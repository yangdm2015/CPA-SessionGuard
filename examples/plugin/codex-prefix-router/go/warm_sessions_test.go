package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestWarmSessionBindingsInjectLatestResponseID(t *testing.T) {
	bindings := newWarmSessionBindings()
	req := pluginapi.ExecutorRequest{
		Headers:         http.Header{"Session_id": []string{"codex-session-1"}},
		OriginalRequest: []byte(`{"model":"trae-warm/GPT-5.6-Sol","input":"first"}`),
	}

	preparedFirst, sessionKey, errPrepareFirst := bindings.prepare(req)
	if errPrepareFirst != nil {
		t.Fatal(errPrepareFirst)
	}
	if sessionKey == "" {
		t.Fatal("sessionKey is empty")
	}
	if string(preparedFirst.OriginalRequest) != string(req.OriginalRequest) {
		t.Fatalf("first request changed: %s", preparedFirst.OriginalRequest)
	}
	bindings.recordResponse(sessionKey, []byte(`{"id":"resp-first","status":"completed"}`))

	preparedNext, nextSessionKey, errPrepareNext := bindings.prepare(pluginapi.ExecutorRequest{
		Headers:         req.Headers,
		OriginalRequest: []byte(`{"model":"trae-warm/GPT-5.6-Sol","input":"next"}`),
	})
	if errPrepareNext != nil {
		t.Fatal(errPrepareNext)
	}
	if nextSessionKey != sessionKey {
		t.Fatalf("sessionKey = %q, want %q", nextSessionKey, sessionKey)
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(preparedNext.OriginalRequest, &body); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if body["previous_response_id"] != "resp-first" {
		t.Fatalf("previous_response_id = %#v, want resp-first", body["previous_response_id"])
	}
}

func TestWarmStreamIDCollectorAcrossChunks(t *testing.T) {
	collector := warmStreamIDCollector{}
	collector.consume([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-"))
	collector.consume([]byte("stream\"}}\n\n"))
	if got := collector.responseID(); got != "resp-stream" {
		t.Fatalf("responseID() = %q, want resp-stream", got)
	}
}
