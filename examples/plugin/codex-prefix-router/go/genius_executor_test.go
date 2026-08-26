package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRouteModelRoutesGeniusPrefixToSelf(t *testing.T) {
	cfg, errDecode := decodeConfig([]byte(`
enabled: true
genius_prefix: genius/
genius_model: gpt-5.6-sol
genius_self_route: true
`))
	if errDecode != nil {
		t.Fatal(errDecode)
	}
	resp := routePrefix(cfg, pluginapi.ModelRouteRequest{RequestedModel: "genius/gpt-5.6-sol"})
	if !resp.Handled {
		t.Fatalf("Handled = false, want true; reason=%q", resp.Reason)
	}
	if resp.TargetKind != pluginapi.ModelRouteTargetSelf {
		t.Fatalf("TargetKind = %q, want self", resp.TargetKind)
	}
}

func TestGeniusExecutorUsesProtectedKeyAndStableSession(t *testing.T) {
	t.Setenv("GENIUS_MODELHUB_AK", "test-modelhub-ak")
	var extras []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Fatalf("path = %q, want /responses", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-modelhub-ak" {
			t.Fatalf("Authorization = %q", got)
		}
		extra := r.Header.Get("extra")
		extras = append(extras, extra)
		var extraBody map[string]string
		if errDecode := json.Unmarshal([]byte(extra), &extraBody); errDecode != nil {
			t.Fatalf("extra = %q: %v", extra, errDecode)
		}
		if matched := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(extraBody["session_id"]); !matched {
			t.Fatalf("session_id = %q, want UUID", extraBody["session_id"])
		}
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		var payload map[string]any
		if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
			t.Fatal(errDecode)
		}
		if payload["model"] != "gpt-5.6-sol" {
			t.Fatalf("model = %q, want gpt-5.6-sol", payload["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_test","status":"completed"}`))
	}))
	defer server.Close()

	configRequest, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: []byte(`
enabled: true
genius_prefix: genius/
genius_model: gpt-5.6-sol
genius_self_route: true
genius_responses_url: ` + server.URL + `/responses
genius_api_key_env: GENIUS_MODELHUB_AK
`)})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if _, errConfigure := handleMethod(pluginabi.MethodPluginReconfigure, configRequest); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	t.Cleanup(func() {
		_, _ = handleMethod(pluginabi.MethodPluginReconfigure, nil)
	})

	request := rpcExecutorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
		Model:           "genius/gpt-5.6-sol",
		Format:          "openai-response",
		Headers:         http.Header{"Session-Id": []string{"codex-session-1"}},
		OriginalRequest: []byte(`{"model":"genius/gpt-5.6-sol","input":"ping","stream":false}`),
	}}
	rawRequest, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	for range 2 {
		rawResponse, errHandle := handleMethod(pluginabi.MethodExecutorExecute, rawRequest)
		if errHandle != nil {
			t.Fatal(errHandle)
		}
		var response envelope
		if errDecode := json.Unmarshal(rawResponse, &response); errDecode != nil {
			t.Fatal(errDecode)
		}
		if !response.OK {
			t.Fatalf("response error = %+v", response.Error)
		}
	}
	if len(extras) != 2 || extras[0] != extras[1] {
		t.Fatalf("extra headers = %#v, want two stable values", extras)
	}
}
