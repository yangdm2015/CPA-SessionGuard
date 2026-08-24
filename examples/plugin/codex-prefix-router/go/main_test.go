package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestWarmExecutorForwardsResponsesRequest(t *testing.T) {
	wantBody := []byte(`{"model":"trae-warm/GPT-5.6-Sol","input":"ping","stream":false}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path = %q, want /v1/responses", r.URL.Path)
		}
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("body = %s, want %s", body, wantBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed"}`))
	}))
	defer server.Close()

	resp, errRun := runWarmRequest(context.Background(), pluginConfig{
		TraeWarmUpstream: server.URL + "/v1",
	}, pluginapi.ExecutorRequest{
		Format:          "openai-response",
		OriginalRequest: wantBody,
	}, server.Client())
	if errRun != nil {
		t.Fatal(errRun)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != `{"status":"completed"}` {
		t.Fatalf("body = %s", resp.Body)
	}
}

func TestWarmExecutorPreservesUpstreamErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"trae_warm_queued"}}`))
	}))
	defer server.Close()

	resp, errRun := runWarmRequest(context.Background(), pluginConfig{
		TraeWarmUpstream: server.URL + "/v1",
	}, pluginapi.ExecutorRequest{
		Format:  "openai-response",
		Payload: []byte(`{"model":"trae-warm/GPT-5.6-Sol"}`),
	}, server.Client())
	if errRun != nil {
		t.Fatal(errRun)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Headers.Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q, want 5", resp.Headers.Get("Retry-After"))
	}
}

func TestForwardWarmStreamEmitsAllBytes(t *testing.T) {
	input := "event: response.output_text.delta\ndata: {\"delta\":\"OK\"}\n\ndata: [DONE]\n\n"
	var got bytes.Buffer
	errForward := forwardWarmStream(context.Background(), strings.NewReader(input), func(chunk []byte) error {
		_, errWrite := got.Write(chunk)
		return errWrite
	})
	if errForward != nil {
		t.Fatal(errForward)
	}
	if got.String() != input {
		t.Fatalf("stream = %q, want %q", got.String(), input)
	}
}

func TestRouteModelStripsConfiguredPrefixToProvider(t *testing.T) {
	cfg := pluginConfig{
		Enabled:       true,
		SuperPrefix:   "super/",
		SuperProvider: "codex",
		TraePrefix:    "trae/",
		TraeProvider:  "codex",
	}
	resp := routePrefix(cfg, pluginapi.ModelRouteRequest{
		RequestedModel:     "super/GPT-5.6-Sol",
		AvailableProviders: []string{"codex"},
	})

	if !resp.Handled {
		t.Fatalf("Handled = false, want true")
	}
	if resp.TargetKind != pluginapi.ModelRouteTargetProvider {
		t.Fatalf("TargetKind = %q, want provider", resp.TargetKind)
	}
	if resp.Target != "codex" {
		t.Fatalf("Target = %q, want codex", resp.Target)
	}
	if resp.TargetModel != "GPT-5.6-Sol" {
		t.Fatalf("TargetModel = %q, want GPT-5.6-Sol", resp.TargetModel)
	}
}

func TestRouteModelDeclinesUnavailableProvider(t *testing.T) {
	cfg := pluginConfig{Enabled: true, SuperPrefix: "super/", SuperProvider: "codex"}
	resp := routePrefix(cfg, pluginapi.ModelRouteRequest{
		RequestedModel:     "super/GPT-5.6-Sol",
		AvailableProviders: []string{"claude"},
	})

	if resp.Handled {
		t.Fatalf("Handled = true, want false")
	}
}

func TestRouteModelRoutesWarmPrefixToSelf(t *testing.T) {
	cfg := pluginConfig{
		Enabled:           true,
		TraeWarmPrefix:    "trae-warm/",
		TraeWarmModel:     "GPT-5.6-Sol",
		TraeWarmSelfRoute: true,
	}
	resp := routePrefix(cfg, pluginapi.ModelRouteRequest{
		RequestedModel: "trae-warm/GPT-5.6-Sol",
	})

	if !resp.Handled {
		t.Fatalf("Handled = false, want true")
	}
	if resp.TargetKind != pluginapi.ModelRouteTargetSelf {
		t.Fatalf("TargetKind = %q, want self", resp.TargetKind)
	}
}
