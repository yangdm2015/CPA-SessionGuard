package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestAntigravitySDKIdentityOnWire(t *testing.T) {
	const identity = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
	for _, stream := range []bool{false, true} {
		for _, model := range []string{"gemini-3.8-flash-high", "claude-sonnet-4-5"} {
			name := model + "/unary"
			if stream {
				name = model + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				captured := make(chan []byte, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					captured <- body
					response := `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}}`
					if strings.Contains(r.URL.Path, "streamGenerateContent") {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = w.Write([]byte("data: " + response + "\n\n"))
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(response))
					}
				}))
				defer upstream.Close()
				exec := NewAntigravityExecutor(&config.Config{RequestRetry: 0})
				auth := &cliproxyauth.Auth{ID: "sdk-identity-test-" + name, Provider: "antigravity", Attributes: map[string]string{"base_url": upstream.URL}, Metadata: map[string]any{"access_token": "fake-test-token", "project_id": "test-project", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}}
				payload := []byte(`{"model":"` + model + `","max_tokens":1024,"system":[{"type":"text","text":"Preserve this safety directive."},{"type":"text","text":"` + identity + `"},{"type":"text","text":"Preserve this task directive."}],"messages":[{"role":"user","content":"` + identity + `"}],"tools":[{"name":"Read","description":"read file","input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}]}`)
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, ResponseFormat: sdktranslator.FormatClaude, Stream: stream, OriginalRequest: payload}
				req := cliproxyexecutor.Request{Model: model, Payload: payload}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if stream {
					res, err := exec.ExecuteStream(ctx, auth, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for c := range res.Chunks {
						if c.Err != nil {
							t.Fatal(c.Err)
						}
					}
				} else {
					if _, err := exec.Execute(ctx, auth, req, opts); err != nil {
						t.Fatal(err)
					}
				}
				var body []byte
				select {
				case body = <-captured:
				case <-ctx.Done():
					t.Fatal("no upstream request")
				}
				parts := gjson.GetBytes(body, "request.systemInstruction.parts").Array()
				texts := []string{}
				for _, p := range parts {
					texts = append(texts, p.Get("text").String())
				}
				combined := strings.Join(texts, "\n")
				for _, keep := range []string{"Preserve this safety directive.", "Preserve this task directive."} {
					if !strings.Contains(combined, keep) {
						t.Fatalf("lost system directive: %s", keep)
					}
				}
				if strings.HasPrefix(model, "gemini-") {
					if strings.Contains(combined, identity) || !strings.Contains(combined, "You are an AI coding assistant.") {
						t.Fatalf("identity not normalized: %s", combined)
					}
				} else if !strings.Contains(combined, identity) {
					t.Fatal("native Claude identity changed")
				}
				if !strings.Contains(gjson.GetBytes(body, "request.contents").Raw, identity) {
					t.Fatal("user content changed")
				}
				if !strings.Contains(gjson.GetBytes(body, "request.tools").Raw, "Read") {
					t.Fatal("tool schema lost")
				}
			})
		}
	}
}
