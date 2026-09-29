package helps

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const testSDKIdentity = "You are a Claude agent, built on Anthropic's Claude Agent SDK."

func TestNormalizeGeminiSDKIdentity(t *testing.T) {
	input := []byte(`{"model":"gemini-3.8-flash","request":{"systemInstruction":{"role":"user","parts":[{"text":"Keep every safety and task instruction."},{"text":"You are a Claude agent, built on Anthropic's Claude Agent SDK.","extra":true},{"text":"Do not modify files without permission."}]},"contents":[{"role":"user","parts":[{"text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."}]}],"tools":[{"functionDeclarations":[{"name":"Read"}]}],"generationConfig":{"thinkingConfig":{"thinkingBudget":123}}}}`)
	for _, model := range []string{"gemini-3.8-flash", "gemini-3.8-flash-high"} {
		t.Run(model, func(t *testing.T) {
			original := bytes.Clone(input)
			got, count := NormalizeGeminiSDKIdentity(input, "claude", model)
			if count != 1 || gjson.GetBytes(got, "request.systemInstruction.parts.1.text").String() != "You are an AI coding assistant." {
				t.Fatalf("rewrite count=%d payload=%s", count, got)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("modified caller input")
			}
			restored, err := sjson.SetBytes(got, "request.systemInstruction.parts.1.text", testSDKIdentity)
			if err != nil {
				t.Fatal(err)
			}
			var a, b any
			if err = json.Unmarshal(original, &a); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(restored, &b); err != nil {
				t.Fatal(err)
			}
			aa, _ := json.Marshal(a)
			bb, _ := json.Marshal(b)
			if !bytes.Equal(aa, bb) {
				t.Fatal("changed fields other than exact system identity")
			}
			again, n := NormalizeGeminiSDKIdentity(got, "claude", model)
			if n != 0 || !bytes.Equal(got, again) {
				t.Fatal("not idempotent")
			}
		})
	}
	for _, c := range []struct{ format, model string }{{"claude", "claude-sonnet-4-5"}, {"claude", "gemini-3.8-pro"}, {"responses", "gemini-3.8-flash-high"}, {"gemini", "gemini-3.8-flash-high"}, {"claude", "other/gemini-3.8-flash-high"}} {
		got, n := NormalizeGeminiSDKIdentity(input, c.format, c.model)
		if n != 0 || !bytes.Equal(got, input) {
			t.Fatalf("unexpected rewrite for %v", c)
		}
	}
}

func TestNormalizeGeminiSDKIdentityBoundaries(t *testing.T) {
	cases := []struct {
		name, payload string
		count         int
	}{
		{"missing", `{"request":{}}`, 0},
		{"invalid", `{"request":`, 0},
		{"null", `null`, 0},
		{"near_match", `{"request":{"systemInstruction":{"parts":[{"text":"You are a Claude agent, built on Anthropic's Claude Agent SDK. Keep all instructions."}]}}}`, 0},
		{"leading_space", `{"request":{"systemInstruction":{"parts":[{"text":" You are a Claude agent, built on Anthropic's Claude Agent SDK."}]}}}`, 0},
		{"multiple", `{"request":{"systemInstruction":{"parts":[{"text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},{"text":"keep"},{"text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."}]}}}`, 2},
		{"wrong_type", `{"request":{"systemInstruction":{"parts":[{"text":123}]}}}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.payload)
			got, n := NormalizeGeminiSDKIdentity(in, "claude", "gemini-3.8-flash-high")
			if n != c.count {
				t.Fatalf("count=%d want=%d", n, c.count)
			}
			if n == 0 && !bytes.Equal(got, in) {
				t.Fatal("changed nonmatching payload")
			}
			if n > 0 && !gjson.ValidBytes(got) {
				t.Fatal("invalid output")
			}
		})
	}
}
