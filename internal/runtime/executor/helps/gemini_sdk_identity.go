package helps

import (
	"strconv"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizeGeminiSDKIdentity replaces only the demonstrated incompatible Claude
// Agent SDK identity block in a translated Antigravity request. It preserves all
// other system instructions, user content, tool schemas and generation settings.
// The model allowlist intentionally excludes unverified Gemini routes and native
// Claude targets. No generic substring removal or system-block deletion is used.
// The returned count supports payload-free observability at the executor boundary.
func NormalizeGeminiSDKIdentity(payload []byte, sourceFormat, model string) ([]byte, int) {
	if sourceFormat != "claude" || (model != "gemini-3.8-flash" && model != "gemini-3.8-flash-high") || !gjson.ValidBytes(payload) {
		return payload, 0
	}
	const identity = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
	const replacement = "You are an AI coding assistant."
	parts := gjson.GetBytes(payload, "request.systemInstruction.parts")
	if !parts.IsArray() {
		return payload, 0
	}
	result := payload
	count := 0
	for index, part := range parts.Array() {
		text := part.Get("text")
		if text.Type != gjson.String || text.String() != identity {
			continue
		}
		updated, err := sjson.SetBytes(result, "request.systemInstruction.parts."+strconv.Itoa(index)+".text", replacement)
		if err != nil {
			// Never return a partially rewritten request if a future payload shape
			// invalidates the exact JSON paths used above.
			return payload, 0
		}
		result = updated
		count++
	}
	return result, count
}
