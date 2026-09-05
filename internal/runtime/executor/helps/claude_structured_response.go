package helps

import (
	"bytes"
	"strings"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ClaudeStructuredResponseOnly identifies text-only evaluators, not agent turns.
// Claude Code's prompt-hook evaluator consumes the last assistant content block;
// a trailing signature-only thinking block otherwise hides the JSON verdict.
func ClaudeStructuredResponseOnly(from, to sdktranslator.Format, original []byte) bool {
	if from != sdktranslator.FormatClaude || to != sdktranslator.FormatClaude {
		return false
	}
	root := gjson.ParseBytes(original)
	// Claude Code can omit thinking entirely when its internal mode is disabled.
	// Omission also means disabled in the Anthropic request format.
	thinking := root.Get("thinking")
	if thinking.Exists() && thinking.Get("type").String() != "disabled" {
		return false
	}
	tools := root.Get("tools")
	if tools.Exists() && (!tools.IsArray() || len(tools.Array()) != 0) {
		return false
	}
	format := root.Get("output_config.format")
	if !format.Exists() {
		format = root.Get("output_format")
	}
	return format.Get("type").String() == "json_schema" && format.Get("schema").IsObject()
}

// FilterCodexStructuredResponse removes reasoning from a JSON-only evaluator's
// client view. Call after recording usage and caching the original replay data.
// A nil result means this reasoning event has no client-visible content.
func FilterCodexStructuredResponse(data []byte) []byte {
	root := gjson.ParseBytes(data)
	switch eventType := root.Get("type").String(); {
	case strings.HasPrefix(eventType, "response.reasoning"):
		return nil
	case eventType == "response.output_item.added" || eventType == "response.output_item.done":
		if root.Get("item.type").String() == "reasoning" {
			return nil
		}
	case eventType == "response.completed" || eventType == "response.incomplete":
		items := root.Get("response.output")
		if !items.IsArray() {
			return data
		}
		var kept [][]byte
		removed := false
		for _, item := range items.Array() {
			if item.Get("type").String() == "reasoning" {
				removed = true
				continue
			}
			kept = append(kept, []byte(item.Raw))
		}
		if removed {
			array := append([]byte("["), bytes.Join(kept, []byte(","))...)
			array = append(array, ']')
			if filtered, err := sjson.SetRawBytes(data, "response.output", array); err == nil {
				return filtered
			}
		}
	}
	return data
}
