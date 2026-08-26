package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	geniusInvalidEncryptedContentCode  = "invalid_encrypted_content"
	geniusThinkingSignatureInvalidCode = "thinking_signature_invalid"
)

func openGeniusWithReasoningRecovery(ctx context.Context, prepared geniusPreparedRequest, transport geniusTransport, logRetry bool) (*http.Response, error) {
	resp, errOpen := sharedGeniusChannel.Open(ctx, prepared, transport, logRetry)
	if errOpen != nil || resp.StatusCode != http.StatusBadRequest {
		return resp, errOpen
	}
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return nil, fmt.Errorf("read rejected Genius ModelHub response: %w", errRead)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		return nil, fmt.Errorf("close rejected Genius ModelHub response: %w", errClose)
	}
	if !isGeniusInvalidEncryptedContent(body) {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	recoveredBody, removed, errRecover := removeEncryptedReasoningItems(prepared.Body)
	if errRecover != nil {
		return nil, errRecover
	}
	if removed == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	prepared.Body = recoveredBody
	return sharedGeniusChannel.Open(ctx, prepared, transport, logRetry)
}

func isGeniusInvalidEncryptedContent(body []byte) bool {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	code := strings.TrimSpace(payload.Error.Code)
	if code == geniusInvalidEncryptedContentCode || code == geniusThinkingSignatureInvalidCode {
		return true
	}
	message := strings.TrimSpace(payload.Error.Message)
	return strings.Contains(message, "code: "+geniusInvalidEncryptedContentCode+";") ||
		strings.Contains(message, "code: "+geniusThinkingSignatureInvalidCode+";")
}

func removeEncryptedReasoningItems(body []byte) ([]byte, int, error) {
	var payload map[string]json.RawMessage
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return nil, 0, fmt.Errorf("decode Genius reasoning recovery request: %w", errDecode)
	}
	inputRaw, ok := payload["input"]
	if !ok {
		return body, 0, nil
	}
	var input []json.RawMessage
	if json.Unmarshal(inputRaw, &input) != nil {
		return body, 0, nil
	}
	kept := make([]json.RawMessage, 0, len(input))
	removed := 0
	for _, itemRaw := range input {
		var item struct {
			Type             string `json:"type"`
			EncryptedContent string `json:"encrypted_content"`
		}
		if json.Unmarshal(itemRaw, &item) == nil && item.Type == "reasoning" && strings.TrimSpace(item.EncryptedContent) != "" {
			removed++
			continue
		}
		kept = append(kept, itemRaw)
	}
	if removed == 0 {
		return body, 0, nil
	}
	updatedInput, errInput := json.Marshal(kept)
	if errInput != nil {
		return nil, 0, fmt.Errorf("encode Genius reasoning recovery input: %w", errInput)
	}
	payload["input"] = updatedInput
	updatedBody, errBody := json.Marshal(payload)
	if errBody != nil {
		return nil, 0, fmt.Errorf("encode Genius reasoning recovery request: %w", errBody)
	}
	return updatedBody, removed, nil
}
