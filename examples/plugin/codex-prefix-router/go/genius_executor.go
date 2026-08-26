package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func executeGenius(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	resp, errRun := runGeniusExecutorRequest(context.Background(), loadedConfig(), req, false)
	if errRun != nil {
		if _, limited := errRun.(*geniusRateLimitError); limited {
			return errorEnvelopeStatus("genius_modelhub_rate_limited", errRun.Error(), http.StatusTooManyRequests), nil
		}
		return errorEnvelope("genius_modelhub_executor_error", errRun.Error()), nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return errorEnvelopeStatus("genius_modelhub_upstream_error", geniusErrorMessage(resp.Body), resp.StatusCode), nil
	}
	return okEnvelope(pluginapi.ExecutorResponse{Payload: resp.Body, Headers: resp.Headers})
}

func executeGeniusStream(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return errorEnvelope("genius_modelhub_executor_error", "stream_id is required"), nil
	}
	resp, errOpen := openGeniusExecutorRequest(context.Background(), loadedConfig(), req, true)
	if errOpen != nil {
		if _, limited := errOpen.(*geniusRateLimitError); limited {
			return errorEnvelopeStatus("genius_modelhub_rate_limited", errOpen.Error(), http.StatusTooManyRequests), nil
		}
		return errorEnvelope("genius_modelhub_executor_error", errOpen.Error()), nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		body, errRead := io.ReadAll(resp.Body)
		errClose := resp.Body.Close()
		if errRead != nil {
			return errorEnvelope("genius_modelhub_executor_error", errRead.Error()), nil
		}
		if errClose != nil {
			return errorEnvelope("genius_modelhub_executor_error", errClose.Error()), nil
		}
		return errorEnvelopeStatus("genius_modelhub_upstream_error", geniusErrorMessage(body), resp.StatusCode), nil
	}
	go func() {
		errForward := forwardWarmStream(context.Background(), resp.Body, func(chunk []byte) error {
			return emitPluginStreamChunk(streamID, chunk)
		})
		errClose := resp.Body.Close()
		if errForward == nil {
			errForward = errClose
		}
		if errForward != nil {
			closePluginStream(streamID, errForward.Error())
			return
		}
		closePluginStream(streamID, "")
	}()
	return okEnvelope(map[string]any{"headers": cloneResponseHeaders(resp.Header)})
}

func runGeniusRequest(ctx context.Context, cfg pluginConfig, req pluginapi.ExecutorRequest, client *http.Client) (warmHTTPResponse, error) {
	resp, errOpen := openGeniusRequest(ctx, cfg, req, client)
	if errOpen != nil {
		return warmHTTPResponse{}, errOpen
	}
	body, errRead := io.ReadAll(resp.Body)
	errClose := resp.Body.Close()
	if errRead != nil {
		return warmHTTPResponse{}, fmt.Errorf("read Genius ModelHub response: %w", errRead)
	}
	if errClose != nil {
		return warmHTTPResponse{}, fmt.Errorf("close Genius ModelHub response: %w", errClose)
	}
	return warmHTTPResponse{StatusCode: resp.StatusCode, Headers: cloneResponseHeaders(resp.Header), Body: body}, nil
}

func runGeniusExecutorRequest(ctx context.Context, cfg pluginConfig, req rpcExecutorRequest, stream bool) (warmHTTPResponse, error) {
	resp, errOpen := openGeniusExecutorRequest(ctx, cfg, req, stream)
	if errOpen != nil {
		return warmHTTPResponse{}, errOpen
	}
	body, errRead := io.ReadAll(resp.Body)
	errClose := resp.Body.Close()
	if errRead != nil {
		return warmHTTPResponse{}, fmt.Errorf("read Genius ModelHub response: %w", errRead)
	}
	if errClose != nil {
		return warmHTTPResponse{}, fmt.Errorf("close Genius ModelHub response: %w", errClose)
	}
	return warmHTTPResponse{StatusCode: resp.StatusCode, Headers: cloneResponseHeaders(resp.Header), Body: body}, nil
}

func openGeniusRequest(ctx context.Context, cfg pluginConfig, req pluginapi.ExecutorRequest, client *http.Client) (*http.Response, error) {
	prepared, errPrepare := prepareGeniusRequest(cfg, req, "")
	if errPrepare != nil {
		return nil, errPrepare
	}
	return openGeniusWithReasoningRecovery(ctx, prepared, directGeniusTransport{client: client}, false)
}

func openGeniusExecutorRequest(ctx context.Context, cfg pluginConfig, req rpcExecutorRequest, stream bool) (*http.Response, error) {
	prepared, errPrepare := prepareGeniusRequest(cfg, req.ExecutorRequest, req.HostCallbackID)
	if errPrepare != nil {
		return nil, errPrepare
	}
	if strings.TrimSpace(req.HostCallbackID) == "" {
		return openGeniusWithReasoningRecovery(ctx, prepared, directGeniusTransport{client: http.DefaultClient}, false)
	}
	return openGeniusWithReasoningRecovery(ctx, prepared, hostGeniusTransport{stream: stream}, true)
}

func prepareGeniusRequest(cfg pluginConfig, req pluginapi.ExecutorRequest, callbackID string) (geniusPreparedRequest, error) {
	if strings.TrimSpace(req.Format) != "openai-response" {
		return geniusPreparedRequest{}, fmt.Errorf("Genius ModelHub only supports openai-response format, got %q", req.Format)
	}
	responsesURL := strings.TrimSpace(cfg.GeniusResponsesURL)
	if responsesURL == "" {
		return geniusPreparedRequest{}, fmt.Errorf("genius_responses_url is required")
	}
	apiKeyEnv := strings.TrimSpace(cfg.GeniusAPIKeyEnv)
	if apiKeyEnv == "" {
		return geniusPreparedRequest{}, fmt.Errorf("genius_api_key_env is required")
	}
	apiKey := strings.TrimSpace(os.Getenv(apiKeyEnv))
	if apiKey == "" {
		return geniusPreparedRequest{}, fmt.Errorf("Genius ModelHub API key is unavailable")
	}
	sessionKey := warmSessionKey(req)
	if sessionKey == "" {
		return geniusPreparedRequest{}, fmt.Errorf("stable Codex session identifier is required")
	}
	body, errBody := geniusRequestBody(cfg, req)
	if errBody != nil {
		return geniusPreparedRequest{}, errBody
	}
	upstreamURL, errURL := appendQuery(responsesURL, req.Query)
	if errURL != nil {
		return geniusPreparedRequest{}, errURL
	}
	extra, _ := json.Marshal(map[string]string{"session_id": stableSessionUUID(sessionKey)})
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+apiKey)
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", req.Headers.Get("Accept"))
	headers.Set("extra", string(extra))
	if headers.Get("Accept") == "" {
		headers.Set("Accept", "*/*")
	}
	sessionID := stableSessionUUID(sessionKey)
	return geniusPreparedRequest{
		URL:                upstreamURL,
		Headers:            headers,
		Body:               body,
		HostCallbackID:     strings.TrimSpace(callbackID),
		SessionFingerprint: strings.ReplaceAll(sessionID[:13], "-", ""),
	}, nil
}

func geniusRequestBody(cfg pluginConfig, req pluginapi.ExecutorRequest) ([]byte, error) {
	body := req.OriginalRequest
	if len(body) == 0 {
		body = req.Payload
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("Genius ModelHub request body is required")
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return nil, fmt.Errorf("decode Genius ModelHub request: %w", errUnmarshal)
	}
	model := strings.TrimSpace(cfg.GeniusModel)
	if model == "" {
		model = strings.TrimPrefix(strings.TrimSpace(req.Model), cfg.GeniusPrefix)
	}
	if model == "" {
		return nil, fmt.Errorf("genius_model is required")
	}
	payload["model"] = model
	encoded, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode Genius ModelHub request: %w", errMarshal)
	}
	return encoded, nil
}

func stableSessionUUID(sessionKey string) string {
	sum := sha256.Sum256([]byte("codex-prefix-router/genius/" + sessionKey))
	raw := append([]byte(nil), sum[:16]...)
	raw[6] = (raw[6] & 0x0f) | 0x50
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func appendQuery(rawURL string, query url.Values) (string, error) {
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		return "", fmt.Errorf("parse Genius ModelHub URL: %w", errParse)
	}
	values := parsed.Query()
	for key, items := range query {
		for _, item := range items {
			values.Add(key, item)
		}
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}
