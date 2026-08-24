package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type warmHTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type rpcStreamEmitRequest struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
}

type rpcStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error,omitempty"`
}

var warmSessions = newWarmSessionBindings()

func executeWarm(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	prepared, sessionKey, errPrepare := warmSessions.prepare(req.ExecutorRequest)
	if errPrepare != nil {
		return errorEnvelope("trae_warm_executor_error", errPrepare.Error()), nil
	}
	resp, errRun := runWarmRequest(context.Background(), loadedConfig(), prepared, http.DefaultClient)
	if errRun != nil {
		return errorEnvelope("trae_warm_executor_error", errRun.Error()), nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return errorEnvelopeStatus("trae_warm_upstream_error", warmErrorMessage(resp.Body), resp.StatusCode), nil
	}
	warmSessions.recordResponse(sessionKey, resp.Body)
	return okEnvelope(pluginapi.ExecutorResponse{Payload: resp.Body, Headers: resp.Headers})
}

func executeWarmStream(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return errorEnvelope("trae_warm_executor_error", "stream_id is required"), nil
	}
	prepared, sessionKey, errPrepare := warmSessions.prepare(req.ExecutorRequest)
	if errPrepare != nil {
		return errorEnvelope("trae_warm_executor_error", errPrepare.Error()), nil
	}
	resp, errOpen := openWarmRequest(context.Background(), loadedConfig(), prepared, http.DefaultClient)
	if errOpen != nil {
		return errorEnvelope("trae_warm_executor_error", errOpen.Error()), nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		body, errRead := io.ReadAll(resp.Body)
		errClose := resp.Body.Close()
		if errRead != nil {
			return errorEnvelope("trae_warm_executor_error", errRead.Error()), nil
		}
		if errClose != nil {
			return errorEnvelope("trae_warm_executor_error", errClose.Error()), nil
		}
		return errorEnvelopeStatus("trae_warm_upstream_error", warmErrorMessage(body), resp.StatusCode), nil
	}
	go func() {
		collector := warmStreamIDCollector{}
		errForward := forwardWarmStream(context.Background(), resp.Body, func(chunk []byte) error {
			collector.consume(chunk)
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
		warmSessions.recordID(sessionKey, collector.responseID())
		closePluginStream(streamID, "")
	}()
	return okEnvelope(map[string]any{"headers": cloneResponseHeaders(resp.Header)})
}

func runWarmRequest(ctx context.Context, cfg pluginConfig, req pluginapi.ExecutorRequest, client *http.Client) (warmHTTPResponse, error) {
	resp, errOpen := openWarmRequest(ctx, cfg, req, client)
	if errOpen != nil {
		return warmHTTPResponse{}, errOpen
	}
	body, errRead := io.ReadAll(resp.Body)
	errClose := resp.Body.Close()
	if errRead != nil {
		return warmHTTPResponse{}, fmt.Errorf("read Trae Warm response: %w", errRead)
	}
	if errClose != nil {
		return warmHTTPResponse{}, fmt.Errorf("close Trae Warm response: %w", errClose)
	}
	return warmHTTPResponse{StatusCode: resp.StatusCode, Headers: cloneResponseHeaders(resp.Header), Body: body}, nil
}

func openWarmRequest(ctx context.Context, cfg pluginConfig, req pluginapi.ExecutorRequest, client *http.Client) (*http.Response, error) {
	if strings.TrimSpace(req.Format) != "openai-response" {
		return nil, fmt.Errorf("Trae Warm only supports openai-response format, got %q", req.Format)
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.TraeWarmUpstream), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("trae_warm_upstream is required")
	}
	body := req.OriginalRequest
	if len(body) == 0 {
		body = req.Payload
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("Trae Warm request body is required")
	}
	upstreamURL := baseURL + "/responses"
	if len(req.Query) > 0 {
		upstreamURL += "?" + req.Query.Encode()
	}
	httpReq, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, strings.NewReader(string(body)))
	if errRequest != nil {
		return nil, fmt.Errorf("create Trae Warm request: %w", errRequest)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", req.Headers.Get("Accept"))
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "*/*")
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, errDo := client.Do(httpReq)
	if errDo != nil {
		return nil, fmt.Errorf("call Trae Warm upstream: %w", errDo)
	}
	return resp, nil
}

func forwardWarmStream(ctx context.Context, reader io.Reader, emit func([]byte) error) error {
	if reader == nil {
		return fmt.Errorf("Trae Warm stream body is unavailable")
	}
	if emit == nil {
		return fmt.Errorf("Trae Warm stream emitter is unavailable")
	}
	buffer := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		count, errRead := reader.Read(buffer)
		if count > 0 {
			chunk := append([]byte(nil), buffer[:count]...)
			if errEmit := emit(chunk); errEmit != nil {
				return errEmit
			}
		}
		if errRead == io.EOF {
			return nil
		}
		if errRead != nil {
			return errRead
		}
	}
}

func emitPluginStreamChunk(streamID string, payload []byte) error {
	_, errCall := callHost(pluginabi.MethodHostStreamEmit, rpcStreamEmitRequest{StreamID: streamID, Payload: payload})
	return errCall
}

func closePluginStream(streamID, errMsg string) {
	_, _ = callHost(pluginabi.MethodHostStreamClose, rpcStreamCloseRequest{StreamID: streamID, Error: strings.TrimSpace(errMsg)})
}

func cloneResponseHeaders(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for key, values := range headers {
		if strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

func warmErrorMessage(body []byte) string {
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if strings.TrimSpace(payload.Error.Message) != "" {
			return payload.Error.Message
		}
		if strings.TrimSpace(payload.Error.Type) != "" {
			return payload.Error.Type
		}
	}
	return "Trae Warm upstream request failed"
}
