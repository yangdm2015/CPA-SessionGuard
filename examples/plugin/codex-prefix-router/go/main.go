package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const pluginIdentifier = "codex-prefix-router"

var currentConfig atomic.Value

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	Enabled            bool   `yaml:"enabled"`
	SuperPrefix        string `yaml:"super_prefix"`
	SuperProvider      string `yaml:"super_provider"`
	TraePrefix         string `yaml:"trae_prefix"`
	TraeProvider       string `yaml:"trae_provider"`
	TraeWarmPrefix     string `yaml:"trae_warm_prefix"`
	TraeWarmProvider   string `yaml:"trae_warm_provider"`
	TraeWarmModel      string `yaml:"trae_warm_model"`
	TraeWarmSelfRoute  bool   `yaml:"trae_warm_self_route"`
	TraeWarmUpstream   string `yaml:"trae_warm_upstream"`
	GeniusPrefix       string `yaml:"genius_prefix"`
	GeniusModel        string `yaml:"genius_model"`
	GeniusSelfRoute    bool   `yaml:"genius_self_route"`
	GeniusResponsesURL string `yaml:"genius_responses_url"`
	GeniusAPIKeyEnv    string `yaml:"genius_api_key_env"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ModelRouter           bool     `json:"model_router"`
	Executor              bool     `json:"executor"`
	ExecutorModelScope    string   `json:"executor_model_scope"`
	ExecutorInputFormats  []string `json:"executor_input_formats"`
	ExecutorOutputFormats []string `json:"executor_output_formats"`
}

type rpcModelRouteRequest struct {
	pluginapi.ModelRouteRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcExecutorRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodModelRoute:
		return routeModel(request)
	case pluginabi.MethodExecutorIdentifier:
		return okEnvelope(map[string]string{"identifier": pluginIdentifier})
	case pluginabi.MethodExecutorExecute:
		if isGeniusRequest(request) {
			return executeGenius(request)
		}
		return executeWarm(request)
	case pluginabi.MethodExecutorExecuteStream:
		if isGeniusRequest(request) {
			return executeGeniusStream(request)
		}
		return executeWarmStream(request)
	case pluginabi.MethodExecutorCountTokens:
		return okEnvelope(pluginapi.ExecutorResponse{Payload: []byte(`{"input_tokens":0}`)})
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	cfg := defaultPluginConfig()
	if len(req.ConfigYAML) > 0 {
		decoded, errDecode := decodeConfig(req.ConfigYAML)
		if errDecode != nil {
			return errDecode
		}
		cfg = decoded
	}
	currentConfig.Store(cfg)
	return nil
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		Enabled:            true,
		SuperPrefix:        "super/",
		SuperProvider:      "codex",
		TraePrefix:         "trae/",
		TraeWarmPrefix:     "trae-warm/",
		TraeWarmProvider:   "codex",
		TraeWarmModel:      "GPT-5.6-Sol",
		TraeWarmUpstream:   "http://127.0.0.1:18091/v1",
		GeniusPrefix:       "genius/",
		GeniusModel:        "gpt-5.6-sol",
		GeniusResponsesURL: "https://search.bytedance.net/gpt/openapi/online/responses",
		GeniusAPIKeyEnv:    "GENIUS_MODELHUB_AK",
	}
}

func decodeConfig(raw []byte) (pluginConfig, error) {
	cfg := defaultPluginConfig()
	if errUnmarshal := yaml.Unmarshal(raw, &cfg); errUnmarshal != nil {
		return pluginConfig{}, errUnmarshal
	}
	cfg.SuperPrefix = normalizePrefix(cfg.SuperPrefix)
	cfg.SuperProvider = strings.ToLower(strings.TrimSpace(cfg.SuperProvider))
	cfg.TraePrefix = normalizePrefix(cfg.TraePrefix)
	cfg.TraeProvider = strings.ToLower(strings.TrimSpace(cfg.TraeProvider))
	cfg.TraeWarmPrefix = normalizePrefix(cfg.TraeWarmPrefix)
	cfg.TraeWarmProvider = strings.ToLower(strings.TrimSpace(cfg.TraeWarmProvider))
	cfg.TraeWarmModel = strings.TrimSpace(cfg.TraeWarmModel)
	cfg.TraeWarmUpstream = strings.TrimRight(strings.TrimSpace(cfg.TraeWarmUpstream), "/")
	cfg.GeniusPrefix = normalizePrefix(cfg.GeniusPrefix)
	cfg.GeniusModel = strings.TrimSpace(cfg.GeniusModel)
	cfg.GeniusResponsesURL = strings.TrimSpace(cfg.GeniusResponsesURL)
	cfg.GeniusAPIKeyEnv = strings.TrimSpace(cfg.GeniusAPIKeyEnv)
	return cfg, nil
}

func loadedConfig() pluginConfig {
	raw := currentConfig.Load()
	if cfg, ok := raw.(pluginConfig); ok {
		return cfg
	}
	return defaultPluginConfig()
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginIdentifier,
			Version:          "0.6.0",
			Author:           "router-for-me",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "When false, the router declines all prefix routes."},
				{Name: "super_prefix", Type: pluginapi.ConfigFieldTypeString, Description: "Client-visible Super Relay model prefix."},
				{Name: "super_provider", Type: pluginapi.ConfigFieldTypeString, Description: "CPA provider key for stripped super models."},
				{Name: "trae_prefix", Type: pluginapi.ConfigFieldTypeString, Description: "Client-visible Trae model prefix."},
				{Name: "trae_provider", Type: pluginapi.ConfigFieldTypeString, Description: "CPA provider key for stripped trae models."},
				{Name: "trae_warm_prefix", Type: pluginapi.ConfigFieldTypeString, Description: "Client-visible Trae Warm model prefix."},
				{Name: "trae_warm_provider", Type: pluginapi.ConfigFieldTypeString, Description: "CPA provider key used when Trae Warm self route is disabled."},
				{Name: "trae_warm_self_route", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Route Trae Warm requests to this plugin executor."},
				{Name: "trae_warm_upstream", Type: pluginapi.ConfigFieldTypeString, Description: "Loopback base URL of the Trae Warm runtime."},
				{Name: "genius_prefix", Type: pluginapi.ConfigFieldTypeString, Description: "Client-visible Genius ModelHub model prefix."},
				{Name: "genius_model", Type: pluginapi.ConfigFieldTypeString, Description: "ModelHub model served by the Genius self route."},
				{Name: "genius_self_route", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Route Genius ModelHub requests to this plugin executor."},
				{Name: "genius_responses_url", Type: pluginapi.ConfigFieldTypeString, Description: "Genius ModelHub Responses API URL."},
				{Name: "genius_api_key_env", Type: pluginapi.ConfigFieldTypeString, Description: "Environment variable containing the Genius ModelHub API key."},
			},
		},
		Capabilities: registrationCapability{
			ModelRouter:           true,
			Executor:              true,
			ExecutorModelScope:    string(pluginapi.ExecutorModelScopeStatic),
			ExecutorInputFormats:  []string{"responses"},
			ExecutorOutputFormats: []string{"responses"},
		},
	}
}

func routeModel(raw []byte) ([]byte, error) {
	var req rpcModelRouteRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return okEnvelope(routePrefix(loadedConfig(), req.ModelRouteRequest))
}

func routePrefix(cfg pluginConfig, req pluginapi.ModelRouteRequest) pluginapi.ModelRouteResponse {
	if !cfg.Enabled {
		return pluginapi.ModelRouteResponse{Handled: false, Reason: "codex_prefix_router_disabled"}
	}
	model := strings.TrimSpace(req.RequestedModel)
	if cfg.GeniusSelfRoute && cfg.GeniusPrefix != "" && strings.HasPrefix(model, cfg.GeniusPrefix) {
		targetModel := strings.TrimPrefix(model, cfg.GeniusPrefix)
		if cfg.GeniusModel != "" && targetModel != cfg.GeniusModel {
			return pluginapi.ModelRouteResponse{Handled: false, Reason: "genius_model_mismatch"}
		}
		return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetSelf, Reason: "genius_self"}
	}
	if cfg.TraeWarmPrefix != "" && strings.HasPrefix(model, cfg.TraeWarmPrefix) {
		targetModel := strings.TrimPrefix(model, cfg.TraeWarmPrefix)
		if cfg.TraeWarmModel != "" && targetModel != cfg.TraeWarmModel {
			return pluginapi.ModelRouteResponse{Handled: false, Reason: "trae_warm_model_mismatch"}
		}
		if cfg.TraeWarmSelfRoute {
			return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetSelf, Reason: "trae_warm_self"}
		}
		return routeProvider(cfg.TraeWarmProvider, model, req, "trae_warm_provider")
	}
	if cfg.SuperPrefix != "" && strings.HasPrefix(model, cfg.SuperPrefix) {
		return routeProvider(cfg.SuperProvider, strings.TrimPrefix(model, cfg.SuperPrefix), req, "super_prefix")
	}
	if cfg.TraePrefix != "" && strings.HasPrefix(model, cfg.TraePrefix) {
		return routeProvider(cfg.TraeProvider, strings.TrimPrefix(model, cfg.TraePrefix), req, "trae_prefix")
	}
	return pluginapi.ModelRouteResponse{Handled: false}
}

func isGeniusRequest(raw []byte) bool {
	var req rpcExecutorRequest
	if json.Unmarshal(raw, &req) != nil {
		return false
	}
	cfg := loadedConfig()
	return cfg.GeniusSelfRoute && cfg.GeniusPrefix != "" && strings.HasPrefix(strings.TrimSpace(req.Model), cfg.GeniusPrefix)
}

func routeProvider(provider string, targetModel string, req pluginapi.ModelRouteRequest, reason string) pluginapi.ModelRouteResponse {
	provider = strings.ToLower(strings.TrimSpace(provider))
	targetModel = strings.TrimSpace(targetModel)
	if provider == "" {
		return pluginapi.ModelRouteResponse{Handled: false, Reason: reason + "_provider_empty"}
	}
	if !hasProvider(req.AvailableProviders, provider) {
		return pluginapi.ModelRouteResponse{Handled: false, Reason: reason + "_provider_unavailable"}
	}
	return pluginapi.ModelRouteResponse{
		Handled:     true,
		TargetKind:  pluginapi.ModelRouteTargetProvider,
		Target:      provider,
		TargetModel: targetModel,
		Reason:      reason,
	}
}

func hasProvider(providers []string, key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, provider := range providers {
		if strings.ToLower(strings.TrimSpace(provider)) == key {
			return true
		}
	}
	return false
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || strings.HasSuffix(prefix, "/") {
		return prefix
	}
	return prefix + "/"
}

func okEnvelope(value any) ([]byte, error) {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func errorEnvelopeStatus(code, message string, status int) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}

func callHost(method string, payload any) (json.RawMessage, error) {
	rawPayload, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, errMarshal)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var response C.cliproxy_buffer
	var requestPtr *C.uint8_t
	if len(rawPayload) > 0 {
		cPayload := C.CBytes(rawPayload)
		if cPayload == nil {
			return nil, fmt.Errorf("allocate host callback %s", method)
		}
		defer C.free(cPayload)
		requestPtr = (*C.uint8_t)(cPayload)
	}
	callCode := C.call_host_api(cMethod, requestPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response, code=%d", method, int(callCode))
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &env); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host envelope %s: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error == nil {
			return nil, fmt.Errorf("host callback %s failed", method)
		}
		return nil, fmt.Errorf("host callback %s: %s", method, env.Error.Message)
	}
	return env.Result, nil
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

var _ = http.StatusOK
