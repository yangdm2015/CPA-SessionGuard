package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

type activeBinding struct {
	SessionID string
	Model     string
}

func main() {
	var configPath, sessionsDir, logPath, baseURL, storePath string
	var lookback, ttl time.Duration
	var apply bool
	flag.StringVar(&configPath, "config", "", "CPA config.yaml path")
	flag.StringVar(&sessionsDir, "sessions", "", "Codex sessions directory")
	flag.StringVar(&logPath, "log", "", "running CPA stdout log")
	flag.StringVar(&baseURL, "base-url", "http://127.0.0.1:8317", "running CPA base URL")
	flag.StringVar(&storePath, "store", "", "destination session binding JSON")
	flag.DurationVar(&lookback, "lookback", 24*time.Hour, "active session lookback")
	flag.DurationVar(&ttl, "ttl", 24*time.Hour, "imported binding TTL")
	flag.BoolVar(&apply, "apply", false, "probe the old CPA and write bindings")
	flag.Parse()

	home, err := os.UserHomeDir()
	fatalIf(err)
	if configPath == "" {
		configPath = filepath.Join(home, ".config", "cliproxyapi", "config.yaml")
	}
	if sessionsDir == "" {
		sessionsDir = filepath.Join(home, ".codex", "sessions")
	}
	if logPath == "" {
		logPath = filepath.Join(home, ".local", "state", "cliproxyapi", "stdout.log")
	}
	cfg, err := internalconfig.LoadConfig(configPath)
	fatalIf(err)
	if storePath == "" {
		storePath = strings.TrimSpace(cfg.Routing.SessionAffinityStore)
		if storePath == "" {
			storePath = filepath.Join(cfg.AuthDir, ".session-affinity.sab")
		}
	}

	bindings, err := collectActiveBindings(sessionsDir, time.Now().Add(-lookback))
	fatalIf(err)
	fmt.Printf("found %d active session/model bindings\n", len(bindings))
	for _, binding := range bindings {
		fmt.Printf("  %s  %s\n", truncate(binding.SessionID), binding.Model)
	}
	if !apply {
		fmt.Println("dry run only; pass --apply to probe and persist")
		return
	}
	if len(cfg.APIKeys) == 0 || strings.TrimSpace(cfg.APIKeys[0]) == "" {
		fatalIf(errors.New("CPA config has no API key"))
	}
	cache, err := coreauth.NewSessionCacheWithStore(ttl, coreauth.NewFileSessionBindingStore(storePath))
	fatalIf(err)
	defer cache.Stop()
	client := &http.Client{Timeout: 3 * time.Minute}
	for _, binding := range bindings {
		authID, errProbe := probeBinding(client, strings.TrimRight(baseURL, "/"), cfg.APIKeys[0], logPath, binding)
		if errProbe != nil {
			fmt.Fprintf(os.Stderr, "skip %s %s: %v\n", truncate(binding.SessionID), binding.Model, errProbe)
			continue
		}
		key := coreauth.SessionBindingKey("mixed", "codex:"+binding.SessionID, binding.Model)
		if errBind := cache.BindAliases(authID, key); errBind != nil {
			fatalIf(errBind)
		}
		fmt.Printf("migrated %s %s -> %s\n", truncate(binding.SessionID), binding.Model, authID)
	}
}

func collectActiveBindings(root string, since time.Time) ([]activeBinding, error) {
	unique := make(map[string]activeBinding)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			return nil
		}
		info, errInfo := entry.Info()
		if errInfo != nil || info.ModTime().Before(since) {
			return errInfo
		}
		sessionID, models, errRead := readCodexSession(path)
		if errRead != nil || sessionID == "" {
			return errRead
		}
		for model := range models {
			binding := activeBinding{SessionID: sessionID, Model: model}
			unique[sessionID+"\x00"+model] = binding
		}
		return nil
	})
	bindings := make([]activeBinding, 0, len(unique))
	for _, binding := range unique {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].SessionID == bindings[j].SessionID {
			return bindings[i].Model < bindings[j].Model
		}
		return bindings[i].SessionID < bindings[j].SessionID
	})
	return bindings, err
}

func readCodexSession(path string) (string, map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	models := make(map[string]struct{})
	sessionID := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		switch gjson.GetBytes(line, "type").String() {
		case "session_meta":
			sessionID = strings.TrimSpace(gjson.GetBytes(line, "payload.id").String())
		case "turn_context":
			if model := strings.TrimSpace(gjson.GetBytes(line, "payload.model").String()); model != "" {
				lowerModel := strings.ToLower(model)
				if !strings.HasPrefix(lowerModel, "trae/") && !strings.HasPrefix(lowerModel, "trae-warm/") {
					models[model] = struct{}{}
				}
			}
		}
	}
	return sessionID, models, scanner.Err()
}

func probeBinding(client *http.Client, baseURL, apiKey, logPath string, binding activeBinding) (string, error) {
	offset, err := fileSize(logPath)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"model": binding.Model, "input": "Reply with OK.", "max_output_tokens": 16, "stream": false,
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/responses", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session-Id", binding.SessionID)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("probe returned HTTP %d", resp.StatusCode)
	}
	traceID := strings.TrimSpace(resp.Header.Get("X-CPA-TRACE-ID"))
	parts := strings.Split(traceID, "-")
	if len(parts) == 0 || len(parts[len(parts)-1]) != 8 {
		return "", errors.New("probe response did not include a usable CPA trace ID")
	}
	requestID := parts[len(parts)-1]
	pattern := regexp.MustCompile(`\[` + regexp.QuoteMeta(requestID) + `\].*session-affinity:.* auth=([^ ]+) `)
	for attempt := 0; attempt < 20; attempt++ {
		logBytes, errRead := readFrom(logPath, offset)
		if errRead != nil {
			return "", errRead
		}
		if match := pattern.FindSubmatch(logBytes); len(match) == 2 {
			return string(match[1]), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("selected auth was not found in the CPA log")
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func readFrom(path string, offset int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err = file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func truncate(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:8] + "..."
}

func fatalIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
