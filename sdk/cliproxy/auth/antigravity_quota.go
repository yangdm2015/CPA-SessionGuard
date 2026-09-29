package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

const (
	antigravityQuotaURL          = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
	antigravityQuotaProbeTimeout = 5 * time.Second
	antigravityQuotaCacheTTL     = 10 * time.Minute
	antigravityOAuthClientID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	antigravityOAuthClientSecret = "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"
)

// DefaultWeeklyQuotaThreshold is the minimum weekly remaining quota fraction (1%).
const DefaultWeeklyQuotaThreshold = 0.01

// AntigravityQuotaSnapshot stores the latest known quota state for an Antigravity credential.
type AntigravityQuotaSnapshot struct {
	WeeklyResetAt             time.Time
	WeeklyRemainingFraction   float64
	FiveHourResetAt           time.Time
	FiveHourRemainingFraction float64
	FetchedAt                 time.Time
}

type antigravityQuotaState struct {
	mu       sync.RWMutex
	snapshot AntigravityQuotaSnapshot
}

var antigravityQuotaByAuth sync.Map // map[string]*antigravityQuotaState

func GetAntigravityQuotaSnapshot(authID string) (AntigravityQuotaSnapshot, bool) {
	val, ok := antigravityQuotaByAuth.Load(authID)
	if !ok {
		return AntigravityQuotaSnapshot{}, false
	}
	state, okState := val.(*antigravityQuotaState)
	if !okState || state == nil {
		return AntigravityQuotaSnapshot{}, false
	}
	state.mu.RLock()
	snap := state.snapshot
	state.mu.RUnlock()
	if snap.FetchedAt.IsZero() || time.Since(snap.FetchedAt) > antigravityQuotaCacheTTL {
		return snap, false
	}
	return snap, true
}

func SetAntigravityQuotaSnapshot(authID string, snap AntigravityQuotaSnapshot) {
	if authID == "" {
		return
	}
	val, _ := antigravityQuotaByAuth.LoadOrStore(authID, &antigravityQuotaState{})
	state, okState := val.(*antigravityQuotaState)
	if !okState || state == nil {
		return
	}
	state.mu.Lock()
	state.snapshot = snap
	state.mu.Unlock()
}

func refreshAntigravityTokenDirect(ctx context.Context, refreshToken, proxyURL string) (string, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return "", fmt.Errorf("missing refresh token")
	}
	form := url.Values{}
	form.Set("client_id", antigravityOAuthClientID)
	form.Set("client_secret", antigravityOAuthClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if errReq != nil {
		return "", errReq
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "antigravity/cli/1.0.13")

	client := &http.Client{Timeout: 10 * time.Second}
	if proxyURL != "" {
		if transport, _, errP := proxyutil.BuildHTTPTransport(proxyURL); errP == nil && transport != nil {
			client.Transport = transport
		}
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return "", errDo
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh status %d", resp.StatusCode)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return strings.TrimSpace(tokenResp.AccessToken), nil
}

func fetchAntigravityQuota(ctx context.Context, auth *Auth, proxyURL string) (AntigravityQuotaSnapshot, bool) {
	if auth == nil || auth.Metadata == nil {
		return AntigravityQuotaSnapshot{}, false
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	accessToken = strings.TrimSpace(accessToken)
	refreshToken, _ := auth.Metadata["refresh_token"].(string)
	refreshToken = strings.TrimSpace(refreshToken)
	if accessToken == "" && refreshToken == "" {
		return AntigravityQuotaSnapshot{}, false
	}
	projectID, _ := auth.Metadata["project_id"].(string)
	projectID = strings.TrimSpace(projectID)

	probeCtx, cancel := context.WithTimeout(ctx, antigravityQuotaProbeTimeout)
	defer cancel()

	payload := map[string]string{}
	if projectID != "" {
		payload["project"] = projectID
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{}
	if proxyURL != "" {
		if transport, _, errP := proxyutil.BuildHTTPTransport(proxyURL); errP == nil && transport != nil {
			client.Transport = transport
		}
	}

	callQuotaAPI := func(token string) (*http.Response, error) {
		req, errReq := http.NewRequestWithContext(probeCtx, http.MethodPost, antigravityQuotaURL, bytes.NewReader(data))
		if errReq != nil {
			return nil, errReq
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)")
		return client.Do(req)
	}

	if accessToken == "" && refreshToken != "" {
		if refreshed, err := refreshAntigravityTokenDirect(probeCtx, refreshToken, proxyURL); err == nil && refreshed != "" {
			accessToken = refreshed
			auth.Metadata["access_token"] = refreshed
		}
	}
	if accessToken == "" {
		return AntigravityQuotaSnapshot{}, false
	}

	resp, errDo := callQuotaAPI(accessToken)
	if errDo == nil && resp != nil && resp.StatusCode == http.StatusUnauthorized && refreshToken != "" {
		_ = resp.Body.Close()
		if refreshed, err := refreshAntigravityTokenDirect(probeCtx, refreshToken, proxyURL); err == nil && refreshed != "" {
			accessToken = refreshed
			auth.Metadata["access_token"] = refreshed
			resp, errDo = callQuotaAPI(accessToken)
		}
	}
	if errDo != nil || resp == nil {
		return AntigravityQuotaSnapshot{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return AntigravityQuotaSnapshot{}, false
	}

	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if errRead != nil {
		return AntigravityQuotaSnapshot{}, false
	}

	var parsed struct {
		Groups []struct {
			DisplayName string `json:"displayName"`
			Buckets     []struct {
				BucketID          string  `json:"bucketId"`
				Window            string  `json:"window"`
				ResetTime         string  `json:"resetTime"`
				RemainingFraction float64 `json:"remainingFraction"`
			} `json:"buckets"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return AntigravityQuotaSnapshot{}, false
	}

	snap := AntigravityQuotaSnapshot{
		FetchedAt:                 time.Now(),
		WeeklyRemainingFraction:   1.0,
		FiveHourRemainingFraction: 1.0,
	}

	for _, g := range parsed.Groups {
		isGemini := strings.Contains(strings.ToLower(g.DisplayName), "gemini")
		for _, b := range g.Buckets {
			t, _ := time.Parse(time.RFC3339, b.ResetTime)
			if strings.Contains(b.BucketID, "weekly") || b.Window == "weekly" {
				if isGemini || snap.WeeklyResetAt.IsZero() {
					snap.WeeklyResetAt = t
					snap.WeeklyRemainingFraction = b.RemainingFraction
				}
			} else if strings.Contains(b.BucketID, "5h") || b.Window == "5h" {
				if isGemini || snap.FiveHourResetAt.IsZero() {
					snap.FiveHourResetAt = t
					snap.FiveHourRemainingFraction = b.RemainingFraction
				}
			}
		}
	}
	return snap, true
}

func refreshAntigravityQuotasAsync(candidates []*Auth) {
	for _, a := range candidates {
		if a == nil || !strings.EqualFold(strings.TrimSpace(a.Provider), "antigravity") {
			continue
		}
		if _, fresh := GetAntigravityQuotaSnapshot(a.ID); fresh {
			continue
		}
		go func(candidate *Auth) {
			proxyURL := ""
			if candidate != nil {
				proxyURL = candidate.ProxyURL
			}
			snap, ok := fetchAntigravityQuota(context.Background(), candidate, proxyURL)
			if ok {
				SetAntigravityQuotaSnapshot(candidate.ID, snap)
			}
		}(a)
	}
}

// WeeklyRemainingFraction returns the normalized weekly remaining quota fraction (0.0 to 1.0)
// and true if known and unexpired.
func WeeklyRemainingFraction(auth *Auth, now time.Time) (float64, bool) {
	if auth == nil {
		return 1.0, false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "antigravity") || isGeminiOrAntigravity(auth.Provider, "") {
		val, ok := antigravityQuotaByAuth.Load(auth.ID)
		if ok {
			if state, okState := val.(*antigravityQuotaState); okState && state != nil {
				state.mu.RLock()
				snap := state.snapshot
				state.mu.RUnlock()
				if !snap.FetchedAt.IsZero() {
					if snap.WeeklyResetAt.IsZero() || snap.WeeklyResetAt.After(now) {
						return snap.WeeklyRemainingFraction, true
					}
				}
			}
		}
	}
	if isCodexAuth(auth) {
		if pct, ok := auth.codexWeeklyQuotaRemaining(now); ok {
			return pct / 100.0, true
		}
	}
	return 1.0, false
}

// IsAuthWeeklyQuotaDepleted checks if the candidate's weekly quota remaining fraction is below the threshold.
func IsAuthWeeklyQuotaDepleted(auth *Auth, threshold float64, now time.Time) bool {
	if auth == nil {
		return false
	}
	if threshold <= 0 {
		threshold = DefaultWeeklyQuotaThreshold
	}
	remaining, known := WeeklyRemainingFraction(auth, now)
	if !known {
		return false
	}
	return remaining < threshold
}

// HasAlternativeAuthAboveWeeklyThreshold checks if candidates contains at least one other auth
// whose weekly quota is above threshold (or unknown/fresh).
func HasAlternativeAuthAboveWeeklyThreshold(candidates []*Auth, excludeAuthID string, threshold float64, now time.Time) bool {
	for _, c := range candidates {
		if c == nil || c.ID == excludeAuthID {
			continue
		}
		if !IsAuthWeeklyQuotaDepleted(c, threshold, now) {
			return true
		}
	}
	return false
}

// FilterAuthsAboveWeeklyQuotaThreshold narrows candidates to those with weekly quota above threshold.
// If all candidates are below threshold, the original slice is returned as a fallback.
func FilterAuthsAboveWeeklyQuotaThreshold(candidates []*Auth, threshold float64, now time.Time) []*Auth {
	if len(candidates) <= 1 {
		return candidates
	}
	var above []*Auth
	for _, a := range candidates {
		if a != nil && !IsAuthWeeklyQuotaDepleted(a, threshold, now) {
			above = append(above, a)
		}
	}
	if len(above) > 0 {
		return above
	}
	return candidates
}
