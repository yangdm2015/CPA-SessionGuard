package auth

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const codexWeeklyQuotaObservationsMetadataKey = "codex_weekly_quota_observations"

const (
	codexWeeklyUsageURL          = "https://chatgpt.com/backend-api/wham/usage"
	codexWeeklyQuotaProbeTimeout = 8 * time.Second
	codexWeeklyUsageBodyLimit    = 64 << 10
	codexWeeklyQuotaThreshold    = 15.0
)

type codexWeeklyQuotaSnapshot struct {
	remainingPercent float64
	resetAt          time.Time
}

type codexWeeklyQuotaState struct {
	mu       sync.RWMutex
	snapshot codexWeeklyQuotaSnapshot
}

type codexUsageWindow struct {
	UsedPercent        float64 `json:"used_percent"`
	LimitWindowSeconds int64   `json:"limit_window_seconds"`
	ResetAfterSeconds  int64   `json:"reset_after_seconds"`
	ResetAt            int64   `json:"reset_at"`
}

type codexUsageResponse struct {
	RateLimit struct {
		PrimaryWindow   *codexUsageWindow `json:"primary_window"`
		SecondaryWindow *codexUsageWindow `json:"secondary_window"`
	} `json:"rate_limit"`
}

func (a *Auth) ensureCodexWeeklyQuotaState() {
	if a != nil && a.codexWeeklyQuota == nil {
		a.codexWeeklyQuota = &codexWeeklyQuotaState{}
	}
}

func (a *Auth) observeCodexWeeklyQuota(remainingPercent float64, resetAt time.Time) {
	if a == nil || !validCodexWeeklyQuota(remainingPercent, resetAt) {
		return
	}
	a.ensureCodexWeeklyQuotaState()
	a.codexWeeklyQuota.mu.Lock()
	a.codexWeeklyQuota.snapshot = codexWeeklyQuotaSnapshot{
		remainingPercent: remainingPercent,
		resetAt:          resetAt,
	}
	a.codexWeeklyQuota.mu.Unlock()
}

func (a *Auth) codexWeeklyQuotaRemaining(now time.Time) (float64, bool) {
	if a == nil || a.codexWeeklyQuota == nil {
		return 0, false
	}
	a.codexWeeklyQuota.mu.RLock()
	snapshot := a.codexWeeklyQuota.snapshot
	a.codexWeeklyQuota.mu.RUnlock()
	if !validCodexWeeklyQuota(snapshot.remainingPercent, snapshot.resetAt) || !now.Before(snapshot.resetAt) {
		return 0, false
	}
	return snapshot.remainingPercent, true
}

func validCodexWeeklyQuota(remainingPercent float64, resetAt time.Time) bool {
	return !math.IsNaN(remainingPercent) && !math.IsInf(remainingPercent, 0) &&
		remainingPercent >= 0 && remainingPercent <= 100 && !resetAt.IsZero()
}

type codexWeeklyQuotaObservations struct {
	mu        sync.RWMutex
	snapshots map[string]codexWeeklyQuotaSnapshot
}

// ObserveCodexWeeklyQuota records a request-scoped Codex weekly quota reading.
// The auth manager transfers it to the selected credential when execution ends.
func ObserveCodexWeeklyQuota(opts cliproxyexecutor.Options, authID string, remainingPercent float64, resetAt time.Time) {
	if opts.Metadata == nil || authID == "" || !validCodexWeeklyQuota(remainingPercent, resetAt) {
		return
	}
	observations, _ := opts.Metadata[codexWeeklyQuotaObservationsMetadataKey].(*codexWeeklyQuotaObservations)
	if observations == nil {
		observations = &codexWeeklyQuotaObservations{snapshots: make(map[string]codexWeeklyQuotaSnapshot)}
		opts.Metadata[codexWeeklyQuotaObservationsMetadataKey] = observations
	}
	observations.mu.Lock()
	observations.snapshots[authID] = codexWeeklyQuotaSnapshot{
		remainingPercent: remainingPercent,
		resetAt:          resetAt,
	}
	observations.mu.Unlock()
}

func codexWeeklyQuotaObservation(opts cliproxyexecutor.Options, authID string) (codexWeeklyQuotaSnapshot, bool) {
	if opts.Metadata == nil || authID == "" {
		return codexWeeklyQuotaSnapshot{}, false
	}
	observations, _ := opts.Metadata[codexWeeklyQuotaObservationsMetadataKey].(*codexWeeklyQuotaObservations)
	if observations == nil {
		return codexWeeklyQuotaSnapshot{}, false
	}
	observations.mu.RLock()
	snapshot, ok := observations.snapshots[authID]
	observations.mu.RUnlock()
	return snapshot, ok
}

func codexColdBindingCandidates(ctx context.Context, auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	refreshCodexWeeklyQuotas(ctx, auths)
	return selectCodexWeeklyQuotaCandidates(auths, time.Now())
}

func selectCodexWeeklyQuotaCandidates(auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	unknown := make([]*Auth, 0, len(auths))
	known := make([]*Auth, 0, len(auths))
	healthy := make([]*Auth, 0, len(auths))
	lowestHealthy := make([]*Auth, 0, len(auths))
	lowestRemaining := 101.0
	hasLow := false
	hasCodexAuth := false
	for _, auth := range auths {
		if !isCodexAuth(auth) {
			continue
		}
		hasCodexAuth = true
		remaining, quotaKnown := auth.codexWeeklyQuotaRemaining(now)
		if !quotaKnown {
			unknown = append(unknown, auth)
			continue
		}
		known = append(known, auth)
		if remaining < codexWeeklyQuotaThreshold {
			hasLow = true
			continue
		}
		healthy = append(healthy, auth)
		switch {
		case remaining < lowestRemaining:
			lowestRemaining = remaining
			lowestHealthy = append(lowestHealthy[:0], auth)
		case remaining == lowestRemaining:
			lowestHealthy = append(lowestHealthy, auth)
		}
	}
	if !hasCodexAuth {
		return auths
	}
	if len(unknown) > 0 {
		return unknown
	}
	if len(healthy) == 0 {
		return known
	}
	if hasLow {
		return healthy
	}
	if len(lowestHealthy) > 0 {
		return lowestHealthy
	}
	return auths
}

func refreshCodexWeeklyQuotas(ctx context.Context, auths []*Auth) {
	var wg sync.WaitGroup
	for _, auth := range auths {
		if !isCodexAuth(auth) {
			continue
		}
		wg.Add(1)
		go func(candidate *Auth) {
			defer wg.Done()
			remaining, resetAt, ok := fetchCodexWeeklyQuota(ctx, candidate)
			if ok {
				candidate.observeCodexWeeklyQuota(remaining, resetAt)
			}
		}(auth)
	}
	wg.Wait()
}

func fetchCodexWeeklyQuota(ctx context.Context, auth *Auth) (float64, time.Time, bool) {
	if auth == nil || auth.Metadata == nil {
		return 0, time.Time{}, false
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	accountID, _ := auth.Metadata["account_id"].(string)
	accessToken = strings.TrimSpace(accessToken)
	accountID = strings.TrimSpace(accountID)
	if accessToken == "" || accountID == "" {
		return 0, time.Time{}, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, codexWeeklyQuotaProbeTimeout)
	defer cancel()
	req, errRequest := http.NewRequestWithContext(probeCtx, http.MethodGet, codexWeeklyUsageURL, nil)
	if errRequest != nil {
		return 0, time.Time{}, false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("ChatGPT-Account-Id", accountID)
	req.Header.Set("Accept", "application/json")

	response, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		return 0, time.Time{}, false
	}
	var usage codexUsageResponse
	errDecode := json.NewDecoder(io.LimitReader(response.Body, codexWeeklyUsageBodyLimit)).Decode(&usage)
	errClose := response.Body.Close()
	if response.StatusCode != http.StatusOK || errDecode != nil || errClose != nil {
		return 0, time.Time{}, false
	}

	now := time.Now()
	for _, window := range []*codexUsageWindow{usage.RateLimit.PrimaryWindow, usage.RateLimit.SecondaryWindow} {
		if window == nil || window.LimitWindowSeconds != int64((7*24*time.Hour)/time.Second) {
			continue
		}
		resetAt := time.Unix(window.ResetAt, 0)
		if !resetAt.After(now) && window.ResetAfterSeconds > 0 {
			resetAt = now.Add(time.Duration(window.ResetAfterSeconds) * time.Second)
		}
		remaining := math.Max(0, math.Min(100, 100-window.UsedPercent))
		if validCodexWeeklyQuota(remaining, resetAt) {
			return remaining, resetAt, true
		}
	}
	return 0, time.Time{}, false
}

func isCodexAuth(auth *Auth) bool {
	return auth != nil && executorKeyFromAuth(auth) == "codex"
}
