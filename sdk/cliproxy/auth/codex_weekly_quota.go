package auth

import (
	"math"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const codexWeeklyQuotaObservationsMetadataKey = "codex_weekly_quota_observations"

type codexWeeklyQuotaSnapshot struct {
	remainingPercent float64
	resetAt          time.Time
}

type codexWeeklyQuotaState struct {
	mu       sync.RWMutex
	snapshot codexWeeklyQuotaSnapshot
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

func codexColdBindingCandidates(auths []*Auth, now time.Time) []*Auth {
	hasHealthierCodexAuth := false
	for _, auth := range auths {
		if !isCodexAuth(auth) {
			continue
		}
		if remaining, known := auth.codexWeeklyQuotaRemaining(now); known && remaining > 5 {
			hasHealthierCodexAuth = true
			break
		}
	}
	if !hasHealthierCodexAuth {
		return auths
	}

	filtered := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		remaining, known := auth.codexWeeklyQuotaRemaining(now)
		if isCodexAuth(auth) && known && remaining <= 5 {
			continue
		}
		filtered = append(filtered, auth)
	}
	return filtered
}

func isCodexAuth(auth *Auth) bool {
	return auth != nil && executorKeyFromAuth(auth) == "codex"
}
