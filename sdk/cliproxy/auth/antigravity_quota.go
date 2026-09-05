package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

const (
	antigravityQuotaURL          = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
	antigravityQuotaProbeTimeout = 5 * time.Second
	antigravityQuotaCacheTTL     = 10 * time.Minute
)

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

func fetchAntigravityQuota(ctx context.Context, auth *Auth, proxyURL string) (AntigravityQuotaSnapshot, bool) {
	if auth == nil || auth.Metadata == nil {
		return AntigravityQuotaSnapshot{}, false
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
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

	req, errReq := http.NewRequestWithContext(probeCtx, http.MethodPost, antigravityQuotaURL, bytes.NewReader(data))
	if errReq != nil {
		return AntigravityQuotaSnapshot{}, false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)")

	client := &http.Client{}
	if proxyURL != "" {
		if transport, _, errP := proxyutil.BuildHTTPTransport(proxyURL); errP == nil && transport != nil {
			client.Transport = transport
		}
	}

	resp, errDo := client.Do(req)
	if errDo != nil {
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
		for _, b := range g.Buckets {
			t, _ := time.Parse(time.RFC3339, b.ResetTime)
			if strings.Contains(b.BucketID, "weekly") || b.Window == "weekly" {
				if snap.WeeklyResetAt.IsZero() || (!t.IsZero() && t.Before(snap.WeeklyResetAt)) {
					snap.WeeklyResetAt = t
					snap.WeeklyRemainingFraction = b.RemainingFraction
				}
			} else if strings.Contains(b.BucketID, "5h") || b.Window == "5h" {
				if snap.FiveHourResetAt.IsZero() || (!t.IsZero() && t.Before(snap.FiveHourResetAt)) {
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
