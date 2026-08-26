package helps

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const codexWeeklyWindowMinutes int64 = 7 * 24 * 60

// ObserveCodexWeeklyQuotaHeaders records a weekly quota reading from Codex HTTP headers.
func ObserveCodexWeeklyQuotaHeaders(opts cliproxyexecutor.Options, auth *cliproxyauth.Auth, headers http.Header) {
	if auth == nil || len(headers) == 0 {
		return
	}
	now := time.Now()
	for _, window := range []string{"Primary", "Secondary"} {
		prefix := "X-Codex-" + window + "-"
		minutes, errMinutes := strconv.ParseInt(strings.TrimSpace(headers.Get(prefix+"Window-Minutes")), 10, 64)
		usedPercent, errUsed := strconv.ParseFloat(strings.TrimSpace(headers.Get(prefix+"Used-Percent")), 64)
		if errMinutes != nil || errUsed != nil || minutes != codexWeeklyWindowMinutes {
			continue
		}
		resetAt, ok := codexQuotaResetAt(now, headers.Get(prefix+"Reset-At"), headers.Get(prefix+"Reset-After-Seconds"))
		if !ok {
			continue
		}
		observeCodexWeeklyUsedPercent(opts, auth.ID, usedPercent, resetAt)
	}
}

// ObserveCodexWeeklyQuotaEvent records a weekly quota reading from a Codex websocket event.
func ObserveCodexWeeklyQuotaEvent(opts cliproxyexecutor.Options, auth *cliproxyauth.Auth, payload []byte) {
	if auth == nil || gjson.GetBytes(payload, "type").String() != "codex.rate_limits" {
		return
	}
	now := time.Now()
	for _, window := range []string{"primary", "secondary"} {
		path := "rate_limits." + window
		minutes := gjson.GetBytes(payload, path+".window_minutes")
		usedPercent := gjson.GetBytes(payload, path+".used_percent")
		if minutes.Type != gjson.Number || usedPercent.Type != gjson.Number || minutes.Int() != codexWeeklyWindowMinutes {
			continue
		}
		resetAt, ok := codexQuotaEventResetAt(now, payload, path)
		if !ok {
			continue
		}
		observeCodexWeeklyUsedPercent(opts, auth.ID, usedPercent.Float(), resetAt)
	}
}

func observeCodexWeeklyUsedPercent(opts cliproxyexecutor.Options, authID string, usedPercent float64, resetAt time.Time) {
	if math.IsNaN(usedPercent) || math.IsInf(usedPercent, 0) || usedPercent < 0 {
		return
	}
	remainingPercent := 100 - usedPercent
	if remainingPercent < 0 {
		remainingPercent = 0
	}
	cliproxyauth.ObserveCodexWeeklyQuota(opts, authID, remainingPercent, resetAt)
}

func codexQuotaResetAt(now time.Time, rawResetAt, rawResetAfter string) (time.Time, bool) {
	if unixSeconds, errParse := strconv.ParseInt(strings.TrimSpace(rawResetAt), 10, 64); errParse == nil && unixSeconds > now.Unix() {
		return time.Unix(unixSeconds, 0), true
	}
	if seconds, errParse := strconv.ParseInt(strings.TrimSpace(rawResetAfter), 10, 64); errParse == nil && seconds > 0 {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	return time.Time{}, false
}

func codexQuotaEventResetAt(now time.Time, payload []byte, path string) (time.Time, bool) {
	if resetAt := gjson.GetBytes(payload, path+".reset_at"); resetAt.Exists() && resetAt.Int() > now.Unix() {
		return time.Unix(resetAt.Int(), 0), true
	}
	if resetAfter := gjson.GetBytes(payload, path+".reset_after_seconds"); resetAfter.Exists() && resetAfter.Int() > 0 {
		return now.Add(time.Duration(resetAfter.Int()) * time.Second), true
	}
	return time.Time{}, false
}
