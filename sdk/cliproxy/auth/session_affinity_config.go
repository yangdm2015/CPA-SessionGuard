package auth

// UpdateSessionAffinityOptions applies policy changes without discarding durable bindings.
func (m *Manager) UpdateSessionAffinityOptions(weeklyThreshold float64, subagents bool, rebindOn string) {
	m.selectorMu.Lock()
	defer m.selectorMu.Unlock()
	m.mu.RLock()
	affinity, ok := m.selector.(*SessionAffinitySelector)
	m.mu.RUnlock()
	if !ok || affinity == nil {
		return
	}
	affinity.mu.Lock()
	defer affinity.mu.Unlock()
	affinity.weeklyQuotaThreshold = weeklyThreshold
	affinity.subagentAffinity = subagents
	affinity.rebindOnQuotaOnly = normalizeSessionAffinityRebindOn(rebindOn) == SessionAffinityRebindOnQuota
}
