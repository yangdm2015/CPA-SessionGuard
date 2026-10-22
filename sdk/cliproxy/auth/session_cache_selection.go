package auth

import "time"

// NewSessionCacheWithCapacity applies the upstream bound to non-strict caches.
// Strict persistent caches fail closed instead of evicting established bindings.
func NewSessionCacheWithCapacity(ttl time.Duration, maxEntries int) *SessionCache {
	c, _ := newSessionCacheWithStore(ttl, nil)
	c.mu.Lock()
	c.maxEntries = maxEntries
	c.mu.Unlock()
	return c
}

// setSessionAliases records selection order independently of TTL refreshes.
func (c *SessionCache) setSessionAliases(authID, provider, sessionID string, keys ...string) {
	if c == nil || authID == "" || len(keys) == 0 {
		return
	}
	if err := c.BindAliases(authID, keys...); err != nil {
		return
	}
	c.recordSessionSelection(authID, provider, sessionID, keys...)
}

func (c *SessionCache) recordSessionSelection(authID, provider, sessionID string, keys ...string) {
	if c == nil || len(keys) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[keys[0]]
	if !ok || entry.authID != authID {
		return
	}
	c.bindingSequence++
	binding := sessionBinding{sessionID: sessionID, provider: provider, sequence: c.bindingSequence}
	c.replaceAliasGroupsWithBindingLocked(authID, entry.expiresAt, entry.aliases, binding, entry)
}
