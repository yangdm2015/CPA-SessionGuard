package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxStableSessionAliases = 64

// sessionEntry stores an auth binding, its identifier aliases, and expiration.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
	aliases   []string
}

// SessionCache provides TTL-based session to auth mapping with automatic cleanup.
type SessionCache struct {
	mu       sync.RWMutex
	entries  map[string]sessionEntry
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
	store    SessionBindingStore
	storeErr error
}

// NewSessionCache creates a cache with the specified TTL.
// A background goroutine periodically cleans expired entries.
func NewSessionCache(ttl time.Duration) *SessionCache {
	cache, _ := newSessionCacheWithStore(ttl, nil)
	return cache
}

// NewSessionCacheWithStore restores unexpired bindings from store.
func NewSessionCacheWithStore(ttl time.Duration, store SessionBindingStore) (*SessionCache, error) {
	return newSessionCacheWithStore(ttl, store)
}

func newSessionCacheWithStore(ttl time.Duration, store SessionBindingStore) (*SessionCache, error) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	c := &SessionCache{
		entries: make(map[string]sessionEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
		store:   store,
	}
	if err := c.restore(); err != nil {
		c.storeErr = err
		go c.cleanupLoop()
		return c, err
	}
	go c.cleanupLoop()
	return c, nil
}

func (c *SessionCache) restore() error {
	if c == nil || c.store == nil {
		return nil
	}
	records, err := c.store.Load(context.Background())
	if err != nil {
		return err
	}
	now := time.Now()
	for _, record := range records {
		aliases := compactSessionAliases(mergeSessionAliases(nil, record.Aliases...))
		if record.AuthID == "" || len(aliases) == 0 || !now.Before(record.ExpiresAt) {
			continue
		}
		for _, alias := range aliases {
			if existing, ok := c.entries[alias]; ok && existing.authID != record.AuthID {
				return fmt.Errorf("conflicting persisted session binding for %q", alias)
			}
		}
		c.replaceAliasGroupsLocked(record.AuthID, record.ExpiresAt, aliases)
	}
	return nil
}

// Get retrieves the auth ID bound to a session, if still valid.
// Does NOT refresh the TTL on access.
func (c *SessionCache) Get(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	now := time.Now()
	c.mu.RLock()
	entry, ok := c.entries[sessionID]
	if ok && now.Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.authID, true
	}
	c.mu.RUnlock()
	if !ok {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok = c.entries[sessionID]
	if !ok {
		return "", false
	}
	if time.Now().Before(entry.expiresAt) {
		return entry.authID, true
	}
	c.removeAliasGroupLocked(entry)
	return "", false
}

// GetAndRefresh retrieves the auth ID bound to a session and refreshes the TTL
// for every identifier known to represent the same logical session.
func (c *SessionCache) GetAndRefresh(sessionID string) (string, bool) {
	authID, ok, _ := c.GetAndRefreshPersistent(sessionID)
	return authID, ok
}

// GetAndRefreshPersistent refreshes a binding and durably records the new expiry.
func (c *SessionCache) GetAndRefreshPersistent(sessionID string) (string, bool, error) {
	if sessionID == "" {
		return "", false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return "", false, c.storeErr
	}
	entry, ok := c.entries[sessionID]
	if !ok {
		return "", false, nil
	}
	if !now.Before(entry.expiresAt) {
		c.removeAliasGroupLocked(entry)
		return "", false, c.persistLocked()
	}

	aliases := compactSessionAliases(mergeSessionAliases([]string{sessionID}, entry.aliases...))
	c.replaceAliasGroupsLocked(entry.authID, now.Add(c.ttl), aliases, entry)
	return entry.authID, true, c.persistLocked()
}

// Set binds a session to an auth ID with TTL refresh. Existing aliases for the
// same logical session remain attached when the binding is refreshed or moved.
func (c *SessionCache) Set(sessionID, authID string) {
	c.SetAliases(authID, sessionID)
}

// SetAliases binds multiple identifiers for one logical session to an auth ID.
func (c *SessionCache) SetAliases(authID string, sessionIDs ...string) {
	_ = c.BindAliases(authID, sessionIDs...)
}

// BindAliases durably binds identifiers for one logical session to an auth.
func (c *SessionCache) BindAliases(authID string, sessionIDs ...string) error {
	if authID == "" {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return c.storeErr
	}

	aliases := mergeSessionAliases(nil, sessionIDs...)
	previousGroups := make([]sessionEntry, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		entry, ok := c.entries[sessionID]
		if !ok {
			continue
		}
		if !now.Before(entry.expiresAt) {
			c.removeAliasGroupLocked(entry)
			continue
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	if len(aliases) == 0 {
		return nil
	}
	c.replaceAliasGroupsLocked(authID, now.Add(c.ttl), aliases, previousGroups...)
	return c.persistLocked()
}

// BindAliasesIfMatch adds aliases only while primaryID is still bound to expectedAuthID.
func (c *SessionCache) BindAliasesIfMatch(primaryID, expectedAuthID string, sessionIDs ...string) (bool, error) {
	if primaryID == "" || expectedAuthID == "" {
		return false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return false, c.storeErr
	}
	primary, ok := c.entries[primaryID]
	if !ok || primary.authID != expectedAuthID || !now.Before(primary.expiresAt) {
		return false, nil
	}
	aliases := mergeSessionAliases(primary.aliases, sessionIDs...)
	previousGroups := []sessionEntry{primary}
	for _, alias := range aliases {
		entry, exists := c.entries[alias]
		if !exists || !now.Before(entry.expiresAt) {
			continue
		}
		if entry.authID != expectedAuthID {
			return false, fmt.Errorf("session alias is already bound to another auth")
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	c.replaceAliasGroupsLocked(expectedAuthID, now.Add(c.ttl), aliases, previousGroups...)
	return true, c.persistLocked()
}

func (c *SessionCache) persistLocked() error {
	if c.store == nil {
		return nil
	}
	records := make([]SessionBindingRecord, 0)
	seen := make(map[string]struct{})
	for _, entry := range c.entries {
		if len(entry.aliases) == 0 {
			continue
		}
		key := entry.authID + "\x00" + entry.expiresAt.UTC().Format(time.RFC3339Nano) + "\x00" + strings.Join(entry.aliases, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, SessionBindingRecord{
			AuthID: entry.authID, ExpiresAt: entry.expiresAt.UTC(), Aliases: append([]string(nil), entry.aliases...),
		})
	}
	err := c.store.Save(context.Background(), records)
	if err != nil {
		c.storeErr = err
	}
	return err
}

// StoreError reports a persistent storage failure that requires operator action.
func (c *SessionCache) StoreError() error {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.storeErr
}

func (c *SessionCache) replaceAliasGroupsLocked(authID string, expiresAt time.Time, aliases []string, previousGroups ...sessionEntry) {
	for _, previous := range previousGroups {
		c.removeAliasGroupLocked(previous)
	}
	entry := sessionEntry{authID: authID, expiresAt: expiresAt, aliases: aliases}
	for _, alias := range aliases {
		c.entries[alias] = entry
	}
}

func (c *SessionCache) removeAliasGroupLocked(entry sessionEntry) {
	for _, alias := range entry.aliases {
		current, ok := c.entries[alias]
		if !ok || current.authID != entry.authID || !current.expiresAt.Equal(entry.expiresAt) ||
			!equalSessionAliases(current.aliases, entry.aliases) {
			continue
		}
		delete(c.entries, alias)
	}
}

func compactSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, isLocalPromptCacheSessionAlias)
}

func compactHomeSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, func(alias string) bool {
		return strings.HasPrefix(alias, "pck:")
	})
}

func compactSessionAliasesWith(aliases []string, isPromptCacheAlias func(string) bool) []string {
	compacted := make([]string, 0, len(aliases))
	hasPromptCacheKey := false
	stableAliases := 0
	for _, alias := range aliases {
		if isPromptCacheAlias(alias) {
			if hasPromptCacheKey {
				continue
			}
			hasPromptCacheKey = true
		} else {
			if stableAliases >= maxStableSessionAliases {
				continue
			}
			stableAliases++
		}
		compacted = append(compacted, alias)
	}
	return compacted
}

func isLocalPromptCacheSessionAlias(alias string) bool {
	if strings.HasPrefix(alias, "pck:") {
		return true
	}
	_, sessionAndModel, ok := strings.Cut(alias, "::")
	return ok && strings.HasPrefix(sessionAndModel, "pck:")
}

func equalSessionAliases(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mergeSessionAliases(existing []string, candidates ...string) []string {
	aliases := make([]string, 0, len(existing)+len(candidates))
	seen := make(map[string]struct{}, cap(aliases))
	add := func(alias string) {
		if alias == "" {
			return
		}
		if _, ok := seen[alias]; ok {
			return
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	for _, alias := range existing {
		add(alias)
	}
	for _, alias := range candidates {
		add(alias)
	}
	return aliases
}

// Touch refreshes the expiration for a session binding if it currently matches expectedAuthID.
func (c *SessionCache) Touch(sessionID, expectedAuthID string) bool {
	touched, _ := c.TouchPersistent(sessionID, expectedAuthID)
	return touched
}

// TouchPersistent refreshes a matching binding and persists the new expiry.
func (c *SessionCache) TouchPersistent(sessionID, expectedAuthID string) (bool, error) {
	if sessionID == "" || expectedAuthID == "" {
		return false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return false, c.storeErr
	}
	entry, ok := c.entries[sessionID]
	if !ok || entry.authID != expectedAuthID || !now.Before(entry.expiresAt) {
		return false, nil
	}
	aliases := compactSessionAliases(mergeSessionAliases([]string{sessionID}, entry.aliases...))
	c.replaceAliasGroupsLocked(expectedAuthID, now.Add(c.ttl), aliases, entry)
	return true, c.persistLocked()
}

// CompareAndDelete removes the session binding only if it is currently bound to expectedAuthID.
func (c *SessionCache) CompareAndDelete(sessionID, expectedAuthID string) bool {
	deleted, _ := c.CompareAndDeletePersistent(sessionID, expectedAuthID)
	return deleted
}

// CompareAndDeletePersistent removes a matching binding and persists the change.
func (c *SessionCache) CompareAndDeletePersistent(sessionID, expectedAuthID string) (bool, error) {
	if sessionID == "" || expectedAuthID == "" {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return false, c.storeErr
	}
	entry, ok := c.entries[sessionID]
	if !ok || entry.authID != expectedAuthID {
		return false, nil
	}
	delete(c.entries, sessionID)
	for _, alias := range entry.aliases {
		if alias == sessionID {
			continue
		}
		current, exists := c.entries[alias]
		if !exists || current.authID != entry.authID {
			continue
		}
		filtered := make([]string, 0, len(current.aliases))
		for _, candidate := range current.aliases {
			if candidate != sessionID {
				filtered = append(filtered, candidate)
			}
		}
		current.aliases = filtered
		c.entries[alias] = current
	}
	return true, c.persistLocked()
}

// Invalidate removes a specific session binding without allowing another alias
// in the same group to recreate it on its next refresh.
func (c *SessionCache) Invalidate(sessionID string) {
	if sessionID == "" {
		return
	}
	c.mu.Lock()
	entry, ok := c.entries[sessionID]
	delete(c.entries, sessionID)
	if ok {
		for _, alias := range entry.aliases {
			if alias == sessionID {
				continue
			}
			current, exists := c.entries[alias]
			if !exists || current.authID != entry.authID {
				continue
			}
			filtered := make([]string, 0, len(current.aliases))
			for _, candidate := range current.aliases {
				if candidate != sessionID {
					filtered = append(filtered, candidate)
				}
			}
			current.aliases = filtered
			c.entries[alias] = current
		}
	}
	_ = c.persistLocked()
	c.mu.Unlock()
}

// InvalidateAuth removes all sessions bound to a specific auth ID.
// Used when an auth becomes unavailable.
func (c *SessionCache) InvalidateAuth(authID string) {
	if authID == "" {
		return
	}
	c.mu.Lock()
	for sid, entry := range c.entries {
		if entry.authID == authID {
			delete(c.entries, sid)
		}
	}
	_ = c.persistLocked()
	c.mu.Unlock()
}

// Stop terminates the background cleanup goroutine.
func (c *SessionCache) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

func (c *SessionCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *SessionCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	changed := false
	for sid, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, sid)
			changed = true
		}
	}
	if changed {
		_ = c.persistLocked()
	}
	c.mu.Unlock()
}
