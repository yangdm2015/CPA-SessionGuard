package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxStableSessionAliases = 64
	maxStrictSessionEntries = 65536
)

var errSessionBindingConflict = errors.New("session binding belongs to another auth")

// sessionEntry stores an auth binding, its identifier aliases, and expiration.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
	aliases   []string
}

// SessionCache provides TTL-based session to auth mapping with automatic cleanup.
type SessionCache struct {
	mu             sync.RWMutex
	entries        map[string]sessionEntry
	ttl            time.Duration
	ttlUpdateCh    chan time.Duration
	stopCh         chan struct{}
	stopOnce       sync.Once
	refs           atomic.Int64
	store          SessionBindingStore
	storeErr       error
	restorePending bool
	strict         bool
}

// NewSessionCache creates a cache with the specified TTL.
// A background goroutine periodically cleans expired entries.
func NewSessionCache(ttl time.Duration) *SessionCache {
	cache, _ := newSessionCacheWithStore(ttl, nil)
	return cache
}

// NewSessionCacheWithStore restores unexpired bindings from store.
func NewSessionCacheWithStore(ttl time.Duration, store SessionBindingStore) (*SessionCache, error) {
	return newSessionCacheWithStoreMode(ttl, store, false)
}

func newSessionCacheWithStore(ttl time.Duration, store SessionBindingStore) (*SessionCache, error) {
	return newSessionCacheWithStoreMode(ttl, store, false)
}

func newSessionCacheWithStoreMode(ttl time.Duration, store SessionBindingStore, strict bool) (*SessionCache, error) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	c := &SessionCache{
		entries:     make(map[string]sessionEntry),
		ttl:         ttl,
		ttlUpdateCh: make(chan time.Duration, 1),
		stopCh:      make(chan struct{}),
		store:       store,
		strict:      strict,
	}
	c.refs.Store(1)
	if err := c.restore(); err != nil {
		c.storeErr = err
		c.restorePending = true
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
	restored := &SessionCache{entries: make(map[string]sessionEntry)}
	for _, record := range records {
		aliases := compactSessionAliases(mergeSessionAliases(nil, record.Aliases...))
		if record.AuthID == "" || len(aliases) == 0 || (!c.strict && !now.Before(record.ExpiresAt)) {
			continue
		}
		for _, alias := range aliases {
			if existing, ok := restored.entries[alias]; ok && existing.authID != record.AuthID {
				return fmt.Errorf("conflicting persisted session binding for %q", alias)
			}
		}
		restored.replaceAliasGroupsLocked(record.AuthID, record.ExpiresAt, aliases)
		if c.strict && len(restored.entries) > maxStrictSessionEntries {
			return fmt.Errorf("strict session binding capacity exceeded")
		}
	}
	c.entries = restored.entries
	return nil
}

func (c *SessionCache) SetStrict(strict bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.strict = strict
	c.mu.Unlock()
}

func (c *SessionCache) entryActiveLocked(now time.Time, entry sessionEntry) bool {
	return c.strict || now.Before(entry.expiresAt)
}

// EnsureStoreAvailable retries the operation that last failed without changing
// the recovery authority: failed loads are loaded again, while failed saves
// retry the current in-memory snapshot.
func (c *SessionCache) EnsureStoreAvailable() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureStoreAvailableLocked()
}

// SetTTL changes the lifetime used by subsequent binding refreshes. Existing
// entries keep their current expiry until they are touched.
func (c *SessionCache) SetTTL(ttl time.Duration) {
	if c == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.ttl = ttl
	c.mu.Unlock()
	interval := ttl / 2
	select {
	case c.ttlUpdateCh <- interval:
	default:
		select {
		case <-c.ttlUpdateCh:
		default:
		}
		select {
		case c.ttlUpdateCh <- interval:
		default:
		}
	}
}

func (c *SessionCache) ttlDuration() time.Duration {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ttl
}

func (c *SessionCache) ensureStoreAvailableLocked() error {
	if c.storeErr == nil {
		return nil
	}
	if c.restorePending {
		if err := c.restore(); err != nil {
			c.storeErr = err
			return err
		}
		c.restorePending = false
		c.storeErr = nil
		return nil
	}
	return c.persistLocked()
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
	if ok && c.entryActiveLocked(now, entry) {
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
	if c.entryActiveLocked(time.Now(), entry) {
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

// GetPersistent reads a binding only after recovering any pending store error.
// Strict bindings do not need TTL refreshes, so this avoids a full-store write
// on every cache hit.
func (c *SessionCache) GetPersistent(sessionID string) (string, bool, error) {
	if c == nil || sessionID == "" {
		return "", false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return "", false, err
	}
	entry, ok := c.entries[sessionID]
	if !ok || !c.entryActiveLocked(now, entry) {
		return "", false, nil
	}
	return entry.authID, true, nil
}

// FindUniqueAuthByPrefix finds an existing binding across model-specific keys.
// Conflicting auths fail closed because selecting either one could switch the
// account for an established session.
func (c *SessionCache) FindUniqueAuthByPrefix(prefix string) (string, bool, error) {
	if c == nil || prefix == "" {
		return "", false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return "", false, err
	}
	authID := ""
	for key, entry := range c.entries {
		if !strings.HasPrefix(key, prefix) || !c.entryActiveLocked(now, entry) {
			continue
		}
		if authID != "" && authID != entry.authID {
			return "", false, fmt.Errorf("conflicting strict session bindings for %q", prefix)
		}
		authID = entry.authID
	}
	return authID, authID != "", nil
}

// GetAndRefreshPersistent refreshes a binding and durably records the new expiry.
func (c *SessionCache) GetAndRefreshPersistent(sessionID string) (string, bool, error) {
	if sessionID == "" {
		return "", false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return "", false, err
	}
	entry, ok := c.entries[sessionID]
	if !ok {
		return "", false, nil
	}
	if !c.entryActiveLocked(now, entry) {
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
	return c.bindAliases(authID, false, sessionIDs...)
}

// BindAliasesStrict never replaces an active binding owned by another auth.
func (c *SessionCache) BindAliasesStrict(authID string, sessionIDs ...string) error {
	return c.bindAliases(authID, true, sessionIDs...)
}

// BindAliasesStrictForPrefixes atomically verifies every model-specific binding
// for a logical session before adding aliases for the selected model.
func (c *SessionCache) BindAliasesStrictForPrefixes(authID string, prefixes []string, sessionIDs ...string) error {
	if authID == "" {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return err
	}

	aliases := mergeSessionAliases(nil, sessionIDs...)
	previousGroups := make([]sessionEntry, 0, len(sessionIDs))
	for key, entry := range c.entries {
		if !c.entryActiveLocked(now, entry) || !hasAnySessionPrefix(key, prefixes) {
			continue
		}
		if entry.authID != authID {
			return fmt.Errorf("%w: %q", errSessionBindingConflict, key)
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	for _, sessionID := range sessionIDs {
		entry, ok := c.entries[sessionID]
		if !ok {
			continue
		}
		if !c.entryActiveLocked(now, entry) {
			c.removeAliasGroupLocked(entry)
			continue
		}
		if entry.authID != authID {
			return fmt.Errorf("%w: %q", errSessionBindingConflict, sessionID)
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	if len(aliases) == 0 {
		return nil
	}
	if !c.strictReplacementFitsLocked(aliases, previousGroups...) {
		return fmt.Errorf("strict session binding capacity exceeded")
	}
	c.replaceAliasGroupsLocked(authID, now.Add(c.ttl), aliases, previousGroups...)
	return c.persistLocked()
}

// RebindAliasesStrictForPrefixes atomically replaces any existing bindings matching prefixes
// with authID for authorized failovers (e.g. quota limit exhaustion).
func (c *SessionCache) RebindAliasesStrictForPrefixes(authID string, prefixes []string, sessionIDs ...string) error {
	if authID == "" {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return err
	}

	aliases := mergeSessionAliases(nil, sessionIDs...)
	previousGroups := make([]sessionEntry, 0, len(sessionIDs))
	for key, entry := range c.entries {
		if !c.entryActiveLocked(now, entry) || !hasAnySessionPrefix(key, prefixes) {
			continue
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	for _, sessionID := range sessionIDs {
		entry, ok := c.entries[sessionID]
		if !ok {
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

func hasAnySessionPrefix(key string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (c *SessionCache) bindAliases(authID string, rejectConflict bool, sessionIDs ...string) error {
	if authID == "" {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return err
	}

	aliases := mergeSessionAliases(nil, sessionIDs...)
	previousGroups := make([]sessionEntry, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		entry, ok := c.entries[sessionID]
		if !ok {
			continue
		}
		if !c.entryActiveLocked(now, entry) {
			c.removeAliasGroupLocked(entry)
			continue
		}
		if rejectConflict && entry.authID != authID {
			return fmt.Errorf("%w: %q", errSessionBindingConflict, sessionID)
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
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return false, err
	}
	primary, ok := c.entries[primaryID]
	if !ok || primary.authID != expectedAuthID || !c.entryActiveLocked(now, primary) {
		return false, nil
	}
	// Put the aliases observed by the current request first so compaction never
	// drops the newest continuation ID in favor of stale history.
	aliases := mergeSessionAliases(sessionIDs, primary.aliases...)
	previousGroups := []sessionEntry{primary}
	for _, alias := range aliases {
		entry, exists := c.entries[alias]
		if !exists || !c.entryActiveLocked(now, entry) {
			continue
		}
		if entry.authID != expectedAuthID {
			return false, fmt.Errorf("session alias is already bound to another auth")
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	if !c.strictReplacementFitsLocked(aliases, previousGroups...) {
		return false, fmt.Errorf("strict session binding capacity exceeded")
	}
	c.replaceAliasGroupsLocked(expectedAuthID, now.Add(c.ttl), aliases, previousGroups...)
	return true, c.persistLocked()
}

func (c *SessionCache) persistLocked() error {
	if c.store == nil {
		c.storeErr = nil
		c.restorePending = false
		return nil
	}
	err := c.store.Save(context.Background(), c.bindingRecordsLocked())
	c.storeErr = err
	if err == nil {
		c.restorePending = false
	}
	return err
}

func (c *SessionCache) bindingRecordsLocked() []SessionBindingRecord {
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
	return records
}

func (c *SessionCache) MigrateStore(store SessionBindingStore, strict bool) error {
	if c == nil || store == nil {
		return fmt.Errorf("session binding store is unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return err
	}
	if strict && !c.strict {
		now := time.Now()
		for _, entry := range c.entries {
			if !now.Before(entry.expiresAt) {
				c.removeAliasGroupLocked(entry)
			}
		}
	}
	if strict && len(c.entries) > maxStrictSessionEntries {
		return fmt.Errorf("strict session binding capacity exceeded")
	}
	if err := store.Save(context.Background(), c.bindingRecordsLocked()); err != nil {
		return err
	}
	c.store = store
	c.strict = strict
	c.storeErr = nil
	c.restorePending = false
	return nil
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

func (c *SessionCache) strictReplacementFitsLocked(aliases []string, previousGroups ...sessionEntry) bool {
	if !c.strict {
		return true
	}
	removed := make(map[string]struct{})
	for _, previous := range previousGroups {
		for _, alias := range previous.aliases {
			if current, ok := c.entries[alias]; ok && current.authID == previous.authID && current.expiresAt.Equal(previous.expiresAt) {
				removed[alias] = struct{}{}
			}
		}
	}
	added := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		if alias != "" {
			added[alias] = struct{}{}
		}
	}
	return len(c.entries)-len(removed)+len(added) <= maxStrictSessionEntries
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
	return c.TouchPersistentFor(sessionID, expectedAuthID, 0)
}

// TouchPersistentFor keeps a binding alive for at least minRemaining, in
// addition to the configured TTL used for ordinary activity refreshes.
func (c *SessionCache) TouchPersistentFor(sessionID, expectedAuthID string, minRemaining time.Duration) (bool, error) {
	if sessionID == "" || expectedAuthID == "" {
		return false, nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return false, err
	}
	entry, ok := c.entries[sessionID]
	if !ok || entry.authID != expectedAuthID || !c.entryActiveLocked(now, entry) {
		return false, nil
	}
	aliases := compactSessionAliases(mergeSessionAliases([]string{sessionID}, entry.aliases...))
	remaining := c.ttl
	if minRemaining > remaining {
		remaining = minRemaining
	}
	c.replaceAliasGroupsLocked(expectedAuthID, now.Add(remaining), aliases, entry)
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
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return false, err
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
	if err := c.ensureStoreAvailableLocked(); err != nil {
		c.mu.Unlock()
		return
	}
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
	if err := c.ensureStoreAvailableLocked(); err != nil {
		c.mu.Unlock()
		return
	}
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

func (c *SessionCache) retain() {
	if c != nil {
		c.refs.Add(1)
	}
}

func (c *SessionCache) release() {
	if c != nil && c.refs.Add(-1) == 0 {
		c.Stop()
	}
}

func (c *SessionCache) cleanupLoop() {
	c.mu.RLock()
	interval := c.ttl / 2
	c.mu.RUnlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case interval = <-c.ttlUpdateCh:
			if interval > 0 {
				ticker.Reset(interval)
			}
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *SessionCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		c.mu.Unlock()
		return
	}
	changed := false
	for sid, entry := range c.entries {
		if !c.entryActiveLocked(now, entry) {
			delete(c.entries, sid)
			changed = true
		}
	}
	if changed {
		_ = c.persistLocked()
	}
	c.mu.Unlock()
}
