package auth

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxStableSessionAliases  = 64
	maxStrictSessionEntries  = 65536
	defaultMaxSessionEntries = 65536
)

// sessionBinding records selection order independently of TTL refreshes and eviction order.
type sessionBinding struct {
	sessionID string
	provider  string
	sequence  uint64
}

var errSessionBindingConflict = errors.New("session binding belongs to another auth")

// sessionEntry stores an auth binding, its identifier aliases, and expiration.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
	aliases   []string
	binding   sessionBinding
}

// SessionCache provides TTL-based session to auth mapping with automatic cleanup.
type SessionCache struct {
	mu               sync.RWMutex
	entries          map[string]sessionEntry
	ttl              time.Duration
	ttlUpdateCh      chan time.Duration
	stopCh           chan struct{}
	stopOnce         sync.Once
	refs             atomic.Int64
	store            SessionBindingStore
	storeErr         error
	restorePending   bool
	strict           bool
	groups           map[string]sessionEntry
	evictionOrder    *list.List
	evictionElements map[string]*list.Element
	maxEntries       int
	sessionGroups    map[string]map[string]struct{}
	bindingSequence  uint64
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
		maxEntries:  defaultMaxSessionEntries,
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
	c.groups = restored.groups
	c.evictionOrder = restored.evictionOrder
	c.evictionElements = restored.evictionElements
	c.sessionGroups = restored.sessionGroups
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
	c.ensureInitializedLocked()
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

func (c *SessionCache) ensureInitializedLocked() {
	if c.sessionGroups == nil {
		c.sessionGroups = make(map[string]map[string]struct{})
	}
	if c.entries == nil {
		c.entries = make(map[string]sessionEntry)
	}
	if c.groups == nil {
		c.groups = make(map[string]sessionEntry)
	}
	if c.evictionOrder == nil {
		c.evictionOrder = list.New()
	}
	if c.evictionElements == nil {
		c.evictionElements = make(map[string]*list.Element)
	}
}

// Get retrieves the auth ID bound to a session, if still valid.
// Does NOT refresh the TTL on access.
func (c *SessionCache) Get(sessionID string) (string, bool) {
	if c == nil || sessionID == "" {
		return "", false
	}
	c.mu.RLock()
	now := time.Now()
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
	c.ensureInitializedLocked()
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
	now := time.Now()
	if c == nil || sessionID == "" {
		return "", false, nil
	}
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
	if c == nil {
		return
	}
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
	now := time.Now()
	if authID == "" {
		return nil
	}
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
	if c == nil || authID == "" {
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
	var binding sessionBinding
	for _, previous := range previousGroups {
		if previous.binding.sequence > binding.sequence {
			binding = previous.binding
		}
	}
	c.replaceAliasGroupsWithBindingLocked(authID, expiresAt, aliases, binding, previousGroups...)
}

func (c *SessionCache) replaceAliasGroupsWithBindingLocked(authID string, expiresAt time.Time, aliases []string, binding sessionBinding, previousGroups ...sessionEntry) {
	c.ensureInitializedLocked()
	for _, previous := range previousGroups {
		c.removeAliasGroupLocked(previous)
	}
	if len(aliases) == 0 {
		return
	}
	primaryKey := aliases[0]
	if existing, ok := c.groups[primaryKey]; ok {
		c.removeAliasGroupLocked(existing)
	}
	entry := sessionEntry{authID: authID, expiresAt: expiresAt, aliases: append([]string(nil), aliases...), binding: binding}
	c.groups[primaryKey] = entry
	if binding.sequence != 0 {
		if c.sessionGroups[binding.sessionID] == nil {
			c.sessionGroups[binding.sessionID] = make(map[string]struct{})
		}
		c.sessionGroups[binding.sessionID][primaryKey] = struct{}{}
	}
	for _, alias := range aliases {
		c.entries[alias] = entry
	}
	c.evictionElements[primaryKey] = c.evictionOrder.PushBack(primaryKey)
	if !c.strict && c.maxEntries > 0 && len(c.entries) > c.maxEntries {
		c.evictExcessLocked()
	}
}

func (c *SessionCache) evictExcessLocked() {
	for len(c.entries) > c.maxEntries {
		oldest := c.evictionOrder.Front()
		if oldest == nil {
			break
		}
		primaryKey, _ := oldest.Value.(string)
		group, ok := c.groups[primaryKey]
		if !ok {
			c.evictionOrder.Remove(oldest)
			delete(c.evictionElements, primaryKey)
			continue
		}
		c.removeAliasGroupLocked(group)
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
	if len(entry.aliases) == 0 {
		return
	}
	primaryKey := entry.aliases[0]
	if currentGroup, ok := c.groups[primaryKey]; ok && sameSessionEntryGroup(currentGroup, entry) {
		delete(c.groups, primaryKey)
		if groups := c.sessionGroups[entry.binding.sessionID]; groups != nil {
			delete(groups, primaryKey)
			if len(groups) == 0 {
				delete(c.sessionGroups, entry.binding.sessionID)
			}
		}
		if elem, ok := c.evictionElements[primaryKey]; ok {
			c.evictionOrder.Remove(elem)
			delete(c.evictionElements, primaryKey)
		}
	}
	for _, alias := range entry.aliases {
		current, ok := c.entries[alias]
		if !ok || current.authID != entry.authID || !current.expiresAt.Equal(entry.expiresAt) ||
			!equalSessionAliases(current.aliases, entry.aliases) {
			continue
		}
		delete(c.entries, alias)
	}
}

func sameSessionEntryGroup(left, right sessionEntry) bool {
	return left.authID == right.authID && left.expiresAt.Equal(right.expiresAt) &&
		equalSessionAliases(left.aliases, right.aliases)
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

// latestSessionAuth observes the newest live selection on the requested real providers.
// It does not refresh TTL or eviction order and visits only this session's groups.
func (c *SessionCache) latestSessionAuth(sessionID string, providers map[string]struct{}) string {
	if c == nil || sessionID == "" || len(providers) == 0 {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	var latest sessionEntry
	for key := range c.sessionGroups[sessionID] {
		entry := c.groups[key]
		if _, ok := providers[entry.binding.provider]; !ok || !now.Before(entry.expiresAt) {
			continue
		}
		if entry.binding.sequence > latest.binding.sequence {
			latest = entry
		}
	}
	return latest.authID
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
	now := time.Now()
	if c == nil || sessionID == "" || expectedAuthID == "" {
		return false, nil
	}
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
	if c == nil || sessionID == "" || expectedAuthID == "" {
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
	c.removeAliasGroupLocked(entry)

	surviving := make([]string, 0, len(entry.aliases))
	for _, alias := range entry.aliases {
		if alias != sessionID {
			surviving = append(surviving, alias)
		}
	}
	if len(surviving) > 0 {
		c.replaceAliasGroupsLocked(entry.authID, entry.expiresAt, surviving, entry)
	}
	return true, c.persistLocked()
}

// Invalidate removes a specific session binding without allowing another alias
// in the same group to recreate it on its next refresh.
func (c *SessionCache) Invalidate(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return
	}
	entry, ok := c.entries[sessionID]
	if !ok {
		return
	}
	c.removeAliasGroupLocked(entry)

	surviving := make([]string, 0, len(entry.aliases))
	for _, alias := range entry.aliases {
		if alias != sessionID {
			surviving = append(surviving, alias)
		}
	}
	if len(surviving) > 0 {
		c.replaceAliasGroupsLocked(entry.authID, entry.expiresAt, surviving, entry)
	}
	_ = c.persistLocked()
}

// InvalidateAuth removes all sessions bound to a specific auth ID.
// Used when an auth becomes unavailable.
func (c *SessionCache) InvalidateAuth(authID string) {
	if c == nil || authID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return
	}
	for _, group := range c.groups {
		if group.authID == authID {
			c.removeAliasGroupLocked(group)
		}
	}
	_ = c.persistLocked()
}

// Stop terminates the background cleanup goroutine.
func (c *SessionCache) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
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
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
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

// Len returns the current count of tracked session aliases.
func (c *SessionCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *SessionCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStoreAvailableLocked(); err != nil {
		return
	}
	changed := false
	for _, group := range c.groups {
		if !c.entryActiveLocked(now, group) {
			c.removeAliasGroupLocked(group)
			changed = true
		}
	}
	if changed {
		_ = c.persistLocked()
	}
}
