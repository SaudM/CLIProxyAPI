package auth

import (
	"context"
	"errors"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

const (
	credentialLimitWindowSeconds int64 = 60
	// credentialLimitConcurrencyRetry is the poll interval reported when a credential
	// is saturated on in-flight requests: slot release has no deterministic instant.
	credentialLimitConcurrencyRetry = 250 * time.Millisecond
	credentialLimitDayKeyLayout     = "2006-01-02"
)

// credentialLimits are the effective limits for one credential. Zero means unlimited.
type credentialLimits struct {
	RPM           int
	TPM           int
	MaxConcurrent int
	// RPD / TPD are per calendar day in Location.
	RPD int
	TPD int
	// MaxSessions caps distinct downstream sessions seen within SessionWindow.
	MaxSessions   int
	SessionWindow time.Duration
	// ActiveHours is a daily window in Location; ActiveHoursJitter shifts its edges per credential and day.
	ActiveHours       internalconfig.ActiveHours
	ActiveHoursJitter time.Duration
	Location          *time.Location
	// base* keep the configured values before jitter, for display only.
	baseRPM, baseTPM, baseRPD, baseTPD int
}

func (l credentialLimits) enabled() bool {
	return l.RPM > 0 || l.TPM > 0 || l.MaxConcurrent > 0 || l.RPD > 0 || l.TPD > 0 || l.MaxSessions > 0 || !l.ActiveHours.IsZero()
}

func (l credentialLimits) location() *time.Location {
	if l.Location != nil {
		return l.Location
	}
	return time.Local
}

func (l credentialLimits) sessionWindow() time.Duration {
	if l.SessionWindow <= 0 {
		return internalconfig.DefaultCredentialSessionWindowMinutes * time.Minute
	}
	return l.SessionWindow
}

// limitWindow is a rolling 60 second window made of one-second buckets.
// Stale buckets are ignored on read and overwritten on write, so no rotation pass is needed.
type limitWindow struct {
	sec [credentialLimitWindowSeconds]int64
	val [credentialLimitWindowSeconds]int64
}

func (w *limitWindow) add(sec int64, n int64) {
	idx := sec % credentialLimitWindowSeconds
	if w.sec[idx] != sec {
		w.sec[idx] = sec
		w.val[idx] = 0
	}
	w.val[idx] += n
}

func (w *limitWindow) live(nowSec int64, idx int64) bool {
	return w.val[idx] != 0 && w.sec[idx] > nowSec-credentialLimitWindowSeconds && w.sec[idx] <= nowSec
}

func (w *limitWindow) sum(nowSec int64) int64 {
	var total int64
	for idx := int64(0); idx < credentialLimitWindowSeconds; idx++ {
		if w.live(nowSec, idx) {
			total += w.val[idx]
		}
	}
	return total
}

// recoverAt returns the earliest instant at which the window sum drops below limit.
func (w *limitWindow) recoverAt(nowSec int64, limit int64) time.Time {
	type bucket struct{ sec, val int64 }
	buckets := make([]bucket, 0, credentialLimitWindowSeconds)
	var total int64
	for idx := int64(0); idx < credentialLimitWindowSeconds; idx++ {
		if w.live(nowSec, idx) {
			buckets = append(buckets, bucket{sec: w.sec[idx], val: w.val[idx]})
			total += w.val[idx]
		}
	}
	if total < limit {
		return time.Time{}
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].sec < buckets[j].sec })
	for _, b := range buckets {
		total -= b.val
		if total < limit {
			return time.Unix(b.sec+credentialLimitWindowSeconds, 0)
		}
	}
	return time.Unix(nowSec+credentialLimitWindowSeconds, 0)
}

// oldestLive returns the oldest bucket second still inside the window, or false when empty.
func (w *limitWindow) oldestLive(nowSec int64) (int64, bool) {
	var oldest int64
	found := false
	for idx := int64(0); idx < credentialLimitWindowSeconds; idx++ {
		if w.live(nowSec, idx) && (!found || w.sec[idx] < oldest) {
			oldest = w.sec[idx]
			found = true
		}
	}
	return oldest, found
}

type credentialLimitEntry struct {
	rpm      limitWindow
	tpm      limitWindow
	inFlight int
	// Daily counters roll over at local midnight in loc; loc is remembered from the
	// last admission so token usage recorded later lands in the right day.
	loc         *time.Location
	dayKey      string
	dayRequests int64
	dayTokens   int64
	// sessions maps a downstream session key to the last instant it was admitted.
	sessions map[string]time.Time
}

// rollDay resets the daily counters when the local calendar day changed.
func (e *credentialLimitEntry) rollDay(now time.Time, loc *time.Location) {
	if loc != nil {
		e.loc = loc
	}
	if e.loc == nil {
		e.loc = time.Local
	}
	if key := now.In(e.loc).Format(credentialLimitDayKeyLayout); key != e.dayKey {
		e.dayKey = key
		e.dayRequests = 0
		e.dayTokens = 0
	}
}

// pruneSessions forgets sessions idle for longer than window and returns the oldest live one.
func (e *credentialLimitEntry) pruneSessions(now time.Time, window time.Duration) (oldest time.Time) {
	for key, seen := range e.sessions {
		if now.Sub(seen) >= window {
			delete(e.sessions, key)
			continue
		}
		if oldest.IsZero() || seen.Before(oldest) {
			oldest = seen
		}
	}
	return oldest
}

// credentialLimiter tracks per-credential request, token, session and in-flight counters.
// It has its own lock and never calls back into the Manager.
type credentialLimiter struct {
	mu      sync.Mutex
	entries map[string]*credentialLimitEntry
	now     func() time.Time
}

func newCredentialLimiter() *credentialLimiter {
	return &credentialLimiter{entries: make(map[string]*credentialLimitEntry), now: time.Now}
}

// credentialLease holds one in-flight slot on a credential until released.
type credentialLease struct {
	limiter *credentialLimiter
	authID  string
	once    sync.Once
}

// Release returns the in-flight slot. Safe to call more than once and on a nil lease.
func (l *credentialLease) Release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(func() { l.limiter.release(l.authID) })
}

func (l *credentialLimiter) entryLocked(authID string) *credentialLimitEntry {
	entry := l.entries[authID]
	if entry == nil {
		entry = &credentialLimitEntry{}
		l.entries[authID] = entry
	}
	return entry
}

// jitterFraction maps seed to a stable value in [-1, 1).
func jitterFraction(seed string) float64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	unit := float64(h.Sum64()>>11) / float64(uint64(1)<<53)
	return 2*unit - 1
}

// jitterOffset returns a stable duration in [-span, span) for seed.
func jitterOffset(seed string, span time.Duration) time.Duration {
	if span <= 0 {
		return 0
	}
	return time.Duration(jitterFraction(seed) * float64(span))
}

// jitteredLimit scales base by a stable per-credential offset within ±percent, never below 1.
func jitteredLimit(authID, name string, base, percent int) int {
	if base <= 0 || percent <= 0 {
		return base
	}
	scaled := int(math.Round(float64(base) * (1 + jitterFraction(authID+"|"+name)*float64(percent)/100)))
	if scaled < 1 {
		return 1
	}
	return scaled
}

// activeWindowFor returns the open/close instants of the window that starts on local day
// `day` (midnight in the day's location), with the per-credential, per-day edge jitter.
func activeWindowFor(authID string, hours internalconfig.ActiveHours, day time.Time, jitter time.Duration) (open, closeAt time.Time) {
	open = day.Add(time.Duration(hours.Start) * time.Minute)
	closeAt = day.Add(time.Duration(hours.End) * time.Minute)
	if hours.Wraps() {
		closeAt = closeAt.Add(24 * time.Hour)
	}
	if jitter > 0 {
		key := day.Format(credentialLimitDayKeyLayout)
		open = open.Add(jitterOffset(authID+"|open|"+key, jitter))
		closeAt = closeAt.Add(jitterOffset(authID+"|close|"+key, jitter))
	}
	return open, closeAt
}

// activeHoursState reports whether the credential is inside its window at now and the
// instant of the next edge (close when open, next open when closed).
func activeHoursState(authID string, hours internalconfig.ActiveHours, loc *time.Location, jitter time.Duration, now time.Time) (bool, time.Time) {
	if hours.IsZero() {
		return true, time.Time{}
	}
	local := now.In(loc)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	// A window that wraps midnight may have opened yesterday.
	for _, day := range []time.Time{today.AddDate(0, 0, -1), today} {
		open, closeAt := activeWindowFor(authID, hours, day, jitter)
		if !now.Before(open) && now.Before(closeAt) {
			return true, closeAt
		}
	}
	for _, day := range []time.Time{today, today.AddDate(0, 0, 1)} {
		if open, _ := activeWindowFor(authID, hours, day, jitter); open.After(now) {
			return false, open
		}
	}
	return false, today.AddDate(0, 0, 2)
}

func nextLocalMidnight(now time.Time, loc *time.Location) time.Time {
	local := now.In(loc)
	return time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, loc)
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// blockedUntilLocked evaluates limits without admitting anything. A zero result means
// admissible. It only rolls the day and prunes idle sessions, never counts.
func (l *credentialLimiter) blockedUntilLocked(authID string, entry *credentialLimitEntry, limits credentialLimits, sessionKey string, now time.Time) time.Time {
	var blocked time.Time
	nowSec := now.Unix()
	loc := limits.location()
	if awake, next := activeHoursState(authID, limits.ActiveHours, loc, limits.ActiveHoursJitter, now); !awake {
		blocked = laterOf(blocked, next)
	}
	if limits.MaxConcurrent > 0 && entry.inFlight >= limits.MaxConcurrent {
		blocked = laterOf(blocked, now.Add(credentialLimitConcurrencyRetry))
	}
	if limits.RPM > 0 {
		blocked = laterOf(blocked, entry.rpm.recoverAt(nowSec, int64(limits.RPM)))
	}
	if limits.TPM > 0 {
		blocked = laterOf(blocked, entry.tpm.recoverAt(nowSec, int64(limits.TPM)))
	}
	entry.rollDay(now, loc)
	if (limits.RPD > 0 && entry.dayRequests >= int64(limits.RPD)) || (limits.TPD > 0 && entry.dayTokens >= int64(limits.TPD)) {
		blocked = laterOf(blocked, nextLocalMidnight(now, loc))
	}
	if limits.MaxSessions > 0 && sessionKey != "" {
		oldest := entry.pruneSessions(now, limits.sessionWindow())
		// A session already served by this credential is never turned away by the cap.
		if _, known := entry.sessions[sessionKey]; !known && len(entry.sessions) >= limits.MaxSessions {
			blocked = laterOf(blocked, oldest.Add(limits.sessionWindow()))
		}
	}
	return blocked
}

// tryAcquire admits one request when every limit allows it. On refusal nothing is
// counted and blockedUntil reports the earliest instant worth retrying. sessionKey
// identifies the downstream session; empty means the request has none.
func (l *credentialLimiter) tryAcquire(authID, sessionKey string, limits credentialLimits) (*credentialLease, time.Time, bool) {
	if l == nil || !limits.enabled() {
		return nil, time.Time{}, true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entryLocked(authID)
	if blocked := l.blockedUntilLocked(authID, entry, limits, sessionKey, now); !blocked.IsZero() {
		return nil, blocked, false
	}
	entry.inFlight++
	entry.rpm.add(now.Unix(), 1)
	entry.dayRequests++
	if sessionKey != "" {
		if entry.sessions == nil {
			entry.sessions = make(map[string]time.Time)
		}
		entry.sessions[sessionKey] = now
	}
	return &credentialLease{limiter: l, authID: authID}, time.Time{}, true
}

// nextAvailable reports how long until the credential would next admit a request,
// measured on the limiter's own clock. Zero means it would admit one now.
func (l *credentialLimiter) nextAvailable(authID, sessionKey string, limits credentialLimits) time.Duration {
	if l == nil || !limits.enabled() {
		return 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[authID]
	if entry == nil {
		// Active hours apply before the credential has any state; evaluate on a scratch entry.
		entry = &credentialLimitEntry{}
	}
	blocked := l.blockedUntilLocked(authID, entry, limits, sessionKey, now)
	if blocked.IsZero() {
		return 0
	}
	if wait := blocked.Sub(now); wait > 0 {
		return wait
	}
	return 0
}

func (l *credentialLimiter) release(authID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// A removed credential must not be resurrected by a late release.
	if entry := l.entries[authID]; entry != nil && entry.inFlight > 0 {
		entry.inFlight--
	}
}

func (l *credentialLimiter) recordTokens(authID string, tokens int64) {
	if l == nil || tokens <= 0 || strings.TrimSpace(authID) == "" {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entryLocked(authID)
	entry.tpm.add(now.Unix(), tokens)
	entry.rollDay(now, nil)
	entry.dayTokens += tokens
}

func (l *credentialLimiter) remove(authID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, authID)
}

// CredentialLimitStatus is the management-facing snapshot of one credential's limits and usage.
type CredentialLimitStatus struct {
	RPM           int
	TPM           int
	MaxConcurrent int
	RPD           int
	TPD           int
	MaxSessions   int
	// *Base are the configured values before per-credential jitter.
	RPMBase        int
	TPMBase        int
	RPDBase        int
	TPDBase        int
	RPMUsed        int64
	TPMUsed        int64
	RPDUsed        int64
	TPDUsed        int64
	InFlight       int
	ActiveSessions int
	SessionWindow  time.Duration
	// RPMResetsIn / TPMResetsIn report when the oldest window bucket expires; zero when idle.
	RPMResetsIn time.Duration
	TPMResetsIn time.Duration
	// DayResetsIn is the time until the next local midnight; zero when no daily limit is set.
	DayResetsIn time.Duration
	ActiveHours string
	Timezone    string
	// Awake is false while the active-hours window is closed. AwakeChangesAt is the next
	// window edge (close when awake, open when asleep); zero when no window is set.
	Awake          bool
	AwakeChangesAt time.Time
}

func (l *credentialLimiter) snapshot(authID string, limits credentialLimits) CredentialLimitStatus {
	status := CredentialLimitStatus{
		RPM: limits.RPM, TPM: limits.TPM, MaxConcurrent: limits.MaxConcurrent,
		RPD: limits.RPD, TPD: limits.TPD, MaxSessions: limits.MaxSessions,
		RPMBase: limits.baseRPM, TPMBase: limits.baseTPM, RPDBase: limits.baseRPD, TPDBase: limits.baseTPD,
		SessionWindow: limits.sessionWindow(),
		ActiveHours:   limits.ActiveHours.String(),
		Timezone:      limits.location().String(),
		Awake:         true,
	}
	if l == nil {
		return status
	}
	now := l.now()
	nowSec := now.Unix()
	loc := limits.location()
	status.Awake, status.AwakeChangesAt = activeHoursState(authID, limits.ActiveHours, loc, limits.ActiveHoursJitter, now)
	if limits.RPD > 0 || limits.TPD > 0 {
		status.DayResetsIn = nextLocalMidnight(now, loc).Sub(now)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[authID]
	if entry == nil {
		return status
	}
	entry.rollDay(now, loc)
	status.RPMUsed = entry.rpm.sum(nowSec)
	status.TPMUsed = entry.tpm.sum(nowSec)
	status.RPDUsed = entry.dayRequests
	status.TPDUsed = entry.dayTokens
	status.InFlight = entry.inFlight
	entry.pruneSessions(now, limits.sessionWindow())
	status.ActiveSessions = len(entry.sessions)
	if oldest, ok := entry.rpm.oldestLive(nowSec); ok {
		status.RPMResetsIn = time.Unix(oldest+credentialLimitWindowSeconds, 0).Sub(now)
	}
	if oldest, ok := entry.tpm.oldestLive(nowSec); ok {
		status.TPMResetsIn = time.Unix(oldest+credentialLimitWindowSeconds, 0).Sub(now)
	}
	return status
}

// SetCredentialLimits publishes the global credential-limits defaults. fallbackTimezone
// is the clock used for daily budgets and active hours when a credential has none of
// its own (normally claude-header-defaults.timezone); empty means the server's local time.
func (m *Manager) SetCredentialLimits(cfg internalconfig.CredentialLimits, fallbackTimezone string) {
	if m == nil {
		return
	}
	cfg.Normalize()
	m.credentialLimits.Store(&cfg)
	fallbackTimezone = strings.TrimSpace(fallbackTimezone)
	m.credentialTimezone.Store(&fallbackTimezone)
}

func (m *Manager) credentialLimitsConfig() internalconfig.CredentialLimits {
	if m == nil {
		return internalconfig.CredentialLimits{}
	}
	if cfg := m.credentialLimits.Load(); cfg != nil {
		return *cfg
	}
	return internalconfig.CredentialLimits{}
}

var credentialLocationCache sync.Map // timezone name -> *time.Location

func loadCredentialLocation(name string) (*time.Location, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, false
	}
	if cached, ok := credentialLocationCache.Load(name); ok {
		return cached.(*time.Location), true
	}
	loc, errLoad := time.LoadLocation(name)
	if errLoad != nil {
		return nil, false
	}
	credentialLocationCache.Store(name, loc)
	return loc, true
}

// credentialLocation resolves the clock a credential lives in: its own timezone
// (pool or credential), then the configured fallback, then the server's local time.
func (m *Manager) credentialLocation(auth *Auth) *time.Location {
	if auth != nil {
		if auth.Attributes != nil {
			if loc, ok := loadCredentialLocation(auth.Attributes[AttributeTimezone]); ok {
				return loc
			}
		}
		if value, ok := auth.Metadata[AttributeTimezone].(string); ok {
			if loc, ok := loadCredentialLocation(value); ok {
				return loc
			}
		}
	}
	if m != nil {
		if fallback := m.credentialTimezone.Load(); fallback != nil {
			if loc, ok := loadCredentialLocation(*fallback); ok {
				return loc
			}
		}
	}
	return time.Local
}

// effectiveCredentialLimits resolves per-auth overrides, then provider defaults, then
// globals, and applies the per-credential jitter.
func (m *Manager) effectiveCredentialLimits(auth *Auth) credentialLimits {
	if m == nil || auth == nil {
		return credentialLimits{}
	}
	cfg := m.credentialLimitsConfig()
	resolved := cfg.Resolve(strings.ToLower(strings.TrimSpace(auth.Provider)), executorKeyFromAuth(auth))
	if value, ok := auth.RPMOverride(); ok {
		resolved.RPM = value
	}
	if value, ok := auth.TPMOverride(); ok {
		resolved.TPM = value
	}
	if value, ok := auth.MaxConcurrentOverride(); ok {
		resolved.MaxConcurrent = value
	}
	if value, ok := auth.RPDOverride(); ok {
		resolved.RPD = value
	}
	if value, ok := auth.TPDOverride(); ok {
		resolved.TPD = value
	}
	if value, ok := auth.MaxSessionsOverride(); ok {
		resolved.MaxSessions = value
	}
	if value, ok := auth.ActiveHoursOverride(); ok {
		resolved.ActiveHours = value
	}
	limits := credentialLimits{
		RPM:           jitteredLimit(auth.ID, "rpm", resolved.RPM, cfg.LimitJitterPercent),
		TPM:           jitteredLimit(auth.ID, "tpm", resolved.TPM, cfg.LimitJitterPercent),
		MaxConcurrent: resolved.MaxConcurrent,
		RPD:           jitteredLimit(auth.ID, "rpd", resolved.RPD, cfg.LimitJitterPercent),
		TPD:           jitteredLimit(auth.ID, "tpd", resolved.TPD, cfg.LimitJitterPercent),
		MaxSessions:   resolved.MaxSessions,
		SessionWindow: cfg.SessionWindow(),
		Location:      m.credentialLocation(auth),
		baseRPM:       resolved.RPM,
		baseTPM:       resolved.TPM,
		baseRPD:       resolved.RPD,
		baseTPD:       resolved.TPD,
	}
	// Windows are validated on config load and on management writes; an unparsable
	// value that slipped into an auth file by hand means "always on".
	limits.ActiveHours, _ = internalconfig.ParseActiveHours(resolved.ActiveHours)
	if !limits.ActiveHours.IsZero() {
		limits.ActiveHoursJitter = time.Duration(cfg.ActiveHoursJitterMinutes) * time.Minute
	}
	return limits
}

// acquireCredentialLease admits the auth under its effective limits. A nil lease with
// ok=true means no limit applies to this credential.
func (m *Manager) acquireCredentialLease(auth *Auth, sessionKey string) (*credentialLease, time.Time, bool) {
	if m == nil || auth == nil {
		return nil, time.Time{}, true
	}
	return m.limiter.tryAcquire(auth.ID, sessionKey, m.effectiveCredentialLimits(auth))
}

// credentialSessionKey identifies the downstream session a request belongs to, for the
// per-credential session cap. Only explicit client session identifiers count; subagents
// collapse onto their root session, and requests without an identifier are not sessions.
func credentialSessionKey(opts cliproxyexecutor.Options, req cliproxyexecutor.Request) string {
	info, ok := cliproxysession.ExtractSessionInfo(opts.Headers, req.Payload, opts.Metadata)
	if !ok || info.ClientType == "lcp" {
		return ""
	}
	key := strings.TrimSpace(info.SessionID)
	if idx := strings.Index(key, ":agent:"); idx >= 0 {
		key = key[:idx]
	}
	return key
}

// RecordCredentialTokens adds consumed tokens to the auth's rolling TPM window and daily budget.
func (m *Manager) RecordCredentialTokens(authID string, tokens int64) {
	if m == nil {
		return
	}
	m.limiter.recordTokens(strings.TrimSpace(authID), tokens)
}

// CredentialLimitStatus returns the effective limits and current usage for an auth.
func (m *Manager) CredentialLimitStatus(auth *Auth) CredentialLimitStatus {
	if m == nil || auth == nil {
		return CredentialLimitStatus{}
	}
	return m.limiter.snapshot(auth.ID, m.effectiveCredentialLimits(auth))
}

// CredentialLimitUsagePlugin feeds usage records into the manager's TPM windows.
type CredentialLimitUsagePlugin struct {
	manager *Manager
}

// NewCredentialLimitUsagePlugin creates a usage plugin bound to the manager.
func NewCredentialLimitUsagePlugin(manager *Manager) *CredentialLimitUsagePlugin {
	return &CredentialLimitUsagePlugin{manager: manager}
}

// HandleUsage records the request's counted tokens (cache reads excluded) against
// its auth. It only
// takes the limiter lock, so it cannot stall the usage dispatcher.
func (p *CredentialLimitUsagePlugin) HandleUsage(_ context.Context, record usage.Record) {
	if p == nil || p.manager == nil || strings.TrimSpace(record.AuthID) == "" {
		return
	}
	p.manager.RecordCredentialTokens(record.AuthID, usageRecordCountedTokens(record))
}

// usageRecordCountedTokens returns the tokens a request adds to the tpm/tpd
// budgets: uncached input, cache writes and output. Cache reads are excluded on
// purpose: Claude Code re-reads its whole cached context on every turn, so
// counting them makes one small turn look like 100k+ tokens and the budget stops
// describing what the account actually consumed.
func usageRecordCountedTokens(record usage.Record) int64 {
	if breakdown := record.Detail.TokenBreakdown; breakdown.Valid() && breakdown.TotalTokens > 0 {
		return breakdown.TotalTokens - breakdown.Input.CacheReadTokens
	}
	if record.Detail.TotalTokens > 0 {
		if counted := record.Detail.TotalTokens - record.Detail.CacheReadTokens; counted > 0 {
			return counted
		}
		return 0
	}
	return record.Detail.InputTokens + record.Detail.OutputTokens
}

// credentialLimitTracker is the per-execution-loop bookkeeping for local limits.
// It owns at most one active lease at a time and remembers the earliest instant
// at which a limiter-refused candidate would become admissible again.
type credentialLimitTracker struct {
	activeLease  *credentialLease
	refused      bool
	blockedUntil time.Time
}

// release frees the active lease, if any. Safe to call repeatedly.
func (t *credentialLimitTracker) release() {
	if t == nil || t.activeLease == nil {
		return
	}
	t.activeLease.Release()
	t.activeLease = nil
}

// hold takes ownership of a freshly acquired lease.
func (t *credentialLimitTracker) hold(lease *credentialLease) {
	if t == nil {
		return
	}
	t.activeLease = lease
}

// detach hands the active lease to another owner (e.g. the stream wrapper) without releasing it.
func (t *credentialLimitTracker) detach() *credentialLease {
	if t == nil {
		return nil
	}
	lease := t.activeLease
	t.activeLease = nil
	return lease
}

// noteRefusal records that a candidate was skipped because of a local limit.
func (t *credentialLimitTracker) noteRefusal(blockedUntil time.Time) {
	if t == nil {
		return
	}
	t.refused = true
	if t.blockedUntil.IsZero() || (!blockedUntil.IsZero() && blockedUntil.Before(t.blockedUntil)) {
		t.blockedUntil = blockedUntil
	}
}

// pickFailureError converts an "auth_not_found"/"auth_unavailable" pick failure into a
// typed 429 when the only reason no credential was usable is a local limit. lastErr
// must be nil: an upstream failure keeps its own error and status.
func (t *credentialLimitTracker) pickFailureError(m *Manager, lastErr error, errPick error) error {
	if t == nil || !t.refused || lastErr != nil || !isAuthUnavailablePickError(errPick) {
		return nil
	}
	now := time.Now()
	if m != nil && m.limiter != nil && m.limiter.now != nil {
		now = m.limiter.now()
	}
	return newCredentialLimitError("credential limits exceeded", t.blockedUntil.Sub(now))
}

func isAuthUnavailablePickError(err error) bool {
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(authErr.Code)) {
	case "auth_not_found", "auth_unavailable":
		return true
	default:
		return false
	}
}
