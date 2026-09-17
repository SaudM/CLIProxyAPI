package auth

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

const (
	credentialLimitWindowSeconds int64 = 60
	// credentialLimitConcurrencyRetry is the poll interval reported when a credential
	// is saturated on in-flight requests: slot release has no deterministic instant.
	credentialLimitConcurrencyRetry = 250 * time.Millisecond
)

// credentialLimits are the effective limits for one credential. Zero means unlimited.
type credentialLimits struct {
	RPM           int
	TPM           int
	MaxConcurrent int
}

func (l credentialLimits) enabled() bool {
	return l.RPM > 0 || l.TPM > 0 || l.MaxConcurrent > 0
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
}

// credentialLimiter tracks per-credential request, token and in-flight counters.
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

// blockedUntilLocked evaluates limits without mutating state. A zero result means admissible.
func (l *credentialLimiter) blockedUntilLocked(entry *credentialLimitEntry, limits credentialLimits, now time.Time) time.Time {
	var blocked time.Time
	nowSec := now.Unix()
	if limits.MaxConcurrent > 0 && entry.inFlight >= limits.MaxConcurrent {
		blocked = now.Add(credentialLimitConcurrencyRetry)
	}
	if limits.RPM > 0 {
		if next := entry.rpm.recoverAt(nowSec, int64(limits.RPM)); !next.IsZero() && next.After(blocked) {
			blocked = next
		}
	}
	if limits.TPM > 0 {
		if next := entry.tpm.recoverAt(nowSec, int64(limits.TPM)); !next.IsZero() && next.After(blocked) {
			blocked = next
		}
	}
	return blocked
}

// tryAcquire admits one request when every limit allows it. On refusal nothing is
// mutated and blockedUntil reports the earliest instant worth retrying.
func (l *credentialLimiter) tryAcquire(authID string, limits credentialLimits) (*credentialLease, time.Time, bool) {
	if l == nil || !limits.enabled() {
		return nil, time.Time{}, true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entryLocked(authID)
	if blocked := l.blockedUntilLocked(entry, limits, now); !blocked.IsZero() {
		return nil, blocked, false
	}
	entry.inFlight++
	entry.rpm.add(now.Unix(), 1)
	return &credentialLease{limiter: l, authID: authID}, time.Time{}, true
}

// nextAvailable reports how long until the credential would next admit a request,
// measured on the limiter's own clock. Zero means it would admit one now.
func (l *credentialLimiter) nextAvailable(authID string, limits credentialLimits) time.Duration {
	if l == nil || !limits.enabled() {
		return 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[authID]
	if entry == nil {
		return 0
	}
	blocked := l.blockedUntilLocked(entry, limits, now)
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
	l.entryLocked(authID).tpm.add(now.Unix(), tokens)
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
	RPMUsed       int64
	TPMUsed       int64
	InFlight      int
	// RPMResetsIn / TPMResetsIn report when the oldest window bucket expires; zero when idle.
	RPMResetsIn time.Duration
	TPMResetsIn time.Duration
}

func (l *credentialLimiter) snapshot(authID string, limits credentialLimits) CredentialLimitStatus {
	status := CredentialLimitStatus{RPM: limits.RPM, TPM: limits.TPM, MaxConcurrent: limits.MaxConcurrent}
	if l == nil {
		return status
	}
	now := l.now()
	nowSec := now.Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[authID]
	if entry == nil {
		return status
	}
	status.RPMUsed = entry.rpm.sum(nowSec)
	status.TPMUsed = entry.tpm.sum(nowSec)
	status.InFlight = entry.inFlight
	if oldest, ok := entry.rpm.oldestLive(nowSec); ok {
		status.RPMResetsIn = time.Unix(oldest+credentialLimitWindowSeconds, 0).Sub(now)
	}
	if oldest, ok := entry.tpm.oldestLive(nowSec); ok {
		status.TPMResetsIn = time.Unix(oldest+credentialLimitWindowSeconds, 0).Sub(now)
	}
	return status
}

// SetCredentialLimits publishes the global credential-limits defaults.
func (m *Manager) SetCredentialLimits(cfg internalconfig.CredentialLimits) {
	if m == nil {
		return
	}
	cfg.Normalize()
	m.credentialLimits.Store(&cfg)
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

// effectiveCredentialLimits resolves per-auth overrides, then provider defaults, then globals.
func (m *Manager) effectiveCredentialLimits(auth *Auth) credentialLimits {
	if m == nil || auth == nil {
		return credentialLimits{}
	}
	rpm, tpm, maxConcurrent := m.credentialLimitsConfig().Resolve(strings.ToLower(strings.TrimSpace(auth.Provider)), executorKeyFromAuth(auth))
	if value, ok := auth.RPMOverride(); ok {
		rpm = value
	}
	if value, ok := auth.TPMOverride(); ok {
		tpm = value
	}
	if value, ok := auth.MaxConcurrentOverride(); ok {
		maxConcurrent = value
	}
	return credentialLimits{RPM: rpm, TPM: tpm, MaxConcurrent: maxConcurrent}
}

// acquireCredentialLease admits the auth under its effective limits. A nil lease with
// ok=true means no limit applies to this credential.
func (m *Manager) acquireCredentialLease(auth *Auth) (*credentialLease, time.Time, bool) {
	if m == nil || auth == nil {
		return nil, time.Time{}, true
	}
	return m.limiter.tryAcquire(auth.ID, m.effectiveCredentialLimits(auth))
}

// RecordCredentialTokens adds consumed tokens to the auth's rolling TPM window.
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

// HandleUsage records the request's total token count against its auth. It only
// takes the limiter lock, so it cannot stall the usage dispatcher.
func (p *CredentialLimitUsagePlugin) HandleUsage(_ context.Context, record usage.Record) {
	if p == nil || p.manager == nil || strings.TrimSpace(record.AuthID) == "" {
		return
	}
	p.manager.RecordCredentialTokens(record.AuthID, usageRecordTotalTokens(record))
}

func usageRecordTotalTokens(record usage.Record) int64 {
	if record.Detail.TokenBreakdown.Valid() && record.Detail.TokenBreakdown.TotalTokens > 0 {
		return record.Detail.TokenBreakdown.TotalTokens
	}
	if record.Detail.TotalTokens > 0 {
		return record.Detail.TotalTokens
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
