package auth

import (
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

// fakeClock drives the limiter without sleeping.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
func newFakeClock() *fakeClock               { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }
func newTestLimiter(clock *fakeClock) *credentialLimiter {
	limiter := newCredentialLimiter()
	limiter.now = clock.Now
	return limiter
}

func TestLimitWindow_SumIgnoresStaleBuckets(t *testing.T) {
	var window limitWindow
	base := int64(1_000)
	window.add(base, 3)
	window.add(base+10, 2)
	if got := window.sum(base + 10); got != 5 {
		t.Fatalf("sum inside window = %d, want 5", got)
	}
	// 60 seconds after the first bucket it falls out; the second stays.
	if got := window.sum(base + 60); got != 2 {
		t.Fatalf("sum after first bucket expired = %d, want 2", got)
	}
	// A jump far beyond the window drops everything without any rotation call.
	if got := window.sum(base + 10_000); got != 0 {
		t.Fatalf("sum after long jump = %d, want 0", got)
	}
	// Writing into a slot whose second changed resets it instead of accumulating.
	window.add(base+60, 1)
	if got := window.sum(base + 60); got != 3 {
		t.Fatalf("sum after slot reuse = %d, want 3 (2 live + 1 new)", got)
	}
}

func TestCredentialLimiter_RPMRefusesAtLimitAndRecoversAtOldestBucket(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock)
	limits := credentialLimits{RPM: 2}

	first, _, ok := limiter.tryAcquire("a", "", limits)
	if !ok || first == nil {
		t.Fatalf("first acquire refused")
	}
	first.Release()
	clock.Advance(10 * time.Second)
	second, _, ok := limiter.tryAcquire("a", "", limits)
	if !ok {
		t.Fatalf("second acquire refused")
	}
	second.Release()

	_, blockedUntil, ok := limiter.tryAcquire("a", "", limits)
	if ok {
		t.Fatalf("third acquire admitted over rpm limit")
	}
	wantRecover := time.Unix(clock.Now().Add(-10*time.Second).Unix()+60, 0)
	if !blockedUntil.Equal(wantRecover) {
		t.Fatalf("blockedUntil = %v, want %v (oldest bucket + 60s)", blockedUntil, wantRecover)
	}
	if wait := limiter.nextAvailable("a", "", limits); wait != wantRecover.Sub(clock.Now()) {
		t.Fatalf("nextAvailable = %v, want %v", wait, wantRecover.Sub(clock.Now()))
	}
	// Refusal must not have consumed budget.
	if snap := limiter.snapshot("a", limits); snap.RPMUsed != 2 || snap.InFlight != 0 {
		t.Fatalf("snapshot after refusal = %+v, want RPMUsed=2 InFlight=0", snap)
	}

	clock.now = wantRecover
	if _, _, ok = limiter.tryAcquire("a", "", limits); !ok {
		t.Fatalf("acquire at recovery instant refused")
	}
}

func TestCredentialLimiter_TPMUsesRecordedTokens(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock)
	limits := credentialLimits{TPM: 1000}

	if _, _, ok := limiter.tryAcquire("a", "", limits); !ok {
		t.Fatalf("acquire with empty window refused")
	}
	limiter.recordTokens("a", 999)
	if _, _, ok := limiter.tryAcquire("a", "", limits); !ok {
		t.Fatalf("acquire under tpm limit refused")
	}
	limiter.recordTokens("a", 1)
	_, blockedUntil, ok := limiter.tryAcquire("a", "", limits)
	if ok {
		t.Fatalf("acquire at tpm limit admitted")
	}
	if want := time.Unix(clock.Now().Unix()+60, 0); !blockedUntil.Equal(want) {
		t.Fatalf("blockedUntil = %v, want %v", blockedUntil, want)
	}
	if wait := limiter.nextAvailable("a", "", limits); wait != 60*time.Second {
		t.Fatalf("nextAvailable = %v while tpm exhausted, want 60s", wait)
	}
	clock.Advance(61 * time.Second)
	if _, _, ok = limiter.tryAcquire("a", "", limits); !ok {
		t.Fatalf("acquire after window rolled refused")
	}
}

func TestCredentialLimiter_ConcurrencyLeaseReleaseIsExactlyOnce(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock)
	limits := credentialLimits{MaxConcurrent: 1}

	lease, _, ok := limiter.tryAcquire("a", "", limits)
	if !ok {
		t.Fatalf("first acquire refused")
	}
	_, blockedUntil, ok := limiter.tryAcquire("a", "", limits)
	if ok {
		t.Fatalf("second acquire admitted over concurrency limit")
	}
	if want := clock.Now().Add(credentialLimitConcurrencyRetry); !blockedUntil.Equal(want) {
		t.Fatalf("blockedUntil = %v, want now+%v", blockedUntil, credentialLimitConcurrencyRetry)
	}
	lease.Release()
	lease.Release() // second release must be a no-op
	if snap := limiter.snapshot("a", limits); snap.InFlight != 0 {
		t.Fatalf("inFlight after double release = %d, want 0", snap.InFlight)
	}
	if _, _, ok = limiter.tryAcquire("a", "", limits); !ok {
		t.Fatalf("acquire after release refused")
	}
	var nilLease *credentialLease
	nilLease.Release() // nil-safe
}

func TestCredentialLimiter_ReleaseAfterRemoveIsNoop(t *testing.T) {
	limiter := newTestLimiter(newFakeClock())
	limits := credentialLimits{MaxConcurrent: 1}
	lease, _, ok := limiter.tryAcquire("a", "", limits)
	if !ok {
		t.Fatalf("acquire refused")
	}
	limiter.remove("a")
	lease.Release()
	limiter.mu.Lock()
	_, resurrected := limiter.entries["a"]
	limiter.mu.Unlock()
	if resurrected {
		t.Fatalf("release resurrected a removed entry")
	}
}

func TestCredentialLimiter_DisabledLimitsAreFastPath(t *testing.T) {
	limiter := newTestLimiter(newFakeClock())
	lease, blockedUntil, ok := limiter.tryAcquire("a", "", credentialLimits{})
	if !ok || lease != nil || !blockedUntil.IsZero() {
		t.Fatalf("disabled limits = (%v, %v, %t), want (nil, zero, true)", lease, blockedUntil, ok)
	}
	limiter.mu.Lock()
	entries := len(limiter.entries)
	limiter.mu.Unlock()
	if entries != 0 {
		t.Fatalf("fast path created %d entries, want 0", entries)
	}
	if wait := limiter.nextAvailable("a", "", credentialLimits{}); wait != 0 {
		t.Fatalf("nextAvailable for disabled limits = %v, want 0", wait)
	}
}

func TestManager_EffectiveCredentialLimitsPrecedence(t *testing.T) {
	m := NewManager(nil, nil, nil)
	global := internalconfig.CredentialLimits{
		RPM: 10, TPM: 1000, MaxConcurrent: 3,
		Providers: map[string]internalconfig.CredentialLimitValues{
			"Claude": {RPM: intPtr(20)},
		},
	}
	m.SetCredentialLimits(global, "")

	codex := &Auth{ID: "codex", Provider: "codex"}
	if got := coreCredentialLimits(m.effectiveCredentialLimits(codex)); got != (credentialLimits{RPM: 10, TPM: 1000, MaxConcurrent: 3}) {
		t.Fatalf("codex limits = %+v, want globals", got)
	}
	claude := &Auth{ID: "claude", Provider: "claude"}
	if got := coreCredentialLimits(m.effectiveCredentialLimits(claude)); got != (credentialLimits{RPM: 20, TPM: 1000, MaxConcurrent: 3}) {
		t.Fatalf("claude limits = %+v, want provider rpm override", got)
	}
	overridden := &Auth{ID: "claude-2", Provider: "claude", Metadata: map[string]any{"rpm": 0, "tpm": "500", "max_concurrent": float64(1)}}
	if got := coreCredentialLimits(m.effectiveCredentialLimits(overridden)); got != (credentialLimits{RPM: 0, TPM: 500, MaxConcurrent: 1}) {
		t.Fatalf("overridden limits = %+v, want per-auth values (explicit 0 = unlimited)", got)
	}
	negative := &Auth{ID: "claude-3", Provider: "claude", Metadata: map[string]any{"rpm": -5}}
	if got := m.effectiveCredentialLimits(negative); got.RPM != 20 {
		t.Fatalf("negative override rpm = %d, want inherited 20", got.RPM)
	}
}

func TestCredentialLimitUsagePlugin_FeedsTPM(t *testing.T) {
	m := NewManager(nil, nil, nil)
	clock := newFakeClock()
	m.limiter.now = clock.Now
	plugin := NewCredentialLimitUsagePlugin(m)

	breakdown := usage.Detail{InputTokens: 100, OutputTokens: 50, TotalTokens: 150}
	plugin.HandleUsage(nil, usage.Record{AuthID: "a", Detail: breakdown})
	plugin.HandleUsage(nil, usage.Record{AuthID: "", Detail: breakdown}) // ignored
	plugin.HandleUsage(nil, usage.Record{AuthID: "b", Detail: usage.Detail{InputTokens: 7, OutputTokens: 3}})

	if snap := m.limiter.snapshot("a", credentialLimits{TPM: 1}); snap.TPMUsed != 150 {
		t.Fatalf("a TPMUsed = %d, want 150", snap.TPMUsed)
	}
	if snap := m.limiter.snapshot("b", credentialLimits{TPM: 1}); snap.TPMUsed != 10 {
		t.Fatalf("b TPMUsed = %d, want 10 (input+output fallback)", snap.TPMUsed)
	}
}

func TestCredentialLimitError_StatusAndRetryAfter(t *testing.T) {
	err := newCredentialLimitError("", 1500*time.Millisecond)
	if err.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", err.StatusCode())
	}
	if !isAuthUnavailablePickError(&Error{Code: "auth_unavailable"}) || isAuthUnavailablePickError(&Error{Code: "executor_not_found"}) {
		t.Fatalf("isAuthUnavailablePickError classification wrong")
	}
	headers := SafeResponseHeaders(err)
	if got := headers.Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2 (ceil of 1.5s)", got)
	}
	// Sub-second waits are clamped so the header is still emitted.
	if got := SafeResponseHeaders(newCredentialLimitError("x", 10*time.Millisecond)).Get("Retry-After"); got != "1" {
		t.Fatalf("clamped Retry-After = %q, want 1", got)
	}
	if err.Error() != "credential_limit_exceeded: credential limits exceeded" {
		t.Fatalf("default message = %q", err.Error())
	}
}

func intPtr(v int) *int { return &v }

// coreCredentialLimits keeps only the per-minute/concurrency fields for equality checks.
func coreCredentialLimits(l credentialLimits) credentialLimits {
	return credentialLimits{RPM: l.RPM, TPM: l.TPM, MaxConcurrent: l.MaxConcurrent}
}
