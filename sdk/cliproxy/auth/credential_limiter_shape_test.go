package auth

import (
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func tokyo(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	return loc
}

func mustActiveHours(t *testing.T, raw string) internalconfig.ActiveHours {
	t.Helper()
	hours, err := internalconfig.ParseActiveHours(raw)
	if err != nil {
		t.Fatalf("ParseActiveHours(%q): %v", raw, err)
	}
	return hours
}

func TestCredentialLimiter_DailyBudgetResetsAtLocalMidnight(t *testing.T) {
	loc := tokyo(t)
	clock := &fakeClock{now: time.Date(2026, 9, 18, 23, 59, 30, 0, loc)}
	limiter := newTestLimiter(clock)
	limits := credentialLimits{RPD: 2, Location: loc}

	for i := 0; i < 2; i++ {
		lease, _, ok := limiter.tryAcquire("a", "", limits)
		if !ok {
			t.Fatalf("request %d refused under rpd 2", i+1)
		}
		lease.Release()
	}
	_, blocked, ok := limiter.tryAcquire("a", "", limits)
	wantMidnight := time.Date(2026, 9, 19, 0, 0, 0, 0, loc)
	if ok || !blocked.Equal(wantMidnight) {
		t.Fatalf("third request: ok=%t blocked=%v, want refused until %v", ok, blocked, wantMidnight)
	}
	if status := limiter.snapshot("a", limits); status.RPDUsed != 2 || status.DayResetsIn != 30*time.Second {
		t.Fatalf("snapshot = %+v", status)
	}
	clock.Advance(31 * time.Second)
	if _, _, ok := limiter.tryAcquire("a", "", limits); !ok {
		t.Fatal("daily budget did not reset after local midnight")
	}
	if status := limiter.snapshot("a", limits); status.RPDUsed != 1 {
		t.Fatalf("day counter after rollover = %d, want 1", status.RPDUsed)
	}
}

func TestCredentialLimiter_TPDCountsRecordedTokens(t *testing.T) {
	loc := tokyo(t)
	clock := &fakeClock{now: time.Date(2026, 9, 18, 12, 0, 0, 0, loc)}
	limiter := newTestLimiter(clock)
	limits := credentialLimits{TPD: 100, Location: loc}
	if lease, _, ok := limiter.tryAcquire("a", "", limits); !ok {
		t.Fatal("first request refused")
	} else {
		lease.Release()
	}
	limiter.recordTokens("a", 100)
	if _, blocked, ok := limiter.tryAcquire("a", "", limits); ok || !blocked.Equal(time.Date(2026, 9, 19, 0, 0, 0, 0, loc)) {
		t.Fatalf("over tpd: ok=%t blocked=%v", ok, blocked)
	}
	if wait := limiter.nextAvailable("a", "", limits); wait != 12*time.Hour {
		t.Fatalf("nextAvailable = %v, want 12h until local midnight", wait)
	}
}

func TestCredentialLimiter_SessionCapKeepsKnownSessions(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock)
	limits := credentialLimits{MaxSessions: 2, SessionWindow: 15 * time.Minute}
	admit := func(session string) (time.Time, bool) {
		lease, blocked, ok := limiter.tryAcquire("a", session, limits)
		lease.Release()
		return blocked, ok
	}
	if _, ok := admit("s1"); !ok {
		t.Fatal("s1 refused")
	}
	clock.Advance(time.Minute)
	if _, ok := admit("s2"); !ok {
		t.Fatal("s2 refused")
	}
	blocked, ok := admit("s3")
	if ok || !blocked.Equal(clock.Now().Add(14*time.Minute)) {
		t.Fatalf("s3: ok=%t blocked=%v, want refused until the oldest session expires", ok, blocked)
	}
	if _, ok := admit("s1"); !ok {
		t.Fatal("known session s1 refused by the cap")
	}
	if _, ok := admit(""); !ok {
		t.Fatal("request without a session id refused by the cap")
	}
	if status := limiter.snapshot("a", limits); status.ActiveSessions != 2 || status.MaxSessions != 2 {
		t.Fatalf("snapshot sessions = %+v", status)
	}
	clock.Advance(15 * time.Minute)
	if _, ok := admit("s3"); !ok {
		t.Fatal("s3 still refused after every earlier session went idle")
	}
}

func TestActiveHoursState_WrapsMidnightWithStableJitter(t *testing.T) {
	loc := tokyo(t)
	hours := mustActiveHours(t, "08:30-01:00")
	const jitter = 45 * time.Minute

	night := time.Date(2026, 9, 18, 3, 0, 0, 0, loc)
	awake, next := activeHoursState("acct", hours, loc, jitter, night)
	open := time.Date(2026, 9, 18, 8, 30, 0, 0, loc)
	if awake || next.Before(open.Add(-jitter)) || !next.Before(open.Add(jitter)) {
		t.Fatalf("03:00: awake=%t next=%v, want closed until ~08:30±45m", awake, next)
	}
	if _, again := activeHoursState("acct", hours, loc, jitter, night); !again.Equal(next) {
		t.Fatalf("jitter not stable: %v vs %v", again, next)
	}
	if _, exact := activeHoursState("acct", hours, loc, 0, night); !exact.Equal(open) {
		t.Fatalf("zero jitter next open = %v, want %v", exact, open)
	}

	evening := time.Date(2026, 9, 18, 23, 0, 0, 0, loc)
	closeAt := time.Date(2026, 9, 19, 1, 0, 0, 0, loc)
	awake, next = activeHoursState("acct", hours, loc, jitter, evening)
	if !awake || next.Before(closeAt.Add(-jitter)) || !next.Before(closeAt.Add(jitter)) {
		t.Fatalf("23:00: awake=%t next=%v, want open until ~01:00±45m", awake, next)
	}
	// Just after midnight the window that opened yesterday is still the active one.
	if awake, _ = activeHoursState("acct", hours, loc, 0, time.Date(2026, 9, 19, 0, 30, 0, 0, loc)); !awake {
		t.Fatal("00:30 should still be inside yesterday's window")
	}
	if awake, _ = activeHoursState("acct", internalconfig.ActiveHours{}, loc, jitter, night); !awake {
		t.Fatal("zero window must be always on")
	}
}

func TestCredentialLimiter_ActiveHoursRefuseWithoutState(t *testing.T) {
	loc := tokyo(t)
	clock := &fakeClock{now: time.Date(2026, 9, 18, 3, 0, 0, 0, loc)}
	limiter := newTestLimiter(clock)
	limits := credentialLimits{ActiveHours: mustActiveHours(t, "08:30-01:00"), Location: loc}
	if wait := limiter.nextAvailable("fresh", "", limits); wait != 5*time.Hour+30*time.Minute {
		t.Fatalf("nextAvailable while asleep = %v, want 5h30m", wait)
	}
	if _, _, ok := limiter.tryAcquire("fresh", "", limits); ok {
		t.Fatal("admitted outside active hours")
	}
	clock.Advance(6 * time.Hour)
	if _, _, ok := limiter.tryAcquire("fresh", "", limits); !ok {
		t.Fatal("refused inside active hours")
	}
	status := limiter.snapshot("fresh", limits)
	if !status.Awake || status.ActiveHours != "08:30-01:00" || status.Timezone != "Asia/Tokyo" || status.AwakeChangesAt.IsZero() {
		t.Fatalf("snapshot = %+v", status)
	}
}

func TestJitteredLimit_StableAndBounded(t *testing.T) {
	first := jitteredLimit("acct", "rpm", 1000, 15)
	if first < 850 || first > 1150 || first != jitteredLimit("acct", "rpm", 1000, 15) {
		t.Fatalf("jittered limit = %d, want stable within ±15%%", first)
	}
	if jitteredLimit("acct", "rpm", 0, 15) != 0 || jitteredLimit("acct", "rpm", 1000, 0) != 1000 {
		t.Fatal("zero base or zero percent must pass through")
	}
	if jitteredLimit("acct", "rpm", 1, 50) < 1 {
		t.Fatal("jittered limit dropped below 1")
	}
	differs := false
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		if jitteredLimit(id, "rpm", 1000, 15) != first {
			differs = true
		}
	}
	if !differs {
		t.Fatal("every credential got the same jittered limit")
	}
}

func TestManager_EffectiveCredentialLimitsShape(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetCredentialLimits(internalconfig.CredentialLimits{
		RPD: 600, TPD: 15_000_000, MaxSessions: 4, SessionWindowMinutes: 20,
		ActiveHours: "08:30-01:00", ActiveHoursJitterMinutes: 45, LimitJitterPercent: 15,
	}, "Asia/Tokyo")

	plain := m.effectiveCredentialLimits(&Auth{ID: "plain", Provider: "claude"})
	if plain.baseRPD != 600 || plain.RPD < 510 || plain.RPD > 690 || plain.baseTPD != 15_000_000 {
		t.Fatalf("jittered day budget = %+v", plain)
	}
	if plain.MaxSessions != 4 || plain.SessionWindow != 20*time.Minute || plain.ActiveHours.String() != "08:30-01:00" || plain.ActiveHoursJitter != 45*time.Minute {
		t.Fatalf("shape limits = %+v", plain)
	}
	if plain.location().String() != "Asia/Tokyo" {
		t.Fatalf("fallback location = %s, want Asia/Tokyo", plain.location())
	}

	pinned := m.effectiveCredentialLimits(&Auth{ID: "pinned", Provider: "claude", Attributes: map[string]string{AttributeTimezone: "Europe/Berlin"}})
	if pinned.location().String() != "Europe/Berlin" {
		t.Fatalf("credential timezone ignored: %s", pinned.location())
	}
	alwaysOn := m.effectiveCredentialLimits(&Auth{ID: "always", Provider: "claude", Metadata: map[string]any{"active_hours": "", "max_sessions": 0}})
	if !alwaysOn.ActiveHours.IsZero() || alwaysOn.ActiveHoursJitter != 0 || alwaysOn.MaxSessions != 0 {
		t.Fatalf("explicit empty overrides not honoured: %+v", alwaysOn)
	}
	if !alwaysOn.enabled() {
		t.Fatal("daily budgets alone should keep the limiter enabled")
	}
}

func TestCredentialSessionKey_CollapsesSubagentsOntoRootSession(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "11111111-2222-3333-4444-555555555555")
	root := credentialSessionKey(cliproxyexecutor.Options{Headers: headers}, cliproxyexecutor.Request{})
	if root == "" {
		t.Fatal("no session key from the Claude Code session header")
	}
	headers.Set("X-Claude-Code-Agent-Id", "agent-7")
	if sub := credentialSessionKey(cliproxyexecutor.Options{Headers: headers}, cliproxyexecutor.Request{}); sub != root {
		t.Fatalf("subagent key = %q, want root %q", sub, root)
	}
	if key := credentialSessionKey(cliproxyexecutor.Options{}, cliproxyexecutor.Request{Payload: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)}); key != "" {
		t.Fatalf("hash-derived id counted as a session: %q", key)
	}
}

func TestUsageRecordCountedTokensExcludesCacheReads(t *testing.T) {
	// A Claude Code turn: 2k fresh input, 150k cached context re-read, 3k cache write, 1k output.
	breakdown := usage.NewSubsetTokenBreakdown(155_000, 150_000, 3_000, 1_000, 0, 156_000)
	record := usage.Record{Detail: usage.Detail{InputTokens: 2_000, OutputTokens: 1_000, CacheReadTokens: 150_000, CacheCreationTokens: 3_000, TotalTokens: 156_000, TokenBreakdown: breakdown}}
	if got := usageRecordCountedTokens(record); got != 6_000 {
		t.Fatalf("counted tokens with breakdown = %d, want 6000 (cache reads excluded)", got)
	}
	// Without a valid breakdown the flat detail is used, still net of cache reads.
	flat := usage.Record{Detail: usage.Detail{InputTokens: 2_000, OutputTokens: 1_000, CacheReadTokens: 150_000, TotalTokens: 153_000}}
	if got := usageRecordCountedTokens(flat); got != 3_000 {
		t.Fatalf("counted tokens without breakdown = %d, want 3000", got)
	}
	// Bare input/output when nothing else is reported.
	if got := usageRecordCountedTokens(usage.Record{Detail: usage.Detail{InputTokens: 10, OutputTokens: 5}}); got != 15 {
		t.Fatalf("bare counted tokens = %d, want 15", got)
	}
}
