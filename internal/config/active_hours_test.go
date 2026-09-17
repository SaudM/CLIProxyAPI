package config

import (
	"strings"
	"testing"
)

func TestParseActiveHours(t *testing.T) {
	wrap, errWrap := ParseActiveHours("08:30-01:00")
	if errWrap != nil || wrap.IsZero() || wrap.Start != 510 || wrap.End != 60 || !wrap.Wraps() || wrap.Minutes() != 990 {
		t.Fatalf("wrap window = %+v (err %v)", wrap, errWrap)
	}
	if wrap.String() != "08:30-01:00" {
		t.Fatalf("String() = %q", wrap.String())
	}
	day, errDay := ParseActiveHours(" 09:00-18:00 ")
	if errDay != nil || day.Wraps() || day.Minutes() != 540 {
		t.Fatalf("day window = %+v (err %v)", day, errDay)
	}
	for _, always := range []string{"", "always", "ALWAYS"} {
		if hours, err := ParseActiveHours(always); err != nil || !hours.IsZero() || hours.Minutes() != minutesPerDay {
			t.Fatalf("ParseActiveHours(%q) = %+v, %v; want always-on", always, hours, err)
		}
	}
	for _, bad := range []string{"8-9", "24:00-01:00", "09:00-09:00", "09:00", "09:60-10:00", "a:b-c:d"} {
		if _, err := ParseActiveHours(bad); err == nil {
			t.Fatalf("ParseActiveHours(%q) accepted", bad)
		}
	}
}

func TestCredentialLimitsValidateShapeFields(t *testing.T) {
	if err := (CredentialLimits{LimitJitterPercent: 60}).Validate(); err == nil || !strings.Contains(err.Error(), "limit-jitter-percent") {
		t.Fatalf("jitter > 50 accepted: %v", err)
	}
	if err := (CredentialLimits{ActiveHours: "bad"}).Validate(); err == nil || !strings.Contains(err.Error(), "active-hours") {
		t.Fatalf("bad window accepted: %v", err)
	}
	if err := (CredentialLimits{RPD: -1}).Validate(); err == nil {
		t.Fatal("negative rpd accepted")
	}
	bad := "1-2"
	if err := (CredentialLimits{Providers: map[string]CredentialLimitValues{"claude": {ActiveHours: &bad}}}).Validate(); err == nil {
		t.Fatal("bad provider window accepted")
	}
	ok := CredentialLimits{RPD: 600, TPD: 15_000_000, MaxSessions: 4, SessionWindowMinutes: 15, ActiveHours: "08:30-01:00", ActiveHoursJitterMinutes: 45, LimitJitterPercent: 15}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}
	if ok.SessionWindow().Minutes() != 15 || (CredentialLimits{}).SessionWindow().Minutes() != DefaultCredentialSessionWindowMinutes {
		t.Fatalf("session window = %v / %v", ok.SessionWindow(), (CredentialLimits{}).SessionWindow())
	}
}

func TestCredentialLimitsShapeFieldsParseAndResolve(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
credential-limits:
  rpd: 600
  tpd: 15000000
  max-sessions: 4
  active-hours: "08:30-01:00"
  active-hours-jitter-minutes: 45
  limit-jitter-percent: 15
  providers:
    codex:
      rpd: 100
      active-hours: ""
claude-api-key:
  - api-key: "claude-one"
    rpd: 5
    active-hours: "09:00-18:00"
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	claude := cfg.CredentialLimits.Resolve("claude")
	if claude.RPD != 600 || claude.TPD != 15_000_000 || claude.MaxSessions != 4 || claude.ActiveHours != "08:30-01:00" {
		t.Fatalf("Resolve(claude) = %+v", claude)
	}
	codex := cfg.CredentialLimits.Resolve("codex")
	if codex.RPD != 100 || codex.ActiveHours != "" || codex.TPD != 15_000_000 {
		t.Fatalf("Resolve(codex) = %+v, want provider rpd/active-hours override", codex)
	}
	key := cfg.ClaudeKey[0]
	if key.RPD == nil || *key.RPD != 5 || key.ActiveHours == nil || *key.ActiveHours != "09:00-18:00" {
		t.Fatalf("claude key overrides = %+v", key.CredentialLimitValues)
	}
	if _, errBad := ParseConfigBytes([]byte("credential-limits:\n  active-hours: \"9-5\"\n")); errBad == nil {
		t.Fatal("malformed global active-hours accepted")
	}
	if _, errBad := ParseConfigBytes([]byte("claude-api-key:\n  - api-key: k\n    active-hours: \"9-5\"\n")); errBad == nil {
		t.Fatal("malformed per-key active-hours accepted")
	}
}
