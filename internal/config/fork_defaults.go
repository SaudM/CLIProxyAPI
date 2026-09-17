package config

// Fork defaults: the tuning this fork ships with when config.yaml omits the keys.
// They mirror the reference deployment (see config.example.yaml), so a fresh server
// behaves sensibly without any of these being written down. Every value can still
// be overridden — including switched off — by writing the key explicitly: 0 means
// unlimited for a limit, [] disables a pool, false turns a toggle off.
//
// Server-specific material (proxy lines, credentials, keys, timezones) has no
// default on purpose.

const (
	// DefaultRequestRetry is the number of extra credential retry rounds.
	DefaultRequestRetry = 2
	// DefaultMaxRetryInterval caps, in seconds, how long a retry round waits for the
	// closest credential (per-minute window, short upstream cooldown) before 429.
	DefaultMaxRetryInterval = 30
	// DefaultSessionAffinityTTL keeps a conversation on the same credential this long
	// after its last request.
	DefaultSessionAffinityTTL = "4h"
)

// DefaultCredentialLimits is the per-credential shape of one heavy human user:
// bounded minute, bounded day, a few parallel sessions, slightly different caps per
// account. Sized from measured single-user traffic (~4 req/min sustained, 10/min
// peak, 3 in flight); these are ceilings, not targets.
func DefaultCredentialLimits() CredentialLimits {
	return CredentialLimits{
		RPM:                      30,
		TPM:                      2_000_000,
		MaxConcurrent:            4,
		RPD:                      3000,
		TPD:                      40_000_000,
		MaxSessions:              6,
		SessionWindowMinutes:     DefaultCredentialSessionWindowMinutes,
		ActiveHours:              "",
		ActiveHoursJitterMinutes: 45,
		LimitJitterPercent:       15,
	}
}

// DefaultClaudePlatformPool spreads Claude credentials over a realistic platform mix.
func DefaultClaudePlatformPool() []ClaudePlatformPoolEntry {
	return []ClaudePlatformPoolEntry{
		{OS: "MacOS", Arch: "arm64", Weight: 6},
		{OS: "Windows", Arch: "x64", Weight: 2},
		{OS: "Linux", Arch: "x64", Weight: 1},
		{OS: "MacOS", Arch: "x64", Weight: 1},
	}
}

// applyForkDefaults pre-populates cfg before the YAML is unmarshalled, so absent keys
// keep these values while explicit keys (even zero, false or []) win.
func applyForkDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.RequestRetry = DefaultRequestRetry
	cfg.MaxRetryInterval = DefaultMaxRetryInterval
	cfg.CommercialMode = true
	cfg.ForceModelPrefix = true
	cfg.Routing.SessionAffinity = true
	cfg.Routing.SessionAffinityTTL = DefaultSessionAffinityTTL
	cfg.CredentialLimits = DefaultCredentialLimits()
	stabilize := true
	cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile = &stabilize
	cfg.ClaudeHeaderDefaults.PlatformPool = DefaultClaudePlatformPool()
}

// newDefaultConfig returns the configuration a missing or empty config file yields.
func newDefaultConfig() *Config {
	cfg := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
	applyForkDefaults(cfg)
	return cfg
}
