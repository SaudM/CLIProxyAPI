package config

import (
	"fmt"
	"strings"
	"time"
)

// DefaultCredentialSessionWindowMinutes is how long a downstream session counts as
// active on a credential after its last request when session-window-minutes is unset.
const DefaultCredentialSessionWindowMinutes = 15

// MaxCredentialLimitJitterPercent bounds limit-jitter-percent.
const MaxCredentialLimitJitterPercent = 50

// CredentialLimitValues holds optional per-scope credential limit overrides.
// A nil field inherits the next level up; 0 (or "" for active-hours) means explicitly unlimited.
type CredentialLimitValues struct {
	// RPM caps requests per credential in a rolling 60 second window.
	RPM *int `yaml:"rpm,omitempty" json:"rpm,omitempty"`
	// TPM caps counted tokens (uncached input + cache writes + output; cache reads are
	// excluded) per credential in a rolling 60 second window.
	TPM *int `yaml:"tpm,omitempty" json:"tpm,omitempty"`
	// MaxConcurrent caps in-flight requests per credential.
	MaxConcurrent *int `yaml:"max-concurrent,omitempty" json:"max-concurrent,omitempty"`
	// RPD caps requests per credential per calendar day in the credential's timezone.
	RPD *int `yaml:"rpd,omitempty" json:"rpd,omitempty"`
	// TPD caps counted tokens (same basis as TPM) per credential per calendar day in the credential's timezone.
	TPD *int `yaml:"tpd,omitempty" json:"tpd,omitempty"`
	// MaxSessions caps distinct downstream sessions active on a credential within the session window.
	MaxSessions *int `yaml:"max-sessions,omitempty" json:"max-sessions,omitempty"`
	// ActiveHours restricts the credential to a daily local-time window ("HH:MM-HH:MM"); "" means always.
	ActiveHours *string `yaml:"active-hours,omitempty" json:"active-hours,omitempty"`
}

// CredentialLimits configures the global defaults for per-credential limits.
// Zero values mean unlimited, so an absent block disables every limit.
type CredentialLimits struct {
	RPM           int `yaml:"rpm" json:"rpm"`
	TPM           int `yaml:"tpm" json:"tpm"`
	MaxConcurrent int `yaml:"max-concurrent" json:"max-concurrent"`
	// RPD / TPD cap requests and tokens per calendar day, counted in each credential's own timezone.
	RPD int `yaml:"rpd" json:"rpd"`
	TPD int `yaml:"tpd" json:"tpd"`
	// MaxSessions caps how many distinct downstream sessions one credential serves at the same time;
	// a session stays active for SessionWindowMinutes after its last request.
	MaxSessions          int `yaml:"max-sessions" json:"max-sessions"`
	SessionWindowMinutes int `yaml:"session-window-minutes" json:"session-window-minutes"`
	// ActiveHours is a daily local-time window ("HH:MM-HH:MM", may wrap midnight) outside of which a
	// credential is skipped. ActiveHoursJitterMinutes shifts both edges by a stable per-credential,
	// per-day offset within ±N minutes so accounts do not switch on and off at the same instant.
	ActiveHours              string `yaml:"active-hours" json:"active-hours"`
	ActiveHoursJitterMinutes int    `yaml:"active-hours-jitter-minutes" json:"active-hours-jitter-minutes"`
	// LimitJitterPercent scales rpm/tpm/rpd/tpd per credential by a stable offset within ±N percent so
	// accounts do not share identical caps. Max 50.
	LimitJitterPercent int `yaml:"limit-jitter-percent" json:"limit-jitter-percent"`
	// Providers optionally overrides the top-level values for a provider key
	// (e.g. "claude", "codex", "openai-compatibility-name").
	Providers map[string]CredentialLimitValues `yaml:"providers,omitempty" json:"providers,omitempty"`
}

// ResolvedCredentialLimits are the limits that apply to one provider scope after
// provider overrides are folded into the globals.
type ResolvedCredentialLimits struct {
	RPM           int
	TPM           int
	MaxConcurrent int
	RPD           int
	TPD           int
	MaxSessions   int
	ActiveHours   string
}

// Normalize lowercases and trims provider keys so lookups are case-insensitive.
func (c *CredentialLimits) Normalize() {
	if c == nil {
		return
	}
	c.ActiveHours = strings.TrimSpace(c.ActiveHours)
	if len(c.Providers) == 0 {
		return
	}
	normalized := make(map[string]CredentialLimitValues, len(c.Providers))
	for key, values := range c.Providers {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}
		if values.ActiveHours != nil {
			trimmed := strings.TrimSpace(*values.ActiveHours)
			values.ActiveHours = &trimmed
		}
		normalized[normalizedKey] = values
	}
	c.Providers = normalized
}

// Validate rejects negative limits and malformed windows at every level.
func (c CredentialLimits) Validate() error {
	for name, value := range map[string]int{
		"rpm": c.RPM, "tpm": c.TPM, "max-concurrent": c.MaxConcurrent,
		"rpd": c.RPD, "tpd": c.TPD, "max-sessions": c.MaxSessions,
		"session-window-minutes": c.SessionWindowMinutes, "active-hours-jitter-minutes": c.ActiveHoursJitterMinutes,
		"limit-jitter-percent": c.LimitJitterPercent,
	} {
		if value < 0 {
			return fmt.Errorf("credential-limits.%s: must not be negative", name)
		}
	}
	if c.LimitJitterPercent > MaxCredentialLimitJitterPercent {
		return fmt.Errorf("credential-limits.limit-jitter-percent: must be at most %d", MaxCredentialLimitJitterPercent)
	}
	if _, errHours := ParseActiveHours(c.ActiveHours); errHours != nil {
		return fmt.Errorf("credential-limits.%w", errHours)
	}
	for key, values := range c.Providers {
		if errValidate := values.Validate(fmt.Sprintf("credential-limits.providers.%s", key)); errValidate != nil {
			return errValidate
		}
	}
	return nil
}

// Validate rejects negative override values and malformed windows; prefix names the config location.
func (v CredentialLimitValues) Validate(prefix string) error {
	for name, value := range map[string]*int{
		"rpm": v.RPM, "tpm": v.TPM, "max-concurrent": v.MaxConcurrent,
		"rpd": v.RPD, "tpd": v.TPD, "max-sessions": v.MaxSessions,
	} {
		if errValidate := validateOptionalLimit(prefix+"."+name, value); errValidate != nil {
			return errValidate
		}
	}
	if v.ActiveHours != nil {
		if _, errHours := ParseActiveHours(*v.ActiveHours); errHours != nil {
			return fmt.Errorf("%s.%w", prefix, errHours)
		}
	}
	return nil
}

func validateOptionalLimit(name string, value *int) error {
	if value != nil && *value < 0 {
		return fmt.Errorf("%s: must not be negative", name)
	}
	return nil
}

// SessionWindow returns the configured session window, defaulting when unset.
func (c CredentialLimits) SessionWindow() time.Duration {
	if c.SessionWindowMinutes <= 0 {
		return DefaultCredentialSessionWindowMinutes * time.Minute
	}
	return time.Duration(c.SessionWindowMinutes) * time.Minute
}

// Resolve returns the effective limits for the first provider key that has an
// entry in Providers, falling back to the top-level values for unset fields.
func (c CredentialLimits) Resolve(providerKeys ...string) ResolvedCredentialLimits {
	resolved := ResolvedCredentialLimits{
		RPM: c.RPM, TPM: c.TPM, MaxConcurrent: c.MaxConcurrent,
		RPD: c.RPD, TPD: c.TPD, MaxSessions: c.MaxSessions, ActiveHours: c.ActiveHours,
	}
	if len(c.Providers) == 0 {
		return resolved
	}
	for _, key := range providerKeys {
		values, ok := c.Providers[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		if values.RPM != nil {
			resolved.RPM = *values.RPM
		}
		if values.TPM != nil {
			resolved.TPM = *values.TPM
		}
		if values.MaxConcurrent != nil {
			resolved.MaxConcurrent = *values.MaxConcurrent
		}
		if values.RPD != nil {
			resolved.RPD = *values.RPD
		}
		if values.TPD != nil {
			resolved.TPD = *values.TPD
		}
		if values.MaxSessions != nil {
			resolved.MaxSessions = *values.MaxSessions
		}
		if values.ActiveHours != nil {
			resolved.ActiveHours = *values.ActiveHours
		}
		break
	}
	return resolved
}

// ValidateCredentialLimitOverrides validates per-credential limit overrides for every API-key family.
func (cfg *Config) ValidateCredentialLimitOverrides() error {
	if cfg == nil {
		return nil
	}
	for index := range cfg.GeminiKey {
		if errValidate := cfg.GeminiKey[index].CredentialLimitValues.Validate(fmt.Sprintf("gemini-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.InteractionsKey {
		if errValidate := cfg.InteractionsKey[index].CredentialLimitValues.Validate(fmt.Sprintf("interactions-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.ClaudeKey {
		if errValidate := cfg.ClaudeKey[index].CredentialLimitValues.Validate(fmt.Sprintf("claude-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.VertexCompatAPIKey {
		if errValidate := cfg.VertexCompatAPIKey[index].CredentialLimitValues.Validate(fmt.Sprintf("vertex-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.CodexKey {
		if errValidate := cfg.CodexKey[index].CredentialLimitValues.Validate(fmt.Sprintf("codex-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.XAIKey {
		if errValidate := cfg.XAIKey[index].CredentialLimitValues.Validate(fmt.Sprintf("xai-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.MetaKey {
		if errValidate := cfg.MetaKey[index].CredentialLimitValues.Validate(fmt.Sprintf("meta-api-key[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	for index := range cfg.OpenAICompatibility {
		if errValidate := cfg.OpenAICompatibility[index].CredentialLimitValues.Validate(fmt.Sprintf("openai-compatibility[%d]", index)); errValidate != nil {
			return errValidate
		}
	}
	return nil
}
