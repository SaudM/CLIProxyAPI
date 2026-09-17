package config

import (
	"fmt"
	"strings"
)

// CredentialLimitValues holds optional per-scope credential limit overrides.
// A nil field inherits the next level up; 0 means explicitly unlimited.
type CredentialLimitValues struct {
	// RPM caps requests per credential in a rolling 60 second window.
	RPM *int `yaml:"rpm,omitempty" json:"rpm,omitempty"`
	// TPM caps total tokens (input + output) per credential in a rolling 60 second window.
	TPM *int `yaml:"tpm,omitempty" json:"tpm,omitempty"`
	// MaxConcurrent caps in-flight requests per credential.
	MaxConcurrent *int `yaml:"max-concurrent,omitempty" json:"max-concurrent,omitempty"`
}

// CredentialLimits configures the global defaults for per-credential limits.
// Zero values mean unlimited, so an absent block disables every limit.
type CredentialLimits struct {
	RPM           int `yaml:"rpm" json:"rpm"`
	TPM           int `yaml:"tpm" json:"tpm"`
	MaxConcurrent int `yaml:"max-concurrent" json:"max-concurrent"`
	// Providers optionally overrides the top-level values for a provider key
	// (e.g. "claude", "codex", "openai-compatibility-name").
	Providers map[string]CredentialLimitValues `yaml:"providers,omitempty" json:"providers,omitempty"`
}

// Normalize lowercases and trims provider keys so lookups are case-insensitive.
func (c *CredentialLimits) Normalize() {
	if c == nil || len(c.Providers) == 0 {
		return
	}
	normalized := make(map[string]CredentialLimitValues, len(c.Providers))
	for key, values := range c.Providers {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}
		normalized[normalizedKey] = values
	}
	c.Providers = normalized
}

// Validate rejects negative limits at every level.
func (c CredentialLimits) Validate() error {
	if c.RPM < 0 {
		return fmt.Errorf("credential-limits.rpm: must not be negative")
	}
	if c.TPM < 0 {
		return fmt.Errorf("credential-limits.tpm: must not be negative")
	}
	if c.MaxConcurrent < 0 {
		return fmt.Errorf("credential-limits.max-concurrent: must not be negative")
	}
	for key, values := range c.Providers {
		if errValidate := values.Validate(fmt.Sprintf("credential-limits.providers.%s", key)); errValidate != nil {
			return errValidate
		}
	}
	return nil
}

// Validate rejects negative override values; prefix names the config location.
func (v CredentialLimitValues) Validate(prefix string) error {
	if errValidate := validateOptionalLimit(prefix+".rpm", v.RPM); errValidate != nil {
		return errValidate
	}
	if errValidate := validateOptionalLimit(prefix+".tpm", v.TPM); errValidate != nil {
		return errValidate
	}
	return validateOptionalLimit(prefix+".max-concurrent", v.MaxConcurrent)
}

func validateOptionalLimit(name string, value *int) error {
	if value != nil && *value < 0 {
		return fmt.Errorf("%s: must not be negative", name)
	}
	return nil
}

// Resolve returns the effective limits for the first provider key that has an
// entry in Providers, falling back to the top-level values for unset fields.
func (c CredentialLimits) Resolve(providerKeys ...string) (rpm, tpm, maxConcurrent int) {
	rpm, tpm, maxConcurrent = c.RPM, c.TPM, c.MaxConcurrent
	if len(c.Providers) == 0 {
		return rpm, tpm, maxConcurrent
	}
	for _, key := range providerKeys {
		values, ok := c.Providers[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		if values.RPM != nil {
			rpm = *values.RPM
		}
		if values.TPM != nil {
			tpm = *values.TPM
		}
		if values.MaxConcurrent != nil {
			maxConcurrent = *values.MaxConcurrent
		}
		break
	}
	return rpm, tpm, maxConcurrent
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
