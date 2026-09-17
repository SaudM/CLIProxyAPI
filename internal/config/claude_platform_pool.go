package config

import (
	"fmt"
	"strings"
)

// ClaudePlatformPoolEntry is one (os, arch) platform a Claude credential may be
// assigned automatically when it has no device-profile platform of its own.
// Weight shapes the distribution across credentials (default 1).
type ClaudePlatformPoolEntry struct {
	OS     string `yaml:"os" json:"os"`
	Arch   string `yaml:"arch" json:"arch"`
	Weight int    `yaml:"weight,omitempty" json:"weight,omitempty"`
}

// NormalizeClaudePlatformPool trims fields, defaults weights to 1, merges duplicate
// platforms by summing weights, and drops entries that end up with no weight.
func (cfg *Config) NormalizeClaudePlatformPool() {
	if cfg == nil || len(cfg.ClaudeHeaderDefaults.PlatformPool) == 0 {
		return
	}
	index := make(map[string]int)
	normalized := make([]ClaudePlatformPoolEntry, 0, len(cfg.ClaudeHeaderDefaults.PlatformPool))
	for _, entry := range cfg.ClaudeHeaderDefaults.PlatformPool {
		entry.OS = strings.TrimSpace(entry.OS)
		entry.Arch = strings.TrimSpace(entry.Arch)
		if entry.Weight == 0 {
			entry.Weight = 1
		}
		if entry.Weight < 0 || (entry.OS == "" && entry.Arch == "") {
			continue
		}
		key := entry.OS + "/" + entry.Arch
		if at, seen := index[key]; seen {
			normalized[at].Weight += entry.Weight
			continue
		}
		index[key] = len(normalized)
		normalized = append(normalized, entry)
	}
	cfg.ClaudeHeaderDefaults.PlatformPool = normalized
}

// ValidateClaudePlatformPool rejects platforms outside the Stainless vocabulary and negative weights.
func (cfg *Config) ValidateClaudePlatformPool() error {
	if cfg == nil {
		return nil
	}
	for index, entry := range cfg.ClaudeHeaderDefaults.PlatformPool {
		if entry.Weight < 0 {
			return fmt.Errorf("claude-header-defaults.platform-pool[%d]: weight must not be negative", index)
		}
		if errValidate := (ClaudeDeviceProfileValues{OS: entry.OS, Arch: entry.Arch}).Validate(); errValidate != nil {
			return fmt.Errorf("claude-header-defaults.platform-pool[%d]: %w", index, errValidate)
		}
	}
	return nil
}
