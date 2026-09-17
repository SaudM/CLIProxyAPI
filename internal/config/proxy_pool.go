package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProxyPoolEntry is one outbound proxy a credential may be assigned automatically.
// Timezone lets the credential's cloaked clock follow the proxy's region so an IP
// in one country never pairs with a wall clock from another.
type ProxyPoolEntry struct {
	URL      string `yaml:"url" json:"url"`
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Label    string `yaml:"label,omitempty" json:"label,omitempty"`
}

// UnmarshalYAML accepts either a bare proxy URL scalar or a mapping with url/timezone/label.
func (e *ProxyPoolEntry) UnmarshalYAML(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		e.URL = strings.TrimSpace(node.Value)
		return nil
	}
	type plain ProxyPoolEntry
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*e = ProxyPoolEntry(decoded)
	return nil
}

var proxyPoolSchemes = map[string]struct{}{"http": {}, "https": {}, "socks5": {}, "socks5h": {}}

// NormalizeProxyPool trims fields and drops empty or duplicate URLs, keeping first occurrence order.
func (cfg *Config) NormalizeProxyPool() {
	if cfg == nil || len(cfg.ProxyPool) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(cfg.ProxyPool))
	normalized := make([]ProxyPoolEntry, 0, len(cfg.ProxyPool))
	for _, entry := range cfg.ProxyPool {
		entry.URL = strings.TrimSpace(entry.URL)
		entry.Timezone = strings.TrimSpace(entry.Timezone)
		entry.Label = strings.TrimSpace(entry.Label)
		if entry.URL == "" {
			continue
		}
		if _, duplicate := seen[entry.URL]; duplicate {
			continue
		}
		seen[entry.URL] = struct{}{}
		normalized = append(normalized, entry)
	}
	cfg.ProxyPool = normalized
}

// ValidateProxyPool rejects entries that cannot be used as a proxy or carry an unknown timezone.
func (cfg *Config) ValidateProxyPool() error {
	if cfg == nil {
		return nil
	}
	for index, entry := range cfg.ProxyPool {
		parsed, errParse := url.Parse(entry.URL)
		if errParse != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("proxy-pool[%d]: url must be an absolute proxy URL (http, https, socks5 or socks5h)", index)
		}
		if _, ok := proxyPoolSchemes[strings.ToLower(parsed.Scheme)]; !ok {
			return fmt.Errorf("proxy-pool[%d]: unsupported scheme %q", index, parsed.Scheme)
		}
		if entry.Timezone != "" {
			if _, errLocation := time.LoadLocation(entry.Timezone); errLocation != nil {
				return fmt.Errorf("proxy-pool[%d]: unknown timezone %q", index, entry.Timezone)
			}
		}
	}
	return nil
}
