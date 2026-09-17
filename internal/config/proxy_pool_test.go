package config

import (
	"strings"
	"testing"
)

func TestParseConfigBytesProxyPoolAcceptsScalarAndMappingEntries(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
proxy-pool:
  - "socks5://u:p@10.0.0.1:443"
  - url: " socks5://u:p@10.0.0.2:443 "
    timezone: "Asia/Tokyo"
    label: " jp-2 "
  - url: "socks5://u:p@10.0.0.1:443"
  - url: ""
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes error = %v", err)
	}
	if len(cfg.ProxyPool) != 2 {
		t.Fatalf("pool = %+v, want 2 entries (duplicate and empty dropped)", cfg.ProxyPool)
	}
	if cfg.ProxyPool[0].URL != "socks5://u:p@10.0.0.1:443" || cfg.ProxyPool[0].Timezone != "" {
		t.Fatalf("entry[0] = %+v", cfg.ProxyPool[0])
	}
	if cfg.ProxyPool[1].URL != "socks5://u:p@10.0.0.2:443" || cfg.ProxyPool[1].Timezone != "Asia/Tokyo" || cfg.ProxyPool[1].Label != "jp-2" {
		t.Fatalf("entry[1] = %+v", cfg.ProxyPool[1])
	}
}

func TestParseConfigBytesProxyPoolValidation(t *testing.T) {
	cases := map[string]string{
		"relative url":     "proxy-pool:\n  - \"10.0.0.1:443\"\n",
		"bad scheme":       "proxy-pool:\n  - \"ftp://u:p@10.0.0.1:443\"\n",
		"unknown timezone": "proxy-pool:\n  - url: \"socks5://u:p@10.0.0.1:443\"\n    timezone: \"Mars/Olympus\"\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfigBytes([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "proxy-pool[0]") {
				t.Fatalf("ParseConfigBytes error = %v, want proxy-pool[0] validation error", err)
			}
		})
	}
	if _, err := ParseConfigBytes([]byte("request-retry: 1\n")); err != nil {
		t.Fatalf("empty pool must be valid: %v", err)
	}
}
