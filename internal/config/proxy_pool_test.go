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

func TestParseConfigBytesClaudePlatformPool(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
claude-header-defaults:
  stabilize-device-profile: true
  platform-pool:
    - { os: "MacOS", arch: "arm64", weight: 6 }
    - { os: " Windows ", arch: "x64" }
    - { os: "MacOS", arch: "arm64", weight: 2 }
    - { os: "Linux", arch: "x64", weight: 0 }
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes error = %v", err)
	}
	pool := cfg.ClaudeHeaderDefaults.PlatformPool
	if len(pool) != 3 {
		t.Fatalf("pool = %+v, want 3 entries (duplicate merged)", pool)
	}
	if pool[0].Weight != 8 || pool[1].OS != "Windows" || pool[1].Weight != 1 {
		t.Fatalf("pool = %+v", pool)
	}
	// weight 0 is normalized to the default 1, so the Linux entry stays.
	if pool[2].OS != "Linux" || pool[2].Weight != 1 {
		t.Fatalf("pool[2] = %+v", pool[2])
	}
	if cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile == nil || !*cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile {
		t.Fatalf("stabilize-device-profile not parsed")
	}
	for name, yaml := range map[string]string{
		"bad os":          "claude-header-defaults:\n  platform-pool:\n    - { os: \"macos\", arch: \"arm64\" }\n",
		"bad arch":        "claude-header-defaults:\n  platform-pool:\n    - { os: \"MacOS\", arch: \"amd64\" }\n",
		"negative weight": "claude-header-defaults:\n  platform-pool:\n    - { os: \"MacOS\", arch: \"arm64\", weight: -1 }\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, errParse := ParseConfigBytes([]byte(yaml)); errParse == nil || !strings.Contains(errParse.Error(), "platform-pool[0]") {
				t.Fatalf("ParseConfigBytes error = %v, want platform-pool[0] validation error", errParse)
			}
		})
	}
}
