package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestForkDefaultsApplyWhenKeysAreAbsent(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("host: \"0.0.0.0\"\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if !reflect.DeepEqual(cfg.CredentialLimits, DefaultCredentialLimits()) {
		t.Fatalf("credential-limits = %+v, want fork defaults", cfg.CredentialLimits)
	}
	if cfg.RequestRetry != DefaultRequestRetry || cfg.MaxRetryInterval != DefaultMaxRetryInterval {
		t.Fatalf("retry = %d/%d", cfg.RequestRetry, cfg.MaxRetryInterval)
	}
	if !cfg.Routing.SessionAffinity || cfg.Routing.SessionAffinityTTL != DefaultSessionAffinityTTL {
		t.Fatalf("routing = %+v", cfg.Routing)
	}
	if !cfg.CommercialMode || !cfg.ForceModelPrefix {
		t.Fatalf("commercial-mode=%v force-model-prefix=%v, want both on", cfg.CommercialMode, cfg.ForceModelPrefix)
	}
	if cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile == nil || !*cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile {
		t.Fatal("stabilize-device-profile should default to true")
	}
	if !reflect.DeepEqual(cfg.ClaudeHeaderDefaults.PlatformPool, DefaultClaudePlatformPool()) {
		t.Fatalf("platform-pool = %+v, want the default pool", cfg.ClaudeHeaderDefaults.PlatformPool)
	}
	if cfg.RemoteManagement.PanelGitHubRepository != "https://github.com/SaudM/Cli-Proxy-API-Management-Center" {
		t.Fatalf("panel repo = %q", cfg.RemoteManagement.PanelGitHubRepository)
	}
}

func TestForkDefaultsAreOverlaidByExplicitKeys(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
request-retry: 0
max-retry-interval: 0
commercial-mode: false
routing:
  session-affinity: false
credential-limits:
  rpm: 10
  tpm: 0
claude-header-defaults:
  stabilize-device-profile: false
  platform-pool: []
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if cfg.RequestRetry != 0 || cfg.MaxRetryInterval != 0 || cfg.CommercialMode || cfg.Routing.SessionAffinity {
		t.Fatalf("explicit zero/false not honoured: retry=%d/%d commercial=%v affinity=%v", cfg.RequestRetry, cfg.MaxRetryInterval, cfg.CommercialMode, cfg.Routing.SessionAffinity)
	}
	if cfg.Routing.SessionAffinityTTL != DefaultSessionAffinityTTL {
		t.Fatalf("untouched routing key lost its default: ttl=%q", cfg.Routing.SessionAffinityTTL)
	}
	limits := cfg.CredentialLimits
	if limits.RPM != 10 || limits.TPM != 0 || limits.RPD != 3000 || limits.MaxSessions != 6 || limits.LimitJitterPercent != 15 {
		t.Fatalf("partial credential-limits block = %+v, want rpm 10, tpm unlimited, rest default", limits)
	}
	if cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile == nil || *cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile {
		t.Fatal("stabilize-device-profile: false not honoured")
	}
	if len(cfg.ClaudeHeaderDefaults.PlatformPool) != 0 {
		t.Fatalf("platform-pool: [] should disable the pool, got %+v", cfg.ClaudeHeaderDefaults.PlatformPool)
	}
}

func TestForkDefaultsForMissingAndEmptyConfigFiles(t *testing.T) {
	missing, errMissing := LoadConfigOptional(filepath.Join(t.TempDir(), "absent.yaml"), true)
	if errMissing != nil {
		t.Fatalf("LoadConfigOptional(missing) error = %v", errMissing)
	}
	if missing.CredentialLimits.RPM != 30 || missing.MaxRetryInterval != DefaultMaxRetryInterval {
		t.Fatalf("missing file config = limits %+v retry-interval %d", missing.CredentialLimits, missing.MaxRetryInterval)
	}
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if errWrite := os.WriteFile(empty, []byte("\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cfg, errEmpty := LoadConfigOptional(empty, true)
	if errEmpty != nil {
		t.Fatalf("LoadConfigOptional(empty) error = %v", errEmpty)
	}
	if !reflect.DeepEqual(cfg.CredentialLimits, DefaultCredentialLimits()) || !cfg.Routing.SessionAffinity {
		t.Fatalf("empty file config = %+v", cfg.CredentialLimits)
	}
	if !reflect.DeepEqual(DefaultClaudePlatformPool(), (&Config{ClaudeHeaderDefaults: ClaudeHeaderDefaults{PlatformPool: DefaultClaudePlatformPool()}}).ClaudeHeaderDefaults.PlatformPool) {
		t.Fatal("DefaultClaudePlatformPool must return a fresh, equal slice each call")
	}
}
