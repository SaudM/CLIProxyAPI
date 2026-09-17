package synthesizer

import (
	"fmt"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func platformPoolConfig() *config.Config {
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.PlatformPool = []config.ClaudePlatformPoolEntry{
		{OS: "MacOS", Arch: "arm64", Weight: 3},
		{OS: "Windows", Arch: "x64", Weight: 1},
	}
	return cfg
}

func TestApplyClaudePlatformPoolAssignsStablyAndOnlyToClaude(t *testing.T) {
	cfg := platformPoolConfig()
	auth := &coreauth.Auth{ID: "claude-a@example.json", Provider: "claude"}
	applyClaudePlatformPool(auth, cfg)
	if auth.Attributes[coreauth.AttributeClaudeDeviceOS] == "" || auth.Attributes[coreauth.AttributeClaudeDeviceArch] == "" {
		t.Fatalf("no platform assigned: %v", auth.Attributes)
	}
	if auth.Attributes[coreauth.AttributeClaudeDevicePool] != "true" {
		t.Fatalf("pool marker missing: %v", auth.Attributes)
	}
	again := &coreauth.Auth{ID: "claude-a@example.json", Provider: "claude"}
	applyClaudePlatformPool(again, cfg)
	if again.Attributes[coreauth.AttributeClaudeDeviceOS] != auth.Attributes[coreauth.AttributeClaudeDeviceOS] {
		t.Fatalf("assignment not stable")
	}
	codex := &coreauth.Auth{ID: "codex-a.json", Provider: "codex"}
	applyClaudePlatformPool(codex, cfg)
	if codex.Attributes != nil {
		t.Fatalf("non-Claude credential received a platform: %v", codex.Attributes)
	}
}

func TestApplyClaudePlatformPoolRespectsExplicitDeviceProfile(t *testing.T) {
	cfg := platformPoolConfig()
	explicit := &coreauth.Auth{ID: "x", Provider: "claude", Attributes: map[string]string{coreauth.AttributeClaudeDeviceOS: "Linux"}}
	applyClaudePlatformPool(explicit, cfg)
	if explicit.Attributes[coreauth.AttributeClaudeDeviceOS] != "Linux" || explicit.Attributes[coreauth.AttributeClaudeDevicePool] != "" {
		t.Fatalf("explicit platform overridden: %v", explicit.Attributes)
	}
	none := &coreauth.Auth{ID: "y", Provider: "claude"}
	applyClaudePlatformPool(none, &config.Config{})
	if none.Attributes != nil {
		t.Fatalf("empty pool assigned a platform")
	}
}

func TestPickClaudePlatformPoolEntryFollowsWeights(t *testing.T) {
	pool := platformPoolConfig().ClaudeHeaderDefaults.PlatformPool
	counts := map[string]int{}
	const n = 2000
	for i := 0; i < n; i++ {
		entry, ok := pickClaudePlatformPoolEntry(pool, fmt.Sprintf("account-%d.json", i))
		if !ok {
			t.Fatalf("no pick for %d", i)
		}
		counts[entry.OS+"/"+entry.Arch]++
	}
	mac := float64(counts["MacOS/arm64"]) / n
	if mac < 0.70 || mac > 0.80 {
		t.Fatalf("MacOS/arm64 share = %.3f, want ~0.75 for weight 3:1 (%v)", mac, counts)
	}
	zero := []config.ClaudePlatformPoolEntry{{OS: "Linux", Arch: "x64", Weight: 0}}
	if _, ok := pickClaudePlatformPoolEntry(zero, "a"); ok {
		t.Fatalf("zero-weight entry was picked")
	}
}

func TestSynthesizeAuthFileAppliesPlatformPool(t *testing.T) {
	cfg := platformPoolConfig()
	ctx := &SynthesisContext{Config: cfg, IDGenerator: NewStableIDGenerator()}
	auths, err := SynthesizeAuthFile(ctx, "/tmp/auths/claude-pool@example.json", []byte(`{"type":"claude","access_token":"sk-ant-oat01-x"}`))
	if err != nil || len(auths) != 1 {
		t.Fatalf("SynthesizeAuthFile = (%d, %v)", len(auths), err)
	}
	if auths[0].Attributes[coreauth.AttributeClaudeDevicePool] != "true" {
		t.Fatalf("file auth did not receive a pool platform: %v", auths[0].Attributes)
	}
	pinned, err := SynthesizeAuthFile(ctx, "/tmp/auths/claude-pinned@example.json", []byte(`{"type":"claude","access_token":"sk-ant-oat01-y","device_profile":{"os":"Linux","arch":"x64"}}`))
	if err != nil || len(pinned) != 1 || pinned[0].Attributes[coreauth.AttributeClaudeDeviceOS] != "Linux" || pinned[0].Attributes[coreauth.AttributeClaudeDevicePool] != "" {
		t.Fatalf("explicit device_profile should win: %v (err %v)", pinned, err)
	}
}
