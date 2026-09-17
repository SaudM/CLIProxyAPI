package synthesizer

import (
	"fmt"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func poolConfig() *config.Config {
	return &config.Config{ProxyPool: []config.ProxyPoolEntry{
		{URL: "socks5://u:p@10.0.0.1:443", Timezone: "Asia/Tokyo", Label: "jp-1"},
		{URL: "socks5://u:p@10.0.0.2:443", Timezone: "Asia/Tokyo", Label: "jp-2"},
		{URL: "socks5://u:p@10.0.0.3:443", Timezone: "Asia/Seoul", Label: "kr-1"},
	}}
}

func TestApplyProxyPoolAssignsStablyAndInheritsTimezone(t *testing.T) {
	cfg := poolConfig()
	first := &coreauth.Auth{ID: "claude-a@example.json", Provider: "claude"}
	applyProxyPool(first, cfg)
	if first.ProxyURL == "" || first.Attributes[coreauth.AttributeProxyPool] != "true" {
		t.Fatalf("no pool proxy assigned: %+v", first)
	}
	again := &coreauth.Auth{ID: "claude-a@example.json", Provider: "claude"}
	applyProxyPool(again, cfg)
	if again.ProxyURL != first.ProxyURL {
		t.Fatalf("assignment not stable: %s vs %s", again.ProxyURL, first.ProxyURL)
	}
	wantTZ := ""
	for _, entry := range cfg.ProxyPool {
		if entry.URL == first.ProxyURL {
			wantTZ = entry.Timezone
			if first.Attributes[coreauth.AttributeProxyPoolLabel] != entry.Label {
				t.Fatalf("label = %q, want %q", first.Attributes[coreauth.AttributeProxyPoolLabel], entry.Label)
			}
		}
	}
	if first.Attributes[coreauth.AttributeTimezone] != wantTZ {
		t.Fatalf("timezone = %q, want the pool entry's %q", first.Attributes[coreauth.AttributeTimezone], wantTZ)
	}
}

func TestApplyProxyPoolRespectsExplicitProxyAndTimezone(t *testing.T) {
	cfg := poolConfig()
	explicit := &coreauth.Auth{ID: "x", ProxyURL: "socks5://own@1.2.3.4:1080"}
	applyProxyPool(explicit, cfg)
	if explicit.ProxyURL != "socks5://own@1.2.3.4:1080" || explicit.Attributes[coreauth.AttributeProxyPool] != "" {
		t.Fatalf("explicit proxy overridden: %+v", explicit)
	}
	direct := &coreauth.Auth{ID: "y", ProxyURL: "direct"}
	applyProxyPool(direct, cfg)
	if direct.ProxyURL != "direct" {
		t.Fatalf("direct overridden: %s", direct.ProxyURL)
	}
	pinnedTZ := &coreauth.Auth{ID: "z", Metadata: map[string]any{"timezone": "Europe/Berlin"}}
	applyProxyPool(pinnedTZ, cfg)
	if pinnedTZ.ProxyURL == "" {
		t.Fatalf("pool proxy not assigned to credential with its own timezone")
	}
	if _, overwritten := pinnedTZ.Attributes[coreauth.AttributeTimezone]; overwritten {
		t.Fatalf("credential timezone overwritten by the pool: %v", pinnedTZ.Attributes)
	}
	none := &coreauth.Auth{ID: "n"}
	applyProxyPool(none, &config.Config{})
	if none.ProxyURL != "" {
		t.Fatalf("empty pool assigned a proxy")
	}
}

func TestApplyProxyPoolSpreadsAcrossEntriesAndOnlyMovesAffectedOnRemoval(t *testing.T) {
	cfg := poolConfig()
	counts := map[string]int{}
	assigned := map[string]string{}
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("account-%d.json", i)
		auth := &coreauth.Auth{ID: id}
		applyProxyPool(auth, cfg)
		counts[auth.ProxyURL]++
		assigned[id] = auth.ProxyURL
	}
	for _, entry := range cfg.ProxyPool {
		if counts[entry.URL] < 60 {
			t.Fatalf("entry %s got only %d of 300 credentials: %v", entry.URL, counts[entry.URL], counts)
		}
	}
	// Removing one entry must not reshuffle credentials that hashed to the others.
	removed := cfg.ProxyPool[2].URL
	smaller := &config.Config{ProxyPool: cfg.ProxyPool[:2]}
	for id, before := range assigned {
		auth := &coreauth.Auth{ID: id}
		applyProxyPool(auth, smaller)
		if before != removed && auth.ProxyURL != before {
			t.Fatalf("%s moved from %s to %s although its entry stayed", id, before, auth.ProxyURL)
		}
		if before == removed && auth.ProxyURL == removed {
			t.Fatalf("%s still assigned to a removed entry", id)
		}
	}
}

func TestSynthesizeAuthFileAppliesProxyPool(t *testing.T) {
	cfg := poolConfig()
	ctx := &SynthesisContext{Config: cfg, Now: time.Unix(1_700_000_000, 0), IDGenerator: NewStableIDGenerator()}
	auths, err := SynthesizeAuthFile(ctx, "/tmp/auths/claude-pool@example.json", []byte(`{"type":"claude","access_token":"sk-ant-oat01-x"}`))
	if err != nil || len(auths) != 1 {
		t.Fatalf("SynthesizeAuthFile = (%d auths, %v)", len(auths), err)
	}
	if auths[0].ProxyURL == "" || auths[0].Attributes[coreauth.AttributeProxyPool] != "true" {
		t.Fatalf("file auth did not receive a pool proxy: %+v", auths[0])
	}
	if auths[0].Attributes[coreauth.AttributeTimezone] == "" {
		t.Fatalf("file auth did not inherit the pool timezone")
	}
	own, err := SynthesizeAuthFile(ctx, "/tmp/auths/claude-own@example.json", []byte(`{"type":"claude","access_token":"sk-ant-oat01-y","proxy_url":"socks5://own@9.9.9.9:1080"}`))
	if err != nil || len(own) != 1 || own[0].ProxyURL != "socks5://own@9.9.9.9:1080" || own[0].Attributes[coreauth.AttributeProxyPool] != "" {
		t.Fatalf("file proxy_url should win over the pool: %+v (err %v)", own, err)
	}
}
