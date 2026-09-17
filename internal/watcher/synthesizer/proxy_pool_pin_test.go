package synthesizer

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestApplyProxyPoolHonoursPinnedLabel(t *testing.T) {
	cfg := poolConfig()
	pinned := &coreauth.Auth{ID: "claude-pin@example.json", Provider: "claude", Metadata: map[string]any{"proxy_pool_label": "KR-1"}}
	applyProxyPool(pinned, cfg)
	if pinned.ProxyURL != "socks5://u:p@10.0.0.3:443" {
		t.Fatalf("pinned proxy = %q, want kr-1 entry", pinned.ProxyURL)
	}
	if pinned.Attributes[coreauth.AttributeProxyPoolLabel] != "kr-1" || pinned.Attributes[coreauth.AttributeTimezone] != "Asia/Seoul" {
		t.Fatalf("pinned attributes = %v", pinned.Attributes)
	}
	// A pin whose label disappeared falls back to the same stable hash as an unpinned credential.
	unpinned := &coreauth.Auth{ID: "claude-pin@example.json", Provider: "claude"}
	applyProxyPool(unpinned, cfg)
	stale := &coreauth.Auth{ID: "claude-pin@example.json", Provider: "claude", Metadata: map[string]any{"proxy_pool_label": "gone"}}
	applyProxyPool(stale, cfg)
	if stale.ProxyURL == "" || stale.ProxyURL != unpinned.ProxyURL {
		t.Fatalf("stale pin proxy = %q, want hash assignment %q", stale.ProxyURL, unpinned.ProxyURL)
	}
}
