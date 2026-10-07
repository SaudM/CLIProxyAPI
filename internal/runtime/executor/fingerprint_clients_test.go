package executor

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestClaudeExecutor_DescribeFingerprint_ReportsDownstreamVersions(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/2.1.274 (external, cli)"
	auth := &cliproxyauth.Auth{ID: "claude-clients-report", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-x"}}
	helps.RecordClaudeClientVersion(auth.ID, "claude-cli/2.1.274 (external, cli)")
	helps.RecordClaudeClientVersion(auth.ID, "claude-cli/2.1.301 (external, cli)")
	helps.RecordClaudeClientVersion(auth.ID, "claude-cli/2.1.270 (external, cli)")

	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	clients, ok := report["clients"].(map[string]any)
	if !ok || clients["baseline"] != "2.1.274" {
		t.Fatalf("clients = %v", report["clients"])
	}
	versions := clients["versions"].([]map[string]any)
	byVersion := make(map[string]map[string]any, len(versions))
	for _, item := range versions {
		byVersion[item["version"].(string)] = item
	}
	if len(byVersion) != 3 || byVersion["2.1.274"]["baseline"] != true || byVersion["2.1.274"]["passthrough"] != true {
		t.Fatalf("versions = %v", versions)
	}
	// A newer patch in the baseline line keeps its own User-Agent; an older one is rewritten.
	if byVersion["2.1.301"]["baseline"] != false || byVersion["2.1.301"]["passthrough"] != true {
		t.Fatalf("2.1.301 = %v, want passthrough", byVersion["2.1.301"])
	}
	if byVersion["2.1.270"]["baseline"] != false || byVersion["2.1.270"]["passthrough"] != false {
		t.Fatalf("2.1.270 = %v, want rewritten", byVersion["2.1.270"])
	}
	warnings, _ := report["warnings"].([]string)
	foundNewer, foundOlder := false, false
	for _, warning := range warnings {
		if strings.Contains(warning, "2.1.301 (1 requests)") && strings.Contains(warning, "newer than the credential baseline 2.1.274") {
			foundNewer = true
		}
		if strings.Contains(warning, "2.1.270 (1 requests)") && strings.Contains(warning, "older than the credential baseline 2.1.274") {
			foundOlder = true
		}
	}
	if !foundNewer || !foundOlder {
		t.Fatalf("version warnings = %v, want newer + older", warnings)
	}

	clean := &cliproxyauth.Auth{ID: "claude-clients-clean", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-y"}}
	if _, has := NewClaudeExecutor(cfg).DescribeFingerprint(clean)["clients"]; has {
		t.Fatal("clients reported for a credential that served no native client")
	}
}
