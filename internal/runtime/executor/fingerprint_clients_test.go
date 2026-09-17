package executor

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestClaudeExecutor_DescribeFingerprint_ReportsDownstreamVersions(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/2.1.258 (external, cli)"
	auth := &cliproxyauth.Auth{ID: "claude-clients-report", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-x"}}
	helps.RecordClaudeClientVersion(auth.ID, "claude-cli/2.1.258 (external, cli)")
	helps.RecordClaudeClientVersion(auth.ID, "claude-cli/2.1.301 (external, cli)")

	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	clients, ok := report["clients"].(map[string]any)
	if !ok || clients["baseline"] != "2.1.258" {
		t.Fatalf("clients = %v", report["clients"])
	}
	versions := clients["versions"].([]map[string]any)
	if len(versions) != 2 || versions[0]["version"] != "2.1.258" || versions[0]["baseline"] != true || versions[1]["baseline"] != false {
		t.Fatalf("versions = %v", versions)
	}
	warnings, _ := report["warnings"].([]string)
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning, "2.1.301 (1 requests)") && strings.Contains(warning, "baseline 2.1.258") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no version mismatch warning in %v", warnings)
	}

	clean := &cliproxyauth.Auth{ID: "claude-clients-clean", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-y"}}
	if _, has := NewClaudeExecutor(cfg).DescribeFingerprint(clean)["clients"]; has {
		t.Fatal("clients reported for a credential that served no native client")
	}
}
