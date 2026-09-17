package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// The whole point of a per-credential device profile is that every identity
// signal on one credential agrees. This pins the two that are easiest to get
// out of sync: the User-Agent header and the cc_version inside the body.
func TestClaudeCredentialDeviceProfile_HeaderAndBillingVersionAgree(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/2.2.0 (external, cli)"
	cfg.ClaudeHeaderDefaults.PackageVersion = "0.95.0"
	cfg.ClaudeHeaderDefaults.RuntimeVersion = "v26.4.0"

	const token = "sk-ant-oat01-consistency"
	auth := &cliproxyauth.Auth{
		ID:       "claude-consistency",
		Provider: "claude",
		Metadata: map[string]any{"access_token": token},
		Attributes: map[string]string{
			cliproxyauth.AttributeClaudeDeviceUserAgent:      "claude-cli/2.1.274 (external, cli)",
			cliproxyauth.AttributeClaudeDevicePackageVersion: "0.112.1",
			cliproxyauth.AttributeClaudeDeviceRuntimeVersion: "v26.3.0",
			cliproxyauth.AttributeClaudeDeviceOS:             "Linux",
			cliproxyauth.AttributeClaudeDeviceArch:           "x64",
		},
	}

	payload := []byte(`{"model":"claude-sonnet-5","max_tokens":16,"messages":[{"role":"user","content":"hello there, this is a long enough message"}]}`)
	cloaked, applied, errCloak := applyCloaking(context.Background(), cfg, auth, payload, token, false, false)
	if errCloak != nil || !applied {
		t.Fatalf("applyCloaking = (applied=%t, err=%v)", applied, errCloak)
	}
	billing := gjson.GetBytes(cloaked, "system.0.text").String()
	if !strings.Contains(billing, "cc_version=2.1.274.") {
		t.Fatalf("billing block cc_version does not follow the credential user-agent: %q", billing)
	}

	req, errReq := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if errReq != nil {
		t.Fatal(errReq)
	}
	if errHeaders := applyClaudeHeaders(req, auth, token, false, nil, cloaked, cfg, http.Header{}, false); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders error = %v", errHeaders)
	}
	if got := req.Header.Get("User-Agent"); got != "claude-cli/2.1.274 (external, cli)" {
		t.Fatalf("User-Agent = %q, want credential override", got)
	}
	if got := req.Header.Get("X-Stainless-Package-Version"); got != "0.112.1" {
		t.Fatalf("X-Stainless-Package-Version = %q, want credential tuple", got)
	}
	if got := req.Header.Get("X-Stainless-Runtime-Version"); got != "v26.3.0" {
		t.Fatalf("X-Stainless-Runtime-Version = %q, want credential tuple", got)
	}
	if got := req.Header.Get("X-Stainless-Os"); got != "Linux" {
		t.Fatalf("X-Stainless-Os = %q, want credential Linux", got)
	}
	if got := req.Header.Get("X-Stainless-Arch"); got != "x64" {
		t.Fatalf("X-Stainless-Arch = %q, want credential x64", got)
	}

	// A sibling credential with no override keeps the global baseline on both signals.
	sibling := &cliproxyauth.Auth{ID: "claude-sibling", Provider: "claude", Metadata: map[string]any{"access_token": token}}
	cloakedSibling, _, errSibling := applyCloaking(context.Background(), cfg, sibling, payload, token, false, false)
	if errSibling != nil {
		t.Fatal(errSibling)
	}
	if billingSibling := gjson.GetBytes(cloakedSibling, "system.0.text").String(); !strings.Contains(billingSibling, "cc_version=2.2.0.") {
		t.Fatalf("sibling billing cc_version = %q, want global 2.2.0", billingSibling)
	}
	reqSibling, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if errHeaders := applyClaudeHeaders(reqSibling, sibling, token, false, nil, cloakedSibling, cfg, http.Header{}, false); errHeaders != nil {
		t.Fatal(errHeaders)
	}
	if got := reqSibling.Header.Get("User-Agent"); got != "claude-cli/2.2.0 (external, cli)" {
		t.Fatalf("sibling User-Agent = %q, want global baseline", got)
	}
}
