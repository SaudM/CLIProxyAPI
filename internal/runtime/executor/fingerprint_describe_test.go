package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func fingerprintWarnings(t *testing.T, report map[string]any) []string {
	t.Helper()
	warnings, ok := report["warnings"].([]string)
	if !ok {
		t.Fatalf("warnings has type %T", report["warnings"])
	}
	return warnings
}

func fingerprintHasWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}

// assertNoSecretLeak fails when any of the given secrets appears in the serialized report.
func assertNoSecretLeak(t *testing.T, report map[string]any, secrets ...string) {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaks secret %q: %s", secret, encoded)
		}
	}
}

func TestClaudeExecutor_DescribeFingerprint_OAuthCloaks(t *testing.T) {
	const token = "sk-ant-oat01-secret-token-value"
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/2.1.274 (external, cli)"
	cfg.ClaudeHeaderDefaults.Timezone = "Asia/Singapore"
	auth := &cliproxyauth.Auth{
		ID:       "claude-oauth",
		Provider: "claude",
		ProxyURL: "socks5://user:pass@proxy.local:1080",
		Metadata: map[string]any{
			"access_token":      token,
			"timezone":          "Europe/Berlin",
			"claude_device_ids": []any{"abcdef0123456789abcdef0123456789"},
		},
		Attributes: map[string]string{"header:X-Team": "alpha"},
	}
	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	if report["identity_mode"] != "cloak-claude-code-cli" {
		t.Fatalf("identity_mode = %v", report["identity_mode"])
	}
	if report["auth_kind"] != "oauth" {
		t.Fatalf("auth_kind = %v", report["auth_kind"])
	}
	if report["user_agent"] != "claude-cli/2.1.274 (external, cli)" {
		t.Fatalf("user_agent = %v", report["user_agent"])
	}
	client := report["client"].(map[string]any)
	if client["current_date_timezone"] != "Europe/Berlin" {
		t.Fatalf("timezone = %v, want credential override", client["current_date_timezone"])
	}
	overrides := report["credential_overrides"].(map[string]any)
	if overrides["timezone"] != "Europe/Berlin" {
		t.Fatalf("overrides.timezone = %v", overrides["timezone"])
	}
	if names, _ := overrides["custom_headers"].([]string); len(names) != 1 || names[0] != "X-Team" {
		t.Fatalf("custom_headers = %v", overrides["custom_headers"])
	}
	transport := report["transport"].(map[string]any)
	if transport["tls"] != "utls-claude-code-bun" || transport["http"] != "1.1" {
		t.Fatalf("transport = %v", transport)
	}
	if !strings.HasPrefix(transport["proxy"].(string), "socks5://redacted@proxy.local:1080") {
		t.Fatalf("proxy = %v, want redacted", transport["proxy"])
	}
	device := report["device"].(map[string]any)
	if device["id"] != "abcdef***" || device["id_pool_size"] != 1 {
		t.Fatalf("device = %v", device)
	}
	assertNoSecretLeak(t, report, token, "user:pass", "abcdef0123456789abcdef0123456789")
}

func TestClaudeExecutor_DescribeFingerprint_BareAPIKeyIsPassthrough(t *testing.T) {
	const key = "sk-ant-api03-plain-key"
	cfg := &config.Config{ClaudeKey: []config.ClaudeKey{{APIKey: key}}}
	auth := &cliproxyauth.Auth{
		ID:         "claude-key",
		Provider:   "claude",
		Attributes: map[string]string{"api_key": key},
	}
	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	if report["identity_mode"] != "caller-passthrough" {
		t.Fatalf("identity_mode = %v, want caller-passthrough", report["identity_mode"])
	}
	if report["auth_kind"] != "api-key" {
		t.Fatalf("auth_kind = %v", report["auth_kind"])
	}
	warnings := fingerprintWarnings(t, report)
	if !fingerprintHasWarning(warnings, "caller-passthrough") {
		t.Fatalf("missing passthrough warning: %v", warnings)
	}
	if !fingerprintHasWarning(warnings, "stabilize-device-profile is off") {
		t.Fatalf("missing legacy device warning: %v", warnings)
	}
	assertNoSecretLeak(t, report, key)
}

func TestClaudeExecutor_DescribeFingerprint_CloakModeValidationWarning(t *testing.T) {
	const key = "sk-ant-api03-cloaked"
	cfg := &config.Config{ClaudeKey: []config.ClaudeKey{{APIKey: key, Cloak: &config.CloakConfig{Mode: "always"}}}}
	auth := &cliproxyauth.Auth{ID: "claude-key", Provider: "claude", Attributes: map[string]string{"api_key": key}}
	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	if report["identity_mode"] != "cloak-claude-code-cli" {
		t.Fatalf("always mode identity = %v", report["identity_mode"])
	}
	if report["credential_overrides"].(map[string]any)["cloak_mode"] != "always" {
		t.Fatalf("cloak_mode override missing: %v", report["credential_overrides"])
	}

	typo := &cliproxyauth.Auth{ID: "claude-typo", Provider: "claude", Attributes: map[string]string{"api_key": key}, Metadata: map[string]any{"cloak_mode": "of"}}
	report = NewClaudeExecutor(&config.Config{}).DescribeFingerprint(typo)
	if !fingerprintHasWarning(fingerprintWarnings(t, report), "unrecognised cloak_mode") {
		t.Fatalf("missing unrecognised cloak_mode warning: %v", report["warnings"])
	}
	// Any explicit cloak setting turns cloaking on (cloakConfigured), even a typo.
	if report["identity_mode"] != "cloak-claude-code-cli" {
		t.Fatalf("typo cloak_mode identity = %v", report["identity_mode"])
	}
}

func TestCodexExecutor_DescribeFingerprint(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "codex", Provider: "codex", Metadata: map[string]any{"account_id": "acct_0123456789abcdef"}}

	cfg := &config.Config{}
	cfg.CodexHeaderDefaults.UserAgent = "custom-ua/1.0"
	report := NewCodexExecutor(cfg).DescribeFingerprint(auth)
	if report["user_agent"] != codexUserAgent {
		t.Fatalf("user_agent = %v, want hardcoded while cloaking on", report["user_agent"])
	}
	if !fingerprintHasWarning(fingerprintWarnings(t, report), "codex-header-defaults.user-agent is ignored") {
		t.Fatalf("missing ignored-defaults warning: %v", report["warnings"])
	}
	if report["client"].(map[string]any)["chatgpt_account_id"] != "acct_0***" {
		t.Fatalf("account id = %v, want masked", report["client"].(map[string]any)["chatgpt_account_id"])
	}
	assertNoSecretLeak(t, report, "acct_0123456789abcdef")

	cfg.Codex.DisableCodexCloaking = true
	report = NewCodexExecutor(cfg).DescribeFingerprint(auth)
	if report["user_agent"] != "custom-ua/1.0" || report["identity_mode"] != "fixed" {
		t.Fatalf("cloaking off with config UA: user_agent=%v mode=%v", report["user_agent"], report["identity_mode"])
	}
	cfg.CodexHeaderDefaults.UserAgent = ""
	report = NewCodexExecutor(cfg).DescribeFingerprint(auth)
	if report["identity_mode"] != "caller-passthrough" {
		t.Fatalf("cloaking off without config UA: mode=%v", report["identity_mode"])
	}
	if auto := NewCodexAutoExecutor(cfg).DescribeFingerprint(auth); auto["identity_mode"] != "caller-passthrough" {
		t.Fatalf("auto executor did not delegate: %v", auto["identity_mode"])
	}
}

func TestKimiExecutor_DescribeFingerprint(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "kimi", Provider: "kimi", Metadata: map[string]any{"device_id": "device-0123456789"}}
	report := NewKimiExecutor(&config.Config{}).DescribeFingerprint(auth)
	device := report["device"].(map[string]any)
	if device["id_source"] != "credential" || device["id"] != "device***" {
		t.Fatalf("device = %v", device)
	}
	if !fingerprintHasWarning(fingerprintWarnings(t, report), "identify CLIProxyAPI") {
		t.Fatalf("missing proxy-identifying warning: %v", report["warnings"])
	}
	assertNoSecretLeak(t, report, "device-0123456789")

	noID := &cliproxyauth.Auth{ID: "kimi-2", Provider: "kimi"}
	report = NewKimiExecutor(&config.Config{}).DescribeFingerprint(noID)
	if src := report["device"].(map[string]any)["id_source"]; src != "fallback-literal" && src != "host-kimi-cli" {
		t.Fatalf("id_source without credential id = %v", src)
	}
}

func TestOtherExecutors_DescribeFingerprint(t *testing.T) {
	cfg := &config.Config{}
	cfg.ProxyURL = "http://global-proxy.local:3128"
	auth := &cliproxyauth.Auth{ID: "x", Provider: "x"}

	xai := NewXAIExecutor(cfg).DescribeFingerprint(&cliproxyauth.Auth{ID: "xai", Provider: "xai", Attributes: map[string]string{"using_api": "false"}})
	if xai["identity_mode"] != "fixed" || xai["user_agent"] != "xai-grok-workspace/"+xaiClientVersionValue {
		t.Fatalf("xai = mode:%v ua:%v", xai["identity_mode"], xai["user_agent"])
	}
	if usingAPI := NewXAIExecutor(cfg).DescribeFingerprint(auth); usingAPI["identity_mode"] != "go-default" {
		t.Fatalf("xai using_api default mode = %v", usingAPI["identity_mode"])
	}

	devin := NewDevinExecutor(cfg).DescribeFingerprint(&cliproxyauth.Auth{ID: "devin", Provider: "devin", Metadata: map[string]any{"device_seed": "seed-0123456789"}})
	if devin["identity_mode"] != "suppressed" || devin["device"].(map[string]any)["id_source"] != "seeded" {
		t.Fatalf("devin = %v", devin)
	}
	assertNoSecretLeak(t, devin, "seed-0123456789")

	meta := NewMetaExecutor(cfg).DescribeFingerprint(auth)
	if meta["user_agent"] != metaUserAgent {
		t.Fatalf("meta ua = %v", meta["user_agent"])
	}
	compat := NewOpenAICompatExecutor("openrouter", cfg).DescribeFingerprint(auth)
	if compat["user_agent"] != "cli-proxy-openai-compat" || !fingerprintHasWarning(fingerprintWarnings(t, compat), "identifies the proxy") {
		t.Fatalf("compat = %v", compat)
	}
	gemini := NewGeminiExecutor(cfg).DescribeFingerprint(auth)
	if gemini["identity_mode"] != "go-default" {
		t.Fatalf("gemini mode = %v", gemini["identity_mode"])
	}
	if transport := gemini["transport"].(map[string]any); transport["proxy"] != "http://global-proxy.local:3128" || transport["source"] != "global" {
		t.Fatalf("gemini transport = %v, want global proxy", transport)
	}
	vertex := NewGeminiVertexExecutor(cfg).DescribeFingerprint(auth)
	if vertex["identity_mode"] != "go-default" {
		t.Fatalf("vertex mode = %v", vertex["identity_mode"])
	}
	antigravity := NewAntigravityExecutor(cfg).DescribeFingerprint(&cliproxyauth.Auth{ID: "ag", Provider: "antigravity", Metadata: map[string]any{"user_agent": "antigravity/hub/9.9.9 linux/amd64"}})
	if !strings.Contains(antigravity["user_agent"].(string), "9.9.9") || antigravity["transport"].(map[string]any)["pool"] != "per-credential" {
		t.Fatalf("antigravity = %v", antigravity)
	}
}

func TestClaudeExecutor_DescribeFingerprint_DeviceProfileOverrideDrivesUAAndCCVersion(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClaudeHeaderDefaults.UserAgent = "claude-cli/2.2.0 (external, cli)"
	cfg.ClaudeHeaderDefaults.PackageVersion = "0.95.0"
	cfg.ClaudeHeaderDefaults.RuntimeVersion = "v26.4.0"
	auth := &cliproxyauth.Auth{
		ID:       "claude-oauth",
		Provider: "claude",
		Metadata: map[string]any{"access_token": "sk-ant-oat01-x"},
		Attributes: map[string]string{
			cliproxyauth.AttributeClaudeDeviceUserAgent:      "claude-cli/2.1.274 (external, cli)",
			cliproxyauth.AttributeClaudeDevicePackageVersion: "0.112.1",
			cliproxyauth.AttributeClaudeDeviceRuntimeVersion: "v26.3.0",
			cliproxyauth.AttributeClaudeDeviceOS:             "Linux",
			cliproxyauth.AttributeClaudeDeviceArch:           "x64",
		},
	}
	report := NewClaudeExecutor(cfg).DescribeFingerprint(auth)
	if report["user_agent"] != "claude-cli/2.1.274 (external, cli)" {
		t.Fatalf("user_agent = %v, want credential override", report["user_agent"])
	}
	if report["cc_version"] != "2.1.274" {
		t.Fatalf("cc_version = %v, want 2.1.274 (must follow the credential user-agent)", report["cc_version"])
	}
	device := report["device"].(map[string]any)
	if device["os"] != "Linux" || device["arch"] != "x64" || device["source"] != "credential" {
		t.Fatalf("device = %v", device)
	}
	override := report["credential_overrides"].(map[string]any)["device_profile"].(map[string]string)
	if override["os"] != "Linux" || override["user_agent"] != "claude-cli/2.1.274 (external, cli)" {
		t.Fatalf("device_profile override = %v", override)
	}
}
