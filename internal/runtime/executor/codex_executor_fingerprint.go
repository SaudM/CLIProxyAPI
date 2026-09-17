package executor

import (
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity Codex requests carry for this credential.
func (e *CodexExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	cloaking := e.cfg == nil || !e.cfg.Codex.DisableCodexCloaking
	configuredUA := ""
	if e.cfg != nil {
		configuredUA = strings.TrimSpace(e.cfg.CodexHeaderDefaults.UserAgent)
	}
	mode := fingerprintModeFixed
	userAgent := codexUserAgent
	originator := codexOriginator
	if !cloaking {
		switch {
		case configuredUA != "":
			userAgent = configuredUA
		default:
			mode = fingerprintModeCallerPassthrough
			userAgent = "downstream client User-Agent"
		}
		originator = "downstream passthrough (default " + codexOriginator + ")"
	}
	report := fingerprintBase(e.cfg, auth, mode)
	report["user_agent"] = userAgent
	client := map[string]any{
		"originator":    originator,
		"cloaking":      cloaking,
		"turn_metadata": "downstream passthrough",
	}
	if accountID := fingerprintMetadataString(auth, "account_id"); accountID != "" {
		client["chatgpt_account_id"] = cliproxyauth.MaskIdentifier(accountID)
	}
	if e.cfg != nil && e.cfg.Codex.IdentityConfuse {
		client["identity_confuse"] = true
	}
	report["client"] = client
	report["session"] = "derived-or-downstream"
	fingerprintSetTransport(report, "utls-chrome (http) / go (websocket)", "2 (http) / 1.1 (websocket)")
	if cloaking && configuredUA != "" {
		fingerprintAddWarning(report, "codex-header-defaults.user-agent is ignored while codex cloaking is on; set codex.disable-codex-cloaking: true to honour it")
	}
	if cloaking {
		fingerprintAddWarning(report, "all Codex credentials on this node share the same hardcoded User-Agent")
	}
	fingerprintAddWarning(report, "websocket transport uses Go's TLS ClientHello while HTTP uses a Chrome profile for the same account")
	return report
}

// DescribeFingerprint delegates to the HTTP executor, which owns the identity policy.
func (e *CodexAutoExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || e.httpExec == nil {
		return nil
	}
	return e.httpExec.DescribeFingerprint(auth)
}
