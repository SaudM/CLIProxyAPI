package executor

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity Meta (Muse) requests carry for this credential.
func (e *MetaExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeFixed)
	userAgent := metaUserAgent
	if auth.Attributes != nil {
		if custom := strings.TrimSpace(auth.Attributes["header:User-Agent"]); custom != "" && custom != metaUserAgent {
			userAgent = custom
			fingerprintOverrides(report)["user_agent"] = custom
		}
	}
	report["user_agent"] = userAgent
	report["client"] = map[string]any{}
	report["session"] = "none"
	fingerprintSetTransport(report, "go", "auto")
	return report
}

// DescribeFingerprint reports the identity OpenAI-compatible requests carry for this credential.
func (e *OpenAICompatExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeFixed)
	report["user_agent"] = "cli-proxy-openai-compat"
	report["client"] = map[string]any{}
	report["session"] = "optional prompt_cache_key"
	fingerprintSetTransport(report, "go", "auto")
	fingerprintAddWarning(report, "User-Agent cli-proxy-openai-compat identifies the proxy to the upstream")
	return report
}

// DescribeFingerprint reports the identity Gemini / Interactions requests carry for this credential.
func (e *GeminiExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeGoDefault)
	report["user_agent"] = "Go-http-client (no User-Agent set)"
	report["client"] = map[string]any{}
	report["session"] = "none"
	fingerprintSetTransport(report, "go", "auto")
	return report
}

// DescribeFingerprint reports the identity Vertex requests carry for this credential.
func (e *GeminiVertexExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeGoDefault)
	report["user_agent"] = "Go-http-client (no User-Agent set)"
	report["client"] = map[string]any{}
	report["session"] = "none"
	fingerprintSetTransport(report, "go", "auto")
	return report
}

// DescribeFingerprint reports the identity Antigravity requests carry for this credential.
func (e *AntigravityExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeFixed)
	report["user_agent"] = resolveUserAgent(auth)
	if custom := antigravityConfiguredUserAgent(auth); custom != "" {
		fingerprintOverrides(report)["user_agent"] = custom
	}
	report["client"] = map[string]any{
		"ide_type":      "ANTIGRAVITY",
		"hub_version":   misc.AntigravityLatestVersion(),
		"onboard_agent": misc.AntigravityNodeAPIClientUA,
	}
	report["session"] = "derived"
	fingerprintSetTransport(report, "go", "1.1")
	if transport, ok := report["transport"].(map[string]any); ok {
		transport["pool"] = "per-credential"
	}
	return report
}
