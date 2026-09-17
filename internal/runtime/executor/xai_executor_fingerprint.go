package executor

import (
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity xAI requests carry for this credential.
func (e *XAIExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeFixed)
	report["session"] = "derived (x-grok-conv-id)"
	fingerprintSetTransport(report, "go", "auto")
	if xaiUsingAPI(auth) || !xaiIsCLIChatProxyBaseURL(xaiChatBaseURL(auth)) {
		report["identity_mode"] = fingerprintModeGoDefault
		report["user_agent"] = "Go-http-client (official API path, no client headers)"
		report["client"] = map[string]any{"using_api": true}
		return report
	}
	report["user_agent"] = "xai-grok-workspace/" + xaiClientVersionValue
	report["client"] = map[string]any{
		xaiTokenAuthHeader:            xaiTokenAuthValue,
		xaiClientVersionHeader:        xaiClientVersionValue,
		xaiClientIdentifierHeader:     xaiClientIdentifierValue,
		xaiAuthenticateResponseHeader: xaiAuthenticateResponseValue,
	}
	fingerprintAddWarning(report, "websocket path sends none of the CLI client headers")
	return report
}
