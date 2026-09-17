package executor

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Identity modes reported by DescribeFingerprint implementations.
const (
	fingerprintModeCloakClaudeCodeCLI = "cloak-claude-code-cli"
	fingerprintModeCallerPassthrough  = "caller-passthrough"
	fingerprintModeFixed              = "fixed"
	fingerprintModeGoDefault          = "go-default"
	fingerprintModeSuppressed         = "suppressed"
)

// fingerprintBase builds the provider-independent part of a fingerprint report:
// outbound proxy/pool and the names of per-credential custom headers.
func fingerprintBase(cfg *config.Config, auth *cliproxyauth.Auth, identityMode string) map[string]any {
	globalProxy := ""
	if cfg != nil {
		globalProxy = cfg.ProxyURL
	}
	report := map[string]any{
		"identity_mode": identityMode,
		"transport":     cliproxyauth.FingerprintProxyInfo(auth, globalProxy),
		"warnings":      []string{},
	}
	overrides := map[string]any{}
	if names := cliproxyauth.CustomHeaderNames(auth); len(names) > 0 {
		overrides["custom_headers"] = names
	}
	report["credential_overrides"] = overrides
	return report
}

func fingerprintAddWarning(report map[string]any, warning string) {
	warning = strings.TrimSpace(warning)
	if report == nil || warning == "" {
		return
	}
	existing, _ := report["warnings"].([]string)
	report["warnings"] = append(existing, warning)
}

func fingerprintSetTransport(report map[string]any, tlsProfile, httpVersion string) {
	transport, _ := report["transport"].(map[string]any)
	if transport == nil {
		transport = map[string]any{}
		report["transport"] = transport
	}
	transport["tls"] = tlsProfile
	transport["http"] = httpVersion
}

func fingerprintOverrides(report map[string]any) map[string]any {
	overrides, _ := report["credential_overrides"].(map[string]any)
	if overrides == nil {
		overrides = map[string]any{}
		report["credential_overrides"] = overrides
	}
	return overrides
}

// fingerprintMetadataString reads a string-ish value from Attributes then Metadata.
func fingerprintMetadataString(auth *cliproxyauth.Auth, key string) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
			return value
		}
	}
	if auth.Metadata != nil {
		switch value := auth.Metadata[key].(type) {
		case string:
			return strings.TrimSpace(value)
		case bool:
			if value {
				return "true"
			}
			return "false"
		}
	}
	return ""
}
