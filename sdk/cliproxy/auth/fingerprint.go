package auth

import (
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// FingerprintProxyInfo describes the outbound proxy / connection pool a credential uses.
// Proxy credentials are redacted; globalProxy is the config-level fallback.
func FingerprintProxyInfo(auth *Auth, globalProxy string) map[string]any {
	info := map[string]any{"proxy": "direct", "pool": "shared-default"}
	proxy := ""
	if auth != nil {
		proxy = strings.TrimSpace(auth.ProxyURL)
	}
	switch {
	case proxy != "" && (strings.EqualFold(proxy, "direct") || strings.EqualFold(proxy, "none")):
		info["proxy"] = "direct"
		info["source"] = "credential"
	case proxy != "":
		info["proxy"] = proxyutil.Redact(proxy)
		info["source"] = "credential"
		info["pool"] = "per-proxy"
	case strings.TrimSpace(globalProxy) != "":
		info["proxy"] = proxyutil.Redact(strings.TrimSpace(globalProxy))
		info["source"] = "global"
		info["pool"] = "per-proxy"
	default:
		info["source"] = "none"
	}
	return info
}

// CustomHeaderNames lists the per-credential custom header names (from "header:<Name>"
// attributes) without exposing their values.
func CustomHeaderNames(auth *Auth) []string {
	if auth == nil || len(auth.Attributes) == 0 {
		return nil
	}
	names := make([]string, 0)
	for key := range auth.Attributes {
		if strings.HasPrefix(key, "header:") {
			if name := strings.TrimSpace(strings.TrimPrefix(key, "header:")); name != "" {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// MaskIdentifier keeps a short prefix of an identifier so operators can correlate
// records without the full value leaving the process.
func MaskIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return value[:1] + "***"
	}
	return value[:6] + "***"
}

// Attribute keys carrying a per-credential Claude Code device profile override.
// The synthesizer projects config / auth-file values here; the executor reads
// only attributes so the request path needs no config lookup or metadata lock.
const (
	AttributeClaudeDeviceUserAgent      = "device_profile_user_agent"
	AttributeClaudeDevicePackageVersion = "device_profile_package_version"
	AttributeClaudeDeviceRuntimeVersion = "device_profile_runtime_version"
	AttributeClaudeDeviceOS             = "device_profile_os"
	AttributeClaudeDeviceArch           = "device_profile_arch"
)
