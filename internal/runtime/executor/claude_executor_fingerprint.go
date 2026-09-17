package executor

import (
	"strings"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity an unconfirmed client's request would carry
// to Anthropic on this credential. It runs the same policy resolution as the request
// path with confirmedClaudeCode=false, so the report matches wire behaviour.
func (e *ClaudeExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	apiKey, baseURL := claudeCreds(auth)
	policy, settings := resolveClaudeWirePolicy(e.cfg, auth, apiKey, false)

	mode := fingerprintModeCallerPassthrough
	if policy.Cloak {
		mode = fingerprintModeCloakClaudeCodeCLI
	}
	report := fingerprintBase(e.cfg, auth, mode)
	if policy.OAuth {
		report["auth_kind"] = "oauth"
	} else {
		report["auth_kind"] = "api-key"
	}

	profile := helps.DefaultClaudeDeviceProfile(e.cfg, auth)
	device := map[string]any{
		"os":     profile.OS,
		"arch":   profile.Arch,
		"source": "config",
	}
	if auth.Attributes != nil {
		for _, key := range []string{
			cliproxyauth.AttributeClaudeDeviceUserAgent, cliproxyauth.AttributeClaudeDeviceOS, cliproxyauth.AttributeClaudeDeviceArch,
		} {
			if strings.TrimSpace(auth.Attributes[key]) != "" {
				device["source"] = "credential"
				break
			}
		}
		if strings.EqualFold(strings.TrimSpace(auth.Attributes[cliproxyauth.AttributeClaudeDevicePool]), "true") {
			device["source"] = "platform-pool"
		}
	}
	stabilized := helps.ClaudeDeviceProfileStabilizationEnabled(e.cfg)
	if stabilized {
		if cached, ok := helps.LookupStabilizedClaudeDeviceProfile(auth, apiKey); ok {
			profile = cached
			device["source"] = "stabilized-cache"
		}
	}
	if pool, ok := auth.Metadata["claude_device_ids"]; ok {
		if ids, okIDs := pool.([]any); okIDs && len(ids) > 0 {
			if first, okFirst := ids[0].(string); okFirst {
				device["id"] = cliproxyauth.MaskIdentifier(first)
			}
			device["id_pool_size"] = len(ids)
		}
	}
	report["device"] = device

	if policy.Cloak {
		report["user_agent"] = profile.UserAgent
		report["client"] = map[string]any{
			"x-app":                       "cli",
			"x-stainless-package-version": profile.PackageVersion,
			"x-stainless-runtime-version": profile.RuntimeVersion,
			"x-stainless-lang":            "js",
			"x-stainless-runtime":         "node",
			"system_prompt":               "replaced with Claude Code billing block",
			"current_date_timezone":       claudeCodeTimezone(e.cfg, auth).String(),
		}
		report["session"] = "derived-or-per-api-key-1h"
	} else {
		report["user_agent"] = "downstream client User-Agent (fallback CLIProxyAPI/" + buildinfo.Version + ")"
		report["client"] = map[string]any{
			"x-app":       "downstream passthrough",
			"x-stainless": "downstream passthrough",
			"anthropic-*": "downstream passthrough",
		}
		report["session"] = "downstream passthrough"
		fingerprintAddWarning(report, "caller-passthrough: the downstream client's User-Agent, x-stainless-* and anthropic-* headers reach Anthropic unchanged; set fingerprint-profile: claude-code-cli or a cloak block to present the Claude Code shape")
	}

	if strings.Contains(strings.ToLower(baseURL), "api.anthropic.com") || strings.TrimSpace(baseURL) == "" {
		fingerprintSetTransport(report, "utls-node", "1.1")
	} else {
		fingerprintSetTransport(report, "go", "auto")
	}

	overrides := fingerprintOverrides(report)
	cloakMode := fingerprintMetadataString(auth, "cloak_mode")
	if cloakCfg := resolveClaudeKeyCloakConfig(e.cfg, auth); cloakCfg != nil {
		if mode := strings.TrimSpace(cloakCfg.Mode); mode != "" {
			cloakMode = mode
		}
		if strings.TrimSpace(cloakCfg.Mode) == "" && !policy.ConfirmedClaudeCode {
			fingerprintAddWarning(report, "a cloak block without a mode implicitly enables cloaking for this API key")
		}
	}
	if cloakMode != "" {
		overrides["cloak_mode"] = cloakMode
		switch strings.ToLower(strings.TrimSpace(cloakMode)) {
		case "auto", "always", "never":
		default:
			fingerprintAddWarning(report, "unrecognised cloak_mode "+cloakMode+" is treated as auto")
		}
	}
	if settings.strictMode {
		overrides["cloak_strict_mode"] = true
	}
	if settings.cacheUserID {
		overrides["cloak_cache_user_id"] = true
	}
	if len(settings.sensitiveWords) > 0 {
		overrides["cloak_sensitive_words"] = len(settings.sensitiveWords)
	}
	if profileName := claudeFingerprintProfileFromConfig(e.cfg, auth); profileName != claudeFingerprintProfileDefault {
		overrides["fingerprint_profile"] = profileName
	}
	if timezone := claudeCredentialTimezone(auth); timezone != "" {
		overrides["timezone"] = timezone
	}
	if auth.Attributes != nil {
		deviceOverride := map[string]string{}
		for label, key := range map[string]string{
			"user_agent":      cliproxyauth.AttributeClaudeDeviceUserAgent,
			"package_version": cliproxyauth.AttributeClaudeDevicePackageVersion,
			"runtime_version": cliproxyauth.AttributeClaudeDeviceRuntimeVersion,
			"os":              cliproxyauth.AttributeClaudeDeviceOS,
			"arch":            cliproxyauth.AttributeClaudeDeviceArch,
		} {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				deviceOverride[label] = value
			}
		}
		if len(deviceOverride) > 0 {
			overrides["device_profile"] = deviceOverride
		}
	}
	report["cc_version"] = helps.CredentialClaudeVersion(e.cfg, auth)
	if !stabilized {
		fingerprintAddWarning(report, "stabilize-device-profile is off: confirmed native clients that omit X-Stainless-OS/Arch get the proxy host's OS/arch")
	}
	if len(claudeauth.ReadMetadataString(&auth.Metadata, "access_token")) == 0 && policy.OAuth {
		fingerprintAddWarning(report, "oauth credential has no access_token in metadata")
	}
	return report
}
