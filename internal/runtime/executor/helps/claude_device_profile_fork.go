package helps

// Fork supplement (SaudM/CLIProxyAPI): the read-only fingerprint-visibility panel
// (internal/runtime/executor/*_executor_fingerprint.go) reports the upstream
// identity each credential presents. Upstream v8 rewrote claude_device_profile.go
// and dropped the per-credential helpers the panel used, so they are reconstructed
// here on top of v8's internals. This file adds no client-emulation behaviour; the
// cloak itself follows upstream (device headers, beta gating, TLS) per policy.

import (
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// credentialClaudeDeviceProfile layers a credential's device_profile override
// (auth attributes) over the configured claude-header-defaults / built-in
// baseline. Mirrors the pre-v8 fork implementation using v8's constants.
func credentialClaudeDeviceProfile(cfg *config.Config, auth *cliproxyauth.Auth) ClaudeDeviceProfile {
	hdrDefault := func(cfgVal, fallback string) string {
		if strings.TrimSpace(cfgVal) != "" {
			return strings.TrimSpace(cfgVal)
		}
		return fallback
	}

	var hd config.ClaudeHeaderDefaults
	if cfg != nil {
		hd = cfg.ClaudeHeaderDefaults
	}

	profile := ClaudeDeviceProfile{
		UserAgent:      hdrDefault(hd.UserAgent, defaultClaudeFingerprintUserAgent),
		PackageVersion: hdrDefault(hd.PackageVersion, defaultClaudeFingerprintPackageVersion),
		RuntimeVersion: hdrDefault(hd.RuntimeVersion, defaultClaudeFingerprintRuntimeVersion),
		OS:             hdrDefault(hd.OS, defaultClaudeFingerprintOS),
		Arch:           hdrDefault(hd.Arch, defaultClaudeFingerprintArch),
	}
	if auth != nil && auth.Attributes != nil {
		attr := func(key string) string { return strings.TrimSpace(auth.Attributes[key]) }
		userAgent := attr(cliproxyauth.AttributeClaudeDeviceUserAgent)
		packageVersion := attr(cliproxyauth.AttributeClaudeDevicePackageVersion)
		runtimeVersion := attr(cliproxyauth.AttributeClaudeDeviceRuntimeVersion)
		if userAgent != "" && packageVersion != "" && runtimeVersion != "" {
			profile.UserAgent = userAgent
			profile.PackageVersion = packageVersion
			profile.RuntimeVersion = runtimeVersion
		}
		if os := attr(cliproxyauth.AttributeClaudeDeviceOS); os != "" {
			profile.OS = os
		}
		if arch := attr(cliproxyauth.AttributeClaudeDeviceArch); arch != "" {
			profile.Arch = arch
		}
	}
	if version, ok := parseClaudeCLIVersion(profile.UserAgent); ok {
		profile.version = version
		profile.hasVersion = true
	}
	return profile
}

// DefaultClaudeDeviceProfile returns the device profile a credential would
// present (its override merged onto the baseline). Used by the fingerprint panel.
func DefaultClaudeDeviceProfile(cfg *config.Config, auth *cliproxyauth.Auth) ClaudeDeviceProfile {
	return credentialClaudeDeviceProfile(cfg, auth)
}

// CredentialClaudeVersion returns the Claude Code version string the credential
// presents, falling back to the built-in baseline when the User-Agent is unparsable.
func CredentialClaudeVersion(cfg *config.Config, auth *cliproxyauth.Auth) string {
	profile := credentialClaudeDeviceProfile(cfg, auth)
	if version, ok := parseClaudeCLIVersion(profile.UserAgent); ok {
		return strconv.Itoa(version.major) + "." + strconv.Itoa(version.minor) + "." + strconv.Itoa(version.patch)
	}
	return DefaultClaudeVersion(cfg)
}

// LookupStabilizedClaudeDeviceProfile returns the cached, learned device profile
// for a credential when one is live, without resolving or creating an entry.
func LookupStabilizedClaudeDeviceProfile(auth *cliproxyauth.Auth, apiKey string) (ClaudeDeviceProfile, bool) {
	cacheKey := claudeDeviceProfileCacheKey(auth, apiKey, ClaudeDeviceProfile{})
	claudeDeviceProfileCacheMu.RLock()
	defer claudeDeviceProfileCacheMu.RUnlock()
	entry, ok := claudeDeviceProfileCache[cacheKey]
	if !ok || !entry.expire.After(time.Now()) || entry.profile.UserAgent == "" {
		return ClaudeDeviceProfile{}, false
	}
	return entry.profile, true
}
