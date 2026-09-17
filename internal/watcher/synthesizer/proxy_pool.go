package synthesizer

import (
	"hash/fnv"
	"math"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// applyProxyPool assigns a pool proxy to a credential that has no explicit proxy of
// its own. The choice is a rendezvous hash of the credential ID, so an account keeps
// the same egress IP across reloads and restarts without anything being written to
// its auth file, and adding or removing a pool entry only moves the accounts that
// hashed to that entry. A credential-level proxy_url (including "direct") always wins.
func applyProxyPool(auth *coreauth.Auth, cfg *config.Config) {
	if auth == nil || cfg == nil || len(cfg.ProxyPool) == 0 {
		return
	}
	if strings.TrimSpace(auth.ProxyURL) != "" {
		return
	}
	// A credential pinned to a labelled entry (set at OAuth login, or edited later) uses
	// that entry; a pin whose label no longer exists falls back to the stable hash.
	entry, ok := pinnedProxyPoolEntry(cfg.ProxyPool, auth)
	if !ok {
		entry, ok = pickProxyPoolEntry(cfg.ProxyPool, poolIdentity(auth))
	}
	if !ok {
		return
	}
	auth.ProxyURL = entry.URL
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[coreauth.AttributeProxyPool] = "true"
	if entry.Label != "" {
		auth.Attributes[coreauth.AttributeProxyPoolLabel] = entry.Label
	}
	// The cloaked clock follows the proxy's region unless the credential pins its own timezone.
	if entry.Timezone != "" && !credentialHasTimezone(auth) {
		auth.Attributes[coreauth.AttributeTimezone] = entry.Timezone
	}
}

// pinnedProxyPoolEntry returns the pool entry whose label matches the credential's
// proxy_pool_label metadata, if any.
func pinnedProxyPoolEntry(pool []config.ProxyPoolEntry, auth *coreauth.Auth) (config.ProxyPoolEntry, bool) {
	label := auth.ProxyPoolLabel()
	if label == "" {
		return config.ProxyPoolEntry{}, false
	}
	for _, entry := range pool {
		if strings.EqualFold(strings.TrimSpace(entry.Label), label) {
			return entry, true
		}
	}
	return config.ProxyPoolEntry{}, false
}

// applyCredentialPools applies every automatic per-credential assignment.
func applyCredentialPools(auth *coreauth.Auth, cfg *config.Config) {
	applyProxyPool(auth, cfg)
	applyClaudePlatformPool(auth, cfg)
}

func applyCredentialPoolsToAll(auths []*coreauth.Auth, cfg *config.Config) {
	for _, auth := range auths {
		applyCredentialPools(auth, cfg)
	}
}

// applyClaudePlatformPool assigns an (os, arch) platform to a Claude credential that
// has no device-profile platform of its own, by a weighted rendezvous hash of the
// credential ID. Explicit device_profile os/arch always wins; the software triple is
// never touched because it is bound to the measured TLS profile.
func applyClaudePlatformPool(auth *coreauth.Auth, cfg *config.Config) {
	if auth == nil || cfg == nil || len(cfg.ClaudeHeaderDefaults.PlatformPool) == 0 {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
		return
	}
	if auth.Attributes != nil {
		if strings.TrimSpace(auth.Attributes[coreauth.AttributeClaudeDeviceOS]) != "" ||
			strings.TrimSpace(auth.Attributes[coreauth.AttributeClaudeDeviceArch]) != "" {
			return
		}
	}
	entry, ok := pickClaudePlatformPoolEntry(cfg.ClaudeHeaderDefaults.PlatformPool, poolIdentity(auth))
	if !ok {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	if entry.OS != "" {
		auth.Attributes[coreauth.AttributeClaudeDeviceOS] = entry.OS
	}
	if entry.Arch != "" {
		auth.Attributes[coreauth.AttributeClaudeDeviceArch] = entry.Arch
	}
	auth.Attributes[coreauth.AttributeClaudeDevicePool] = "true"
}

// pickClaudePlatformPoolEntry is weighted rendezvous hashing: each entry scores
// -ln(u)/weight for a per-(identity, entry) uniform u, and the lowest score wins, so
// the share of credentials landing on an entry is proportional to its weight.
func pickClaudePlatformPoolEntry(pool []config.ClaudePlatformPoolEntry, identity string) (config.ClaudePlatformPoolEntry, bool) {
	if len(pool) == 0 || identity == "" {
		return config.ClaudePlatformPoolEntry{}, false
	}
	var best config.ClaudePlatformPoolEntry
	bestScore := math.Inf(1)
	found := false
	for _, entry := range pool {
		weight := entry.Weight
		if weight <= 0 {
			continue
		}
		hasher := fnv.New64a()
		_, _ = hasher.Write([]byte(identity))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(entry.OS + "/" + entry.Arch))
		// Map the top 53 bits to u in (0, 1] so ln(u) is finite.
		u := float64((hasher.Sum64()>>11)+1) / float64(uint64(1)<<53)
		score := -math.Log(u) / float64(weight)
		if !found || score < bestScore {
			best, bestScore, found = entry, score, true
		}
	}
	return best, found
}

func poolIdentity(auth *coreauth.Auth) string {
	if id := strings.TrimSpace(auth.ID); id != "" {
		return id
	}
	if auth.Attributes != nil {
		if path := strings.TrimSpace(auth.Attributes[coreauth.AttributePath]); path != "" {
			return path
		}
	}
	return strings.TrimSpace(auth.FileName)
}

func credentialHasTimezone(auth *coreauth.Auth) bool {
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes[coreauth.AttributeTimezone]) != "" {
		return true
	}
	if auth.Metadata != nil {
		if value, ok := auth.Metadata[coreauth.AttributeTimezone].(string); ok && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// pickProxyPoolEntry returns the entry with the highest rendezvous score for identity.
func pickProxyPoolEntry(pool []config.ProxyPoolEntry, identity string) (config.ProxyPoolEntry, bool) {
	if len(pool) == 0 || identity == "" {
		return config.ProxyPoolEntry{}, false
	}
	var best config.ProxyPoolEntry
	var bestScore uint64
	found := false
	for _, entry := range pool {
		if strings.TrimSpace(entry.URL) == "" {
			continue
		}
		hasher := fnv.New64a()
		_, _ = hasher.Write([]byte(identity))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(entry.URL))
		score := hasher.Sum64()
		if !found || score > bestScore || (score == bestScore && entry.URL < best.URL) {
			best, bestScore, found = entry, score, true
		}
	}
	return best, found
}
