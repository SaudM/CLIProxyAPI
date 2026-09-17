package synthesizer

import (
	"hash/fnv"
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
	entry, ok := pickProxyPoolEntry(cfg.ProxyPool, poolIdentity(auth))
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

func applyProxyPoolToAll(auths []*coreauth.Auth, cfg *config.Config) {
	for _, auth := range auths {
		applyProxyPool(auth, cfg)
	}
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
