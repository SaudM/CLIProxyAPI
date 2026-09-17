package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// GetCredentialLimits returns the global per-credential limit defaults.
func (h *Handler) GetCredentialLimits(c *gin.Context) {
	h.mu.Lock()
	limits := h.cfg.CredentialLimits
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"credential-limits": limits})
}

// GetProxyPool lists the configured proxy pool with redacted URLs and how many
// credentials are currently assigned to each entry.
func (h *Handler) GetProxyPool(c *gin.Context) {
	h.mu.Lock()
	pool := append([]config.ProxyPoolEntry(nil), h.cfg.ProxyPool...)
	h.mu.Unlock()
	assigned := make(map[string]int, len(pool))
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			if auth == nil || !strings.EqualFold(strings.TrimSpace(authAttribute(auth, coreauth.AttributeProxyPool)), "true") {
				continue
			}
			assigned[strings.TrimSpace(auth.ProxyURL)]++
		}
	}
	entries := make([]gin.H, 0, len(pool))
	for _, entry := range pool {
		item := gin.H{"url": proxyutil.Redact(entry.URL), "assigned": assigned[entry.URL]}
		if entry.Label != "" {
			item["label"] = entry.Label
		}
		if entry.Timezone != "" {
			item["timezone"] = entry.Timezone
		}
		entries = append(entries, item)
	}
	c.JSON(http.StatusOK, gin.H{"proxy-pool": entries})
}

// GetCredentialPools reports both automatic assignment pools (outbound proxies and
// Claude device platforms) with how many credentials currently land on each entry,
// so the panel can show what the defaults resolve to without exposing proxy secrets.
func (h *Handler) GetCredentialPools(c *gin.Context) {
	h.mu.Lock()
	proxyPool := append([]config.ProxyPoolEntry(nil), h.cfg.ProxyPool...)
	platformPool := append([]config.ClaudePlatformPoolEntry(nil), h.cfg.ClaudeHeaderDefaults.PlatformPool...)
	stabilize := h.cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile != nil && *h.cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile
	h.mu.Unlock()
	proxyAssigned := make(map[string]int, len(proxyPool))
	platformAssigned := make(map[string]int, len(platformPool))
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			if auth == nil {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(authAttribute(auth, coreauth.AttributeProxyPool)), "true") {
				proxyAssigned[strings.TrimSpace(auth.ProxyURL)]++
			}
			if strings.EqualFold(strings.TrimSpace(authAttribute(auth, coreauth.AttributeClaudeDevicePool)), "true") {
				platformAssigned[authAttribute(auth, coreauth.AttributeClaudeDeviceOS)+"/"+authAttribute(auth, coreauth.AttributeClaudeDeviceArch)]++
			}
		}
	}
	proxies := make([]gin.H, 0, len(proxyPool))
	for _, entry := range proxyPool {
		item := gin.H{"url": proxyutil.Redact(entry.URL), "assigned": proxyAssigned[entry.URL]}
		if entry.Label != "" {
			item["label"] = entry.Label
		}
		if entry.Timezone != "" {
			item["timezone"] = entry.Timezone
		}
		proxies = append(proxies, item)
	}
	platforms := make([]gin.H, 0, len(platformPool))
	for _, entry := range platformPool {
		platforms = append(platforms, gin.H{
			"os": entry.OS, "arch": entry.Arch, "weight": entry.Weight,
			"assigned": platformAssigned[entry.OS+"/"+entry.Arch],
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"proxy-pool":               proxies,
		"platform-pool":            platforms,
		"stabilize-device-profile": stabilize,
	})
}

// PutCredentialLimits replaces the global per-credential limit defaults.
func (h *Handler) PutCredentialLimits(c *gin.Context) {
	var body config.CredentialLimits
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	body.Normalize()
	if errValidate := body.Validate(); errValidate != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errValidate.Error()})
		return
	}
	h.mu.Lock()
	h.cfg.CredentialLimits = body
	h.mu.Unlock()
	h.persist(c)
}
