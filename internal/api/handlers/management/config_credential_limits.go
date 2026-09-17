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
