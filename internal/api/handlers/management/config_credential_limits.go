package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// GetCredentialLimits returns the global per-credential limit defaults.
func (h *Handler) GetCredentialLimits(c *gin.Context) {
	h.mu.Lock()
	limits := h.cfg.CredentialLimits
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"credential-limits": limits})
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
