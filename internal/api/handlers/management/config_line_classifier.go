package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Line-classifier management endpoints. They expose only the runtime-editable
// fields (url, key, model); the lines table and default are operator-fixed in
// the config file. The API key is never returned in full — only a masked tail —
// so listing the config does not leak it.

// GetLineClassifier returns the current settings with the key masked.
func (h *Handler) GetLineClassifier(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	lc := h.cfg.Routing.LineClassifier
	c.JSON(http.StatusOK, gin.H{
		"url":          lc.URL,
		"model":        lc.Model,
		"key_set":      strings.TrimSpace(lc.Key) != "",
		"key_masked":   maskSecretTail(lc.Key),
		"lines":        lc.Lines,
		"default-line": lc.DefaultLine,
		"enabled":      strings.TrimSpace(lc.URL) != "" && strings.TrimSpace(lc.Model) != "",
	})
}

// PutLineClassifier updates url/key/model. An absent or empty "key" keeps the
// existing stored key, so the operator can edit url/model without re-typing the
// secret (which the GET never reveals in full).
func (h *Handler) PutLineClassifier(c *gin.Context) {
	var body struct {
		URL   *string `json:"url"`
		Key   *string `json:"key"`
		Model *string `json:"model"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if body.URL != nil {
		u := strings.TrimSpace(*body.URL)
		if u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "url must start with http:// or https://"})
			return
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	lc := &h.cfg.Routing.LineClassifier
	if body.URL != nil {
		lc.URL = strings.TrimRight(strings.TrimSpace(*body.URL), "/")
	}
	if body.Model != nil {
		lc.Model = strings.TrimSpace(*body.Model)
	}
	// Empty/absent key => keep existing; a non-empty value replaces it.
	if body.Key != nil && strings.TrimSpace(*body.Key) != "" {
		lc.Key = strings.TrimSpace(*body.Key)
	}
	h.persistLocked(c)
}

// maskSecretTail shows only the last 4 chars of a secret, for safe display.
func maskSecretTail(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	r := []rune(k)
	if len(r) <= 4 {
		return "****"
	}
	return "****" + string(r[len(r)-4:])
}
