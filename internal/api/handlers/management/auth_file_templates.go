package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// authFileTemplateField documents one key of an auth file template.
type authFileTemplateField struct {
	Key         string `json:"key"`
	Required    bool   `json:"required"`
	Example     any    `json:"example"`
	Description string `json:"description"`
}

// authFileTemplate is the minimal auth file for one provider plus the optional keys
// the panel can append. Placeholder values are wrapped in angle brackets; an upload
// that still carries one is rejected so a half-edited template cannot become a
// broken credential.
type authFileTemplate struct {
	Provider string
	Label    string
	FileName string
	Required []authFileTemplateField
	Optional []authFileTemplateField
}

// authFileTuningFields are the per-credential knobs every OAuth file may carry.
var authFileTuningFields = []authFileTemplateField{
	{Key: "email", Example: "<you@example.com>", Description: "Account e-mail; used for the card label and the suggested file name. Claude fills it from the account profile when absent."},
	{Key: "note", Example: "", Description: "Free text shown on the credential card."},
	{Key: "proxy_pool_label", Example: "", Description: "Pin the credential to one proxy-pool line by its label (login, refresh and requests share that egress)."},
	{Key: "proxy_url", Example: "", Description: "Explicit egress proxy (socks5://user:pass@host:port). Overrides the proxy pool; leave empty to use the pool."},
	{Key: "timezone", Example: "", Description: "IANA timezone for the cloaked clock and daily budgets. Defaults to the proxy-pool line's timezone."},
	{Key: "device_profile", Example: map[string]string{"os": "", "arch": ""}, Description: "Pin the presented platform: os MacOS|Windows|Linux, arch arm64|x64. Empty = platform pool."},
	{Key: "rpm", Example: 0, Description: "Requests per minute for this credential; omit to inherit the global default, 0 = unlimited."},
	{Key: "tpm", Example: 0, Description: "Counted tokens per minute (uncached input + cache writes + output); omit to inherit."},
	{Key: "max_concurrent", Example: 0, Description: "In-flight requests; omit to inherit."},
	{Key: "rpd", Example: 0, Description: "Requests per calendar day; omit to inherit."},
	{Key: "tpd", Example: 0, Description: "Counted tokens per calendar day; omit to inherit."},
	{Key: "max_sessions", Example: 0, Description: "Distinct downstream sessions per window; omit to inherit."},
	{Key: "active_hours", Example: "", Description: "Daily window HH:MM-HH:MM in the credential's timezone; \"\" = always on, omit to inherit."},
	{Key: "priority", Example: 0, Description: "Selection priority; higher wins for cold bindings."},
	{Key: "weight", Example: 1, Description: "Weight for weighted-round-robin routing."},
	{Key: "disabled", Example: false, Description: "true parks the credential without deleting the file."},
}

var authFileTemplates = []authFileTemplate{
	{
		Provider: "claude",
		Label:    "Claude (OAuth)",
		FileName: "claude-<email>.json",
		Required: []authFileTemplateField{
			{Key: "type", Required: true, Example: "claude", Description: "Provider marker; must be \"claude\"."},
			{Key: "access_token", Required: true, Example: "<access_token>", Description: "OAuth access token (sk-ant-oat01-…)."},
			{Key: "refresh_token", Required: true, Example: "<refresh_token>", Description: "OAuth refresh token (sk-ant-ort01-…); without it the credential stops working when the access token expires."},
			{Key: "expired", Required: true, Example: "<2026-01-01T00:00:00Z>", Description: "Access token expiry, RFC 3339. The proxy refreshes the token shortly before this instant."},
		},
		Optional: authFileTuningFields,
	},
	{
		Provider: "codex",
		Label:    "Codex / ChatGPT (OAuth)",
		FileName: "codex-<email>.json",
		Required: []authFileTemplateField{
			{Key: "type", Required: true, Example: "codex", Description: "Provider marker; must be \"codex\"."},
			{Key: "access_token", Required: true, Example: "<access_token>", Description: "ChatGPT OAuth access token (JWT)."},
			{Key: "refresh_token", Required: true, Example: "<refresh_token>", Description: "OAuth refresh token."},
			{Key: "account_id", Required: true, Example: "<account_id>", Description: "ChatGPT account id sent as Chatgpt-Account-Id. Filled in on the first refresh when absent."},
			{Key: "expired", Required: true, Example: "<2026-01-01T00:00:00Z>", Description: "Access token expiry, RFC 3339."},
		},
		Optional: authFileTuningFields,
	},
}

func authFileTemplateFor(provider string) (authFileTemplate, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "anthropic" {
		provider = "claude"
	}
	for _, template := range authFileTemplates {
		if template.Provider == provider {
			return template, true
		}
	}
	return authFileTemplate{}, false
}

// minimal returns the required keys with their placeholder values, in template order.
func (t authFileTemplate) minimal() map[string]any {
	out := make(map[string]any, len(t.Required))
	for _, field := range t.Required {
		out[field.Key] = field.Example
	}
	return out
}

func (t authFileTemplate) optionalValues() map[string]any {
	out := make(map[string]any, len(t.Optional))
	for _, field := range t.Optional {
		out[field.Key] = field.Example
	}
	return out
}

func (t authFileTemplate) payload() gin.H {
	fields := make([]authFileTemplateField, 0, len(t.Required)+len(t.Optional))
	fields = append(fields, t.Required...)
	fields = append(fields, t.Optional...)
	return gin.H{
		"provider":  t.Provider,
		"label":     t.Label,
		"file_name": t.FileName,
		"template":  t.minimal(),
		"optional":  t.optionalValues(),
		"fields":    fields,
	}
}

// GetAuthFileTemplate returns the minimal upload template for one provider, or the
// list of providers that have one when no provider is given.
func (h *Handler) GetAuthFileTemplate(c *gin.Context) {
	provider := strings.TrimSpace(c.Query("provider"))
	if provider == "" {
		providers := make([]gin.H, 0, len(authFileTemplates))
		for _, template := range authFileTemplates {
			providers = append(providers, gin.H{"provider": template.Provider, "label": template.Label, "file_name": template.FileName})
		}
		c.JSON(http.StatusOK, gin.H{"providers": providers})
		return
	}
	template, ok := authFileTemplateFor(provider)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no template for provider %q", provider)})
		return
	}
	c.JSON(http.StatusOK, template.payload())
}

// isAuthFilePlaceholder reports whether a string value is an untouched template placeholder.
func isAuthFilePlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 2 && strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">")
}

// validateUploadedAuthFile checks an uploaded auth file before it is stored. It
// rejects what can never load (not an object, no type, template placeholders left
// in) and returns warnings for recommended keys that are missing, so the operator
// learns about a credential that will fail later — e.g. no refresh_token — right
// at upload time.
func validateUploadedAuthFile(data []byte) ([]string, error) {
	var metadata map[string]any
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil || metadata == nil {
		return nil, fmt.Errorf("auth file must be a JSON object")
	}
	coreauth.NormalizeCredentialMetadata(metadata)
	rawType, _ := metadata["type"].(string)
	if strings.TrimSpace(rawType) == "" {
		return nil, fmt.Errorf("auth file has no \"type\" (e.g. \"claude\" or \"codex\"); download a template from the panel")
	}
	if isAuthFilePlaceholder(rawType) {
		return nil, fmt.Errorf("\"type\" still contains the template placeholder %s", rawType)
	}
	template, ok := authFileTemplateFor(rawType)
	if !ok {
		return nil, nil
	}
	warnings := make([]string, 0)
	for _, field := range template.Required {
		value, present := metadata[field.Key]
		text, isString := value.(string)
		switch {
		case !present || (isString && strings.TrimSpace(text) == ""):
			warnings = append(warnings, fmt.Sprintf("missing %s: %s", field.Key, field.Description))
		case isString && isAuthFilePlaceholder(text):
			return nil, fmt.Errorf("%s still contains the template placeholder %s; paste the real value", field.Key, text)
		}
	}
	for _, field := range template.Optional {
		if text, isString := metadata[field.Key].(string); isString && isAuthFilePlaceholder(text) {
			return nil, fmt.Errorf("%s still contains the template placeholder %s; fill it in or remove the key", field.Key, text)
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}
