package management

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func templateRequest(t *testing.T, h *Handler, query string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/template"+query, nil)
	h.GetAuthFileTemplate(ctx)
	var payload map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, payload
}

func TestGetAuthFileTemplate(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, coreauth.NewManager(nil, nil, nil))

	code, list := templateRequest(t, h, "")
	providers, _ := list["providers"].([]any)
	if code != http.StatusOK || len(providers) != 2 {
		t.Fatalf("list = %d %v", code, list)
	}
	code, claude := templateRequest(t, h, "?provider=claude")
	if code != http.StatusOK || claude["provider"] != "claude" || claude["file_name"] != "claude-<email>.json" {
		t.Fatalf("claude template = %d %v", code, claude)
	}
	template := claude["template"].(map[string]any)
	for _, key := range []string{"type", "access_token", "refresh_token", "expired"} {
		if _, ok := template[key]; !ok {
			t.Fatalf("minimal template lacks %s: %v", key, template)
		}
	}
	if len(template) != 4 || template["type"] != "claude" {
		t.Fatalf("minimal template = %v, want exactly the four required keys", template)
	}
	optional := claude["optional"].(map[string]any)
	for _, key := range []string{"proxy_pool_label", "device_profile", "rpd", "active_hours", "note"} {
		if _, ok := optional[key]; !ok {
			t.Fatalf("optional keys lack %s: %v", key, optional)
		}
	}
	if code, _ := templateRequest(t, h, "?provider=anthropic"); code != http.StatusOK {
		t.Fatalf("anthropic alias = %d", code)
	}
	if code, _ := templateRequest(t, h, "?provider=gemini"); code != http.StatusNotFound {
		t.Fatalf("unknown provider = %d, want 404", code)
	}
}

func uploadOne(t *testing.T, h *Handler, name, content string) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
	h.UploadAuthFile(ctx)
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return rec.Code, payload
}

func TestUploadAuthFile_TemplateValidation(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	// Untouched template placeholder: rejected before anything is written.
	code, payload := uploadOne(t, h, "claude-a.json", `{"type":"claude","access_token":"<access_token>","refresh_token":"x","expired":"2026-01-01T00:00:00Z"}`)
	if code != http.StatusBadRequest || !strings.Contains(payload["error"].(string), "access_token still contains the template placeholder") {
		t.Fatalf("placeholder upload = %d %v", code, payload)
	}
	if _, exists := manager.GetByID("claude-a.json"); exists {
		t.Fatal("placeholder file was stored")
	}
	// No type at all: rejected with a pointer to the template.
	if code, payload = uploadOne(t, h, "no-type.json", `{"access_token":"x"}`); code != http.StatusBadRequest || !strings.Contains(payload["error"].(string), "\"type\"") {
		t.Fatalf("no-type upload = %d %v", code, payload)
	}
	// Not an object.
	if code, _ = uploadOne(t, h, "array.json", `[1,2]`); code != http.StatusBadRequest {
		t.Fatalf("array upload = %d", code)
	}
	// Missing recommended keys: stored, but the response carries warnings.
	code, payload = uploadOne(t, h, "claude-b.json", `{"type":"claude","access_token":"sk-ant-oat01-x","expired":"2026-01-01T00:00:00Z"}`)
	if code != http.StatusOK || payload["status"] != "ok" {
		t.Fatalf("partial upload = %d %v", code, payload)
	}
	warnings, _ := payload["warnings"].([]any)
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0].(string), "missing refresh_token") {
		t.Fatalf("warnings = %v", payload["warnings"])
	}
	if _, exists := manager.GetByID("claude-b.json"); !exists {
		t.Fatal("file with warnings was not stored")
	}
	// A complete minimal file: no warnings key at all.
	code, payload = uploadOne(t, h, "claude-c.json", `{"type":"claude","access_token":"sk-ant-oat01-x","refresh_token":"sk-ant-ort01-y","expired":"2026-01-01T00:00:00Z"}`)
	if code != http.StatusOK {
		t.Fatalf("complete upload = %d %v", code, payload)
	}
	if _, has := payload["warnings"]; has {
		t.Fatalf("complete upload reported warnings: %v", payload["warnings"])
	}
	// Legacy shapes without a template keep working untouched.
	if code, _ = uploadOne(t, h, "gemini-x.json", `{"type":"gemini","email":"g@example.com"}`); code != http.StatusOK {
		t.Fatalf("gemini upload = %d", code)
	}
}
