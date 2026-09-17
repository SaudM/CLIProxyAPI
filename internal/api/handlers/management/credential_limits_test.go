package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func patchAuthFileFields(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)
	return rec
}

func newLimitsTestHandler(t *testing.T) (*Handler, *coreauth.Manager) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:         "limits.json",
		FileName:   "limits.json",
		Provider:   "claude",
		Attributes: map[string]string{"path": "/tmp/limits.json"},
		Metadata:   map[string]any{"type": "claude"},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	return h, manager
}

func TestPatchAuthFileFields_CredentialLimitOverrides(t *testing.T) {
	h, manager := newLimitsTestHandler(t)

	// Set all three; the kebab alias normalizes to max_concurrent.
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","rpm":30,"tpm":4000,"max-concurrent":2}`); rec.Code != http.StatusOK {
		t.Fatalf("set status = %d body %s", rec.Code, rec.Body.String())
	}
	updated, _ := manager.GetByID("limits.json")
	if rpm, ok := updated.RPMOverride(); !ok || rpm != 30 {
		t.Fatalf("rpm override = (%d, %t), want (30, true)", rpm, ok)
	}
	if tpm, ok := updated.TPMOverride(); !ok || tpm != 4000 {
		t.Fatalf("tpm override = (%d, %t), want (4000, true)", tpm, ok)
	}
	if mc, ok := updated.MaxConcurrentOverride(); !ok || mc != 2 {
		t.Fatalf("max_concurrent override = (%d, %t), want (2, true)", mc, ok)
	}
	if _, legacy := updated.Metadata["max-concurrent"]; legacy {
		t.Fatalf("kebab key persisted instead of canonical max_concurrent")
	}

	// Explicit zero is a real override (unlimited), null deletes.
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","rpm":0,"tpm":null}`); rec.Code != http.StatusOK {
		t.Fatalf("zero/null status = %d body %s", rec.Code, rec.Body.String())
	}
	updated, _ = manager.GetByID("limits.json")
	if rpm, ok := updated.RPMOverride(); !ok || rpm != 0 {
		t.Fatalf("rpm after zero = (%d, %t), want (0, true)", rpm, ok)
	}
	if _, ok := updated.TPMOverride(); ok {
		t.Fatalf("tpm override still present after null")
	}

	// Negatives and nested paths are rejected.
	for _, body := range []string{
		`{"name":"limits.json","rpm":-1}`,
		`{"name":"limits.json","tpm":"abc"}`,
		`{"name":"limits.json","max_concurrent.x":1}`,
		`{"name":"limits.json","rpm":1.5}`,
	} {
		if rec := patchAuthFileFields(t, h, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d, want 400", body, rec.Code)
		}
	}
	// request_retry keeps its legacy "negative clears" behaviour.
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","request_retry":-1}`); rec.Code != http.StatusOK {
		t.Fatalf("request_retry negative status = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestListAuthFiles_ExposesCredentialLimits(t *testing.T) {
	h, manager := newLimitsTestHandler(t)
	manager.SetCredentialLimits(config.CredentialLimits{RPM: 50, TPM: 9000}, "")
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","max_concurrent":3}`); rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d", rec.Code)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(payload.Files))
	}
	entry := payload.Files[0]
	if got, _ := entry["max_concurrent"].(float64); got != 3 {
		t.Fatalf("max_concurrent override in entry = %v, want 3", entry["max_concurrent"])
	}
	if _, present := entry["rpm"]; present {
		t.Fatalf("rpm override should not be present when only the global default applies")
	}
	limits, ok := entry["limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits object missing: %v", entry)
	}
	rpm := limits["rpm"].(map[string]any)
	if rpm["limit"].(float64) != 50 || rpm["used"].(float64) != 0 {
		t.Fatalf("limits.rpm = %v, want limit 50 used 0", rpm)
	}
	mc := limits["max_concurrent"].(map[string]any)
	if mc["limit"].(float64) != 3 || mc["in_flight"].(float64) != 0 {
		t.Fatalf("limits.max_concurrent = %v, want limit 3 in_flight 0", mc)
	}
	if tpm := limits["tpm"].(map[string]any); tpm["limit"].(float64) != 9000 {
		t.Fatalf("limits.tpm = %v, want limit 9000", tpm)
	}
}

func TestCredentialLimitsGlobalEndpoint(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	// PUT persists through the config file, so the handler needs a real path.
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("{}\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	h := NewHandler(&config.Config{AuthDir: t.TempDir()}, configPath, coreauth.NewManager(&memoryAuthStore{}, nil, nil))

	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodPut, "/v0/management/credential-limits", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx.Request = req
		h.PutCredentialLimits(ctx)
		return rec
	}
	if rec := put(`{"rpm":12,"tpm":3400,"max-concurrent":2,"providers":{"Claude":{"rpm":20}}}`); rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body %s", rec.Code, rec.Body.String())
	}
	if rec := put(`{"rpm":-1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative put status = %d, want 400", rec.Code)
	}
	if rec := put(`not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid body status = %d, want 400", rec.Code)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/credential-limits", nil)
	h.GetCredentialLimits(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	var payload struct {
		Limits config.CredentialLimits `json:"credential-limits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Limits.RPM != 12 || payload.Limits.TPM != 3400 || payload.Limits.MaxConcurrent != 2 {
		t.Fatalf("limits = %+v", payload.Limits)
	}
	if v, ok := payload.Limits.Providers["claude"]; !ok || v.RPM == nil || *v.RPM != 20 {
		t.Fatalf("providers = %v, want normalized claude rpm 20", payload.Limits.Providers)
	}
}

// plainExecutorStub is a minimal ProviderExecutor without fingerprint support.
type plainExecutorStub struct{ id string }

func (e *plainExecutorStub) Identifier() string { return e.id }
func (e *plainExecutorStub) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *plainExecutorStub) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *plainExecutorStub) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}
func (e *plainExecutorStub) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *plainExecutorStub) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// fingerprintStubExecutor additionally implements FingerprintDescriber.
type fingerprintStubExecutor struct{ plainExecutorStub }

func (e *fingerprintStubExecutor) DescribeFingerprint(auth *coreauth.Auth) map[string]any {
	return map[string]any{"identity_mode": "stub", "user_agent": "stub/1.0 for " + auth.ID}
}

func TestListAuthFiles_ExposesFingerprintWhenExecutorDescribes(t *testing.T) {
	h, manager := newLimitsTestHandler(t)
	manager.RegisterExecutor(&fingerprintStubExecutor{plainExecutorStub{id: "claude"}})

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	fingerprint, ok := payload.Files[0]["fingerprint"].(map[string]any)
	if !ok {
		t.Fatalf("fingerprint missing: %v", payload.Files[0])
	}
	if fingerprint["identity_mode"] != "stub" || fingerprint["user_agent"] != "stub/1.0 for limits.json" {
		t.Fatalf("fingerprint = %v", fingerprint)
	}

	// An executor without the capability contributes no fingerprint field.
	manager.RegisterExecutor(&plainExecutorStub{id: "claude"})
	rec = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	// Decode into a fresh value: unmarshalling into the populated map would merge keys.
	var second struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := second.Files[0]["fingerprint"]; present {
		t.Fatalf("fingerprint present for a non-describing executor")
	}
}

func TestPatchAuthFileFields_ClaudeDeviceProfile(t *testing.T) {
	h, manager := newLimitsTestHandler(t)

	body := `{"name":"limits.json","device_profile":{"user_agent":"claude-cli/2.1.274 (external, cli)","package_version":"0.112.1","runtime_version":"v26.3.0","os":"Linux","arch":"x64"}}`
	if rec := patchAuthFileFields(t, h, body); rec.Code != http.StatusOK {
		t.Fatalf("set status = %d body %s", rec.Code, rec.Body.String())
	}
	updated, _ := manager.GetByID("limits.json")
	if updated.Attributes[coreauth.AttributeClaudeDeviceUserAgent] != "claude-cli/2.1.274 (external, cli)" || updated.Attributes[coreauth.AttributeClaudeDeviceOS] != "Linux" {
		t.Fatalf("device profile attributes not projected: %v", updated.Attributes)
	}

	// Unmeasured tuple is rejected before anything is persisted.
	bad := `{"name":"limits.json","device_profile":{"user_agent":"claude-cli/9.9.9 (external, cli)","package_version":"0.112.1","runtime_version":"v26.3.0"}}`
	if rec := patchAuthFileFields(t, h, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("unmeasured tuple status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","device_profile":{"os":"macos"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad os status = %d, want 400", rec.Code)
	}

	// Clearing the object removes the projected attributes.
	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","device_profile":null}`); rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d body %s", rec.Code, rec.Body.String())
	}
	updated, _ = manager.GetByID("limits.json")
	if _, present := updated.Attributes[coreauth.AttributeClaudeDeviceUserAgent]; present {
		t.Fatalf("device profile attribute survived clearing")
	}
}

func TestProxyPoolEndpointAndProxySource(t *testing.T) {
	h, manager := newLimitsTestHandler(t)
	h.cfg.ProxyPool = []config.ProxyPoolEntry{
		{URL: "socks5://u:secret@10.0.0.1:443", Timezone: "Asia/Tokyo", Label: "jp-1"},
		{URL: "socks5://u:secret@10.0.0.2:443", Label: "jp-2"},
	}
	pooled := &coreauth.Auth{
		ID: "pooled.json", FileName: "pooled.json", Provider: "claude", ProxyURL: "socks5://u:secret@10.0.0.1:443",
		Attributes: map[string]string{"path": "/tmp/pooled.json", coreauth.AttributeProxyPool: "true", coreauth.AttributeProxyPoolLabel: "jp-1"},
		Metadata:   map[string]any{"type": "claude"},
	}
	if _, err := manager.Register(context.Background(), pooled); err != nil {
		t.Fatalf("register: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/proxy-pool", nil)
	h.GetProxyPool(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("proxy credentials leaked: %s", rec.Body.String())
	}
	var payload struct {
		Pool []map[string]any `json:"proxy-pool"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Pool) != 2 || payload.Pool[0]["assigned"].(float64) != 1 || payload.Pool[1]["assigned"].(float64) != 0 {
		t.Fatalf("pool payload = %v", payload.Pool)
	}
	if payload.Pool[0]["timezone"] != "Asia/Tokyo" || payload.Pool[0]["label"] != "jp-1" {
		t.Fatalf("entry[0] = %v", payload.Pool[0])
	}

	rec = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	var files struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &files); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sources := map[string]any{}
	for _, f := range files.Files {
		sources[f["name"].(string)] = f["proxy_source"]
		if f["name"] == "pooled.json" && f["proxy_label"] != "jp-1" {
			t.Fatalf("proxy_label = %v", f["proxy_label"])
		}
	}
	if sources["pooled.json"] != "pool" || sources["limits.json"] != "none" {
		t.Fatalf("proxy_source = %v", sources)
	}
}

func TestCredentialPoolsEndpoint(t *testing.T) {
	h, manager := newLimitsTestHandler(t)
	stabilize := true
	h.cfg.ProxyPool = []config.ProxyPoolEntry{{URL: "socks5://u:secret@10.0.0.1:443", Timezone: "Asia/Tokyo", Label: "jp-1"}}
	h.cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile = &stabilize
	h.cfg.ClaudeHeaderDefaults.PlatformPool = []config.ClaudePlatformPoolEntry{
		{OS: "MacOS", Arch: "arm64", Weight: 6}, {OS: "Windows", Arch: "x64", Weight: 2},
	}
	pooled := &coreauth.Auth{
		ID: "pooled.json", FileName: "pooled.json", Provider: "claude", ProxyURL: "socks5://u:secret@10.0.0.1:443",
		Attributes: map[string]string{
			"path": "/tmp/pooled.json", coreauth.AttributeProxyPool: "true",
			coreauth.AttributeClaudeDevicePool: "true", coreauth.AttributeClaudeDeviceOS: "Windows", coreauth.AttributeClaudeDeviceArch: "x64",
		},
		Metadata: map[string]any{"type": "claude"},
	}
	if _, err := manager.Register(context.Background(), pooled); err != nil {
		t.Fatalf("register: %v", err)
	}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/credential-pools", nil)
	h.GetCredentialPools(ctx)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Proxy     []map[string]any `json:"proxy-pool"`
		Platform  []map[string]any `json:"platform-pool"`
		Stabilize bool             `json:"stabilize-device-profile"`
		Defaults  struct {
			UserAgent      string            `json:"user_agent"`
			PackageVersion string            `json:"package_version"`
			RuntimeVersion string            `json:"runtime_version"`
			OS             string            `json:"os"`
			Arch           string            `json:"arch"`
			Timeout        string            `json:"timeout"`
			Timezone       string            `json:"timezone"`
			Sources        map[string]string `json:"sources"`
		} `json:"device-profile-defaults"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.Stabilize || len(payload.Proxy) != 1 || payload.Proxy[0]["assigned"].(float64) != 1 {
		t.Fatalf("payload = %s", rec.Body.String())
	}
	if len(payload.Platform) != 2 || payload.Platform[1]["assigned"].(float64) != 1 || payload.Platform[0]["assigned"].(float64) != 0 || payload.Platform[0]["weight"].(float64) != 6 {
		t.Fatalf("platform payload = %v", payload.Platform)
	}
	d := payload.Defaults
	if d.UserAgent != "claude-cli/2.1.274 (external, cli)" || d.PackageVersion != "0.112.1" || d.RuntimeVersion != "v26.3.0" || d.OS != "MacOS" || d.Arch != "arm64" || d.Timeout != "600" {
		t.Fatalf("device-profile-defaults = %+v, want the measured built-in baseline", d)
	}
	if d.Sources["user_agent"] != "built-in" || d.Sources["timeout"] != "built-in" || d.Timezone == "" {
		t.Fatalf("device-profile-defaults sources = %v timezone=%q", d.Sources, d.Timezone)
	}
	cfg := config.Config{}
	cfg.ClaudeHeaderDefaults.Timeout = "300"
	cfg.ClaudeHeaderDefaults.Timezone = "Asia/Tokyo"
	configured := deviceProfileDefaultsPayload(&cfg)
	if configured["timeout"] != "300" || configured["timezone"] != "Asia/Tokyo" {
		t.Fatalf("configured defaults = %v", configured)
	}
	if sources := configured["sources"].(gin.H); sources["timeout"] != "config" || sources["timezone"] != "config" || sources["user_agent"] != "built-in" {
		t.Fatalf("configured sources = %v", sources)
	}
}
