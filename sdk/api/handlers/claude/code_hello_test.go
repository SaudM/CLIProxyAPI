package claude

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func helloRequest(t *testing.T, h *ClaudeCodeAPIHandler, userAgent string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodHead, "/api/hello", nil)
	ctx.Request.Header.Set("User-Agent", userAgent)
	h.ClaudeHello(ctx)
	// gin defers the status write until the response is flushed; read it from the writer.
	return ctx.Writer.Status()
}

func TestClaudeHelloReplaysProbeRoundRobinWithThrottle(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	for _, auth := range []*coreauth.Auth{
		{ID: "a", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-a"}},
		{ID: "b", Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-b"}},
		{ID: "key-only", Provider: "claude", Metadata: map[string]any{"api_key": "sk-ant-api03-x"}},
		{ID: "disabled", Provider: "claude", Disabled: true, Metadata: map[string]any{"access_token": "sk-ant-oat01-d"}},
		{ID: "codex", Provider: "codex", Metadata: map[string]any{"access_token": "x"}},
	} {
		if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("register %s: %v", auth.ID, errRegister)
		}
	}
	h := NewClaudeCodeAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{ProxyURL: "socks5://global:1080"}, manager))

	now := time.Unix(1_800_000_000, 0)
	previous := helloState
	helloState = &claudeHelloState{lastProbe: make(map[string]time.Time), now: func() time.Time { return now }}
	t.Cleanup(func() { helloState = previous })
	var seen []string
	var seenProxy []string
	original := claudeHelloForwarder
	claudeHelloForwarder = func(_ context.Context, globalProxy string, auth *coreauth.Auth) (int, error) {
		seen = append(seen, auth.ID)
		seenProxy = append(seenProxy, globalProxy)
		return http.StatusNoContent, nil
	}
	t.Cleanup(func() { claudeHelloForwarder = original })

	// Non-native callers never trigger a probe.
	if code := helloRequest(t, h, "curl/8.0"); code != http.StatusOK || len(seen) != 0 {
		t.Fatalf("non-native probe: code=%d forwarded=%v", code, seen)
	}
	// Native probes rotate over the usable OAuth credentials only.
	for i := 0; i < 2; i++ {
		if code := helloRequest(t, h, "Bun/1.4.3"); code != http.StatusNoContent {
			t.Fatalf("probe %d code = %d, want upstream 204", i, code)
		}
	}
	if len(seen) != 2 || seen[0] == seen[1] || (seen[0] != "a" && seen[0] != "b") || (seen[1] != "a" && seen[1] != "b") {
		t.Fatalf("forwarded credentials = %v, want a and b once each", seen)
	}
	if seenProxy[0] != "socks5://global:1080" {
		t.Fatalf("global proxy passed = %q", seenProxy[0])
	}
	// Both credentials probed within the interval: the third native probe is not replayed.
	if code := helloRequest(t, h, "Bun/1.4.3"); code != http.StatusOK || len(seen) != 2 {
		t.Fatalf("throttled probe: code=%d forwarded=%v", code, seen)
	}
	now = now.Add(claudeHelloMinInterval)
	if code := helloRequest(t, h, "Bun/1.4.3"); code != http.StatusNoContent || len(seen) != 3 {
		t.Fatalf("probe after interval: code=%d forwarded=%v", code, seen)
	}
}
