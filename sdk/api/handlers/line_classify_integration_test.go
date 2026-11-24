package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/lineclassifier"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// Verifies the classifier is actually invoked by the handler hook (classifyLine)
// and rewrites the model to the chosen line's prefix; and that with no router
// installed the model is returned unchanged (feature off by default).
func TestHandler_ClassifyLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "write"}}},
		})
	}))
	defer srv.Close()

	h := &BaseAPIHandler{}

	// No router installed -> unchanged.
	if got := h.classifyLine(context.Background(), "claude", "claude-x",
		[]byte(`{"messages":[{"role":"user","content":"hi"}]}`)); got != "claude-x" {
		t.Fatalf("no router should pass model through, got %q", got)
	}

	// Install a router pointing at the fake classifier.
	router := lineclassifier.RouterFromConfig(
		[]string{"build", "write", "misc"}, "misc", 200, 2000, 60,
		func() lineclassifier.Settings {
			return lineclassifier.Settings{URL: srv.URL, Model: "cheap"}
		},
	)
	h.SetLineRouter(router)

	body := []byte(`{"model":"claude-x","messages":[{"role":"user","content":"write a tweet"}]}`)
	got := h.classifyLine(context.Background(), "claude", "claude-x", body)
	if got != "write/claude-x" {
		t.Fatalf("handler should rewrite model via classifier, got %q", got)
	}

	// Disabling (empty settings) -> Active() false -> unchanged again.
	h.SetLineRouter(lineclassifier.RouterFromConfig(
		[]string{"build"}, "build", 200, 2000, 60,
		func() lineclassifier.Settings { return lineclassifier.Settings{} },
	))
	if got := h.classifyLine(context.Background(), "claude", "claude-x", body); got != "claude-x" {
		t.Fatalf("disabled classifier should pass through, got %q", got)
	}
}

// TestHandler_ClassifyLine_FallbackToUnprefixedModel guards the partial-migration
// case: the classifier is on, but the line's prefixed models have no account
// while the unprefixed model does (e.g. a main account not yet tagged with a
// line prefix). The request must fall back to the original model, not fail.
func TestHandler_ClassifyLine_FallbackToUnprefixedModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "build"}}},
		})
	}))
	defer srv.Close()

	h := &BaseAPIHandler{}
	h.SetLineRouter(lineclassifier.RouterFromConfig(
		[]string{"build", "write", "misc"}, "misc", 200, 2000, 60,
		func() lineclassifier.Settings { return lineclassifier.Settings{URL: srv.URL, Model: "cheap"} },
	))
	body := []byte(`{"model":"claude-opus","messages":[{"role":"user","content":"fix this bug"}]}`)

	// Only the UNPREFIXED model is served -> fall back to it.
	registry.GetGlobalRegistry().RegisterClient("t-unprefixed", "claude",
		[]*registry.ModelInfo{{ID: "claude-opus"}})
	defer registry.GetGlobalRegistry().UnregisterClient("t-unprefixed")
	if got := h.classifyLine(context.Background(), "claude", "claude-opus", body); got != "claude-opus" {
		t.Fatalf("no prefixed account: want fallback to unprefixed, got %q", got)
	}

	// Once the prefixed model is served, the line wins.
	registry.GetGlobalRegistry().RegisterClient("t-prefixed", "claude",
		[]*registry.ModelInfo{{ID: "build/claude-opus"}})
	defer registry.GetGlobalRegistry().UnregisterClient("t-prefixed")
	if got := h.classifyLine(context.Background(), "claude", "claude-opus", body); got != "build/claude-opus" {
		t.Fatalf("prefixed account present: want build/claude-opus, got %q", got)
	}
}
