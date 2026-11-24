package lineclassifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestRouter(url, model string) (*Router, *int) {
	calls := 0
	get := func() Settings { return Settings{URL: url, Model: model, Key: ""} }
	r := NewRouter(Config{
		Lines:        []string{"build", "write", "misc"},
		DefaultLine:  "misc",
		SnippetChars: 200,
		Timeout:      2 * time.Second,
		TTL:          time.Minute,
	}, get)
	return r, &calls
}

func TestRoute_DisabledPassesThrough(t *testing.T) {
	r, _ := newTestRouter("", "") // not configured
	if got, _ := r.Route(context.Background(), "s1", "claude-x", nil); got != "claude-x" {
		t.Fatalf("disabled router must not touch model, got %q", got)
	}
	if r.Active() {
		t.Fatal("router should be inactive when unconfigured")
	}
}

func TestRoute_ClassifiesAndSticks(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "write"}}},
		})
	}))
	defer srv.Close()

	r, _ := newTestRouter(srv.URL, "cheap")
	body := []byte(`{"model":"claude-x","messages":[{"role":"user","content":"draft a launch tweet"}]}`)

	got, d := r.Route(context.Background(), "sessA", "claude-x", body)
	if got != "write/claude-x" || d.Line != "write" || !d.Classified {
		t.Fatalf("want write/claude-x, got %q", got)
	}
	// Same session reuses the decision: classifier called exactly once.
	if _, d2 := r.Route(context.Background(), "sessA", "claude-x", body); d2.Classified {
		t.Fatal("cached session must not reclassify")
	}
	if calls != 1 {
		t.Fatalf("stickiness broken: classifier called %d times", calls)
	}
}

func TestRoute_DefaultWhenClassifierDown(t *testing.T) {
	r, _ := newTestRouter("http://127.0.0.1:1", "cheap") // nothing listening
	body := []byte(`{"model":"claude-x","messages":[{"role":"user","content":"deploy it"}]}`)
	got, d := r.Route(context.Background(), "sessB", "claude-x", body)
	if got != "misc/claude-x" || !d.Defaulted {
		t.Fatalf("down classifier must fall to default line, got %q", got)
	}
}

func TestRoute_UnknownLabelFallsToDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "backend"}}}, // not in table
		})
	}))
	defer srv.Close()
	r, _ := newTestRouter(srv.URL, "cheap")
	body := []byte(`{"model":"claude-x","messages":[{"role":"user","content":"hi"}]}`)
	if got, d := r.Route(context.Background(), "sessC", "claude-x", body); got != "misc/claude-x" || !d.Defaulted {
		t.Fatalf("invented label must be rejected -> default, got %q", got)
	}
}

func TestApplyLinePrefix_Idempotent(t *testing.T) {
	lines := []string{"build", "write", "misc"}
	if got := ApplyLinePrefix("claude-x", "build", lines); got != "build/claude-x" {
		t.Fatalf("bare: %q", got)
	}
	if got := ApplyLinePrefix("write/claude-x", "build", lines); got != "build/claude-x" {
		t.Fatalf("known-prefix re-point: %q", got)
	}
	if got := ApplyLinePrefix("vendor/x", "build", lines); got != "build/vendor/x" {
		t.Fatalf("unknown prefix kept: %q", got)
	}
}
