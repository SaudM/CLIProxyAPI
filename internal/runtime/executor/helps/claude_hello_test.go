package helps

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type helloRoundTripper struct {
	seen *http.Request
}

func (rt *helloRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.seen = req
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestForwardClaudeCodeHelloReplaysNativeProbe(t *testing.T) {
	t.Parallel()
	rt := &helloRoundTripper{}
	status, errForward := forwardClaudeCodeHello(context.Background(), rt, "api.anthropic.com")
	if errForward != nil || status != http.StatusOK {
		t.Fatalf("forward = (%d, %v), want (200, nil)", status, errForward)
	}
	if rt.seen == nil || rt.seen.Method != http.MethodHead || rt.seen.URL.String() != "https://api.anthropic.com/api/hello" {
		t.Fatalf("upstream request = %+v, want HEAD https://api.anthropic.com/api/hello", rt.seen)
	}
	for name, want := range map[string]string{
		"Connection":      "keep-alive",
		"User-Agent":      ClaudeCodeHelloUserAgent,
		"Accept":          "*/*",
		"Accept-Encoding": "gzip, deflate, br, zstd",
	} {
		if got := rt.seen.Header.Get(name); got != want {
			t.Fatalf("header %s = %q, want %q", name, got, want)
		}
	}
	if _, has := rt.seen.Header["Authorization"]; has {
		t.Fatal("the native probe is unauthenticated; no Authorization header may be sent")
	}
	if got := claudeCodeRequestHeaderOrder(http.MethodHead, "/api/hello"); len(got) != 5 || got[0] != "Connection" || got[1] != "User-Agent" || got[4] != "Accept-Encoding" {
		t.Fatalf("hello header order = %v", got)
	}
	if !IsClaudeCodeHelloUserAgent("Bun/1.4.3") || IsClaudeCodeHelloUserAgent("claude-cli/2.1.274 (external, cli)") || IsClaudeCodeHelloUserAgent("Bun/1.4") {
		t.Fatal("IsClaudeCodeHelloUserAgent misclassifies user agents")
	}
}
