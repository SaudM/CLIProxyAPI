package helps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ClaudeCodeHelloUserAgent is the User-Agent the native Claude Code binary's
// connectivity probe carries: Bun's default fetch identity for the Bun release
// bundled with the advertised Claude Code versions (2.1.273 / 2.1.274 ship Bun
// 1.4.3, captured 2026-09-18).
const ClaudeCodeHelloUserAgent = "Bun/1.4.3"

// claudeCodeHelloPath is probed with HEAD at every Claude Code start against the
// configured base URL, before any authenticated request.
const claudeCodeHelloPath = "/api/hello"

// claudeCodeHelloHeaderOrder is the wire order of the native probe's headers.
var claudeCodeHelloHeaderOrder = []string{
	"Connection",
	"User-Agent",
	"Accept",
	"Host",
	"Accept-Encoding",
}

var bunUserAgentPattern = regexp.MustCompile(`^Bun/\d+\.\d+\.\d+$`)

// IsClaudeCodeHelloUserAgent reports whether userAgent is the Bun fetch identity
// the native Claude Code binary uses for its startup probe.
func IsClaudeCodeHelloUserAgent(userAgent string) bool {
	return bunUserAgentPattern.MatchString(strings.TrimSpace(userAgent))
}

// ForwardClaudeCodeHello replays Claude Code's startup probe (HEAD /api/hello)
// upstream through the credential's own transport and egress (its proxy, else
// globalProxyURL), so an account
// that serves cloaked requests also shows the unauthenticated probe a native
// client emits from the same address. It returns the upstream status code.
func ForwardClaudeCodeHello(ctx context.Context, globalProxyURL string, auth *cliproxyauth.Auth) (int, error) {
	if auth == nil {
		return 0, errors.New("claude hello: auth is nil")
	}
	proxyURL := strings.TrimSpace(auth.ProxyURL)
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(globalProxyURL)
	}
	return forwardClaudeCodeHello(ctx, cachedClaudeCodeRoundTripper(proxyURL, auth), claudeCodeHelloUpstreamHost)
}

const claudeCodeHelloUpstreamHost = "api.anthropic.com"

func forwardClaudeCodeHello(ctx context.Context, roundTripper http.RoundTripper, host string) (int, error) {
	if roundTripper == nil {
		return 0, errors.New("claude hello: no transport")
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+claudeCodeHelloPath, nil)
	if errRequest != nil {
		return 0, fmt.Errorf("claude hello: build request: %w", errRequest)
	}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", ClaudeCodeHelloUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, errRoundTrip := roundTripper.RoundTrip(req)
	if errRoundTrip != nil {
		return 0, fmt.Errorf("claude hello: upstream: %w", errRoundTrip)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		return resp.StatusCode, fmt.Errorf("claude hello: close upstream body: %w", errClose)
	}
	return resp.StatusCode, nil
}
