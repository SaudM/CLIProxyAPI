package claude

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// claudeHelloMinInterval bounds how often one credential replays the startup
// probe upstream. The route is unauthenticated (the native client sends the
// probe without credentials), so this keeps an outside caller from turning an
// account's egress into a beacon.
const claudeHelloMinInterval = 30 * time.Second

// claudeHelloForwarder is swapped by tests.
var claudeHelloForwarder = helps.ForwardClaudeCodeHello

type claudeHelloState struct {
	mu        sync.Mutex
	lastProbe map[string]time.Time
	cursor    atomic.Uint64
	now       func() time.Time
}

var helloState = &claudeHelloState{lastProbe: make(map[string]time.Time), now: time.Now}

// ClaudeHello answers Claude Code's startup connectivity probe (HEAD /api/hello).
// A native probe is replayed upstream through one Claude OAuth credential's own
// transport and egress, chosen round-robin, so every account periodically shows
// the unauthenticated probe a real client emits before its first request. Other
// callers just get 200.
func (h *ClaudeCodeAPIHandler) ClaudeHello(c *gin.Context) {
	if !helps.IsClaudeCodeHelloUserAgent(c.GetHeader("User-Agent")) || h == nil || h.BaseAPIHandler == nil || h.AuthManager == nil {
		c.Status(http.StatusOK)
		return
	}
	auth := helloState.pick(claudeHelloCandidates(h.AuthManager.List()))
	if auth == nil {
		c.Status(http.StatusOK)
		return
	}
	globalProxy := ""
	if h.Cfg != nil {
		globalProxy = h.Cfg.ProxyURL
	}
	status, errForward := claudeHelloForwarder(c.Request.Context(), globalProxy, auth)
	if errForward != nil {
		log.WithError(errForward).Debugf("claude hello: probe via %s failed", auth.ID)
		c.Status(http.StatusOK)
		return
	}
	c.Status(status)
}

// claudeHelloCandidates keeps the Claude OAuth credentials that could serve a
// cloaked request right now, in a stable order.
func claudeHelloCandidates(auths []*coreauth.Auth) []*coreauth.Auth {
	out := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil || auth.Disabled || auth.Unavailable || !strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
			continue
		}
		if token, _ := auth.Metadata["access_token"].(string); strings.TrimSpace(token) == "" {
			continue
		}
		out = append(out, auth)
	}
	return out
}

// pick returns the next credential in round-robin order that has not probed
// within claudeHelloMinInterval, or nil when every candidate is throttled.
func (s *claudeHelloState) pick(candidates []*coreauth.Auth) *coreauth.Auth {
	if len(candidates) == 0 {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	start := int(s.cursor.Add(1)-1) % len(candidates)
	for offset := 0; offset < len(candidates); offset++ {
		auth := candidates[(start+offset)%len(candidates)]
		if last, ok := s.lastProbe[auth.ID]; ok && now.Sub(last) < claudeHelloMinInterval {
			continue
		}
		s.lastProbe[auth.ID] = now
		return auth
	}
	return nil
}
