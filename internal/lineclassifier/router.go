package lineclassifier

import (
	"context"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Router is the single entry point the request pipeline uses. It holds the
// session->line cache and a Classifier, and reads live Settings through a
// getter so the management API can change url/key/model at runtime.
type Router struct {
	cfg        Config
	getSetting func() Settings
	classifier *Classifier

	mu    sync.Mutex
	cache map[string]entry
}

// Config is the fixed part of line routing (not runtime-editable).
type Config struct {
	Lines        []string
	DefaultLine  string
	SnippetChars int
	Timeout      time.Duration
	TTL          time.Duration
}

type entry struct {
	line     string
	expireAt time.Time
}

// NewRouter builds a Router. getSetting must return the current classifier
// Settings each call (so admin edits take effect immediately).
func NewRouter(cfg Config, getSetting func() Settings) *Router {
	r := &Router{
		cfg:        cfg,
		getSetting: getSetting,
		classifier: New(cfg.Lines, cfg.DefaultLine, cfg.SnippetChars, cfg.Timeout),
		cache:      make(map[string]entry),
	}
	go r.janitor()
	return r
}

// Active reports whether line routing should touch requests at all. When the
// classifier is not configured, the router stays completely out of the way
// (returns the model unchanged in Route).
func (r *Router) Active() bool {
	return r != nil && len(r.cfg.Lines) > 0 && r.getSetting().Enabled()
}

// Route decides the line for a request and returns the model name rewritten to
// that line's prefix. session may be empty (then it is never cached). On any
// doubt it returns the model pointed at the default line. If the classifier is
// disabled it returns the model UNCHANGED so existing behaviour is preserved.
func (r *Router) Route(ctx context.Context, session, model string, body []byte) (string, Decision) {
	if !r.Active() {
		return model, Decision{}
	}
	if line, ok := r.getCached(session); ok {
		return ApplyLinePrefix(model, line, r.cfg.Lines), Decision{Line: line}
	}
	snippet := ExtractSnippet(body, r.cfg.SnippetChars)
	line, ok := r.classifier.Classify(ctx, r.getSetting(), snippet)
	d := Decision{Line: line, Classified: true}
	if !ok {
		line = r.cfg.DefaultLine
		d.Line = line
		d.Defaulted = true
	}
	r.putCached(session, line)
	log.WithFields(log.Fields{
		"session":   session,
		"line":      d.Line,
		"defaulted": d.Defaulted,
		"model":     model,
	}).Info("line classifier: new session classified")
	return ApplyLinePrefix(model, line, r.cfg.Lines), d
}

// Decision explains what the router did, so callers can log new classifications
// (and why a default was used) without re-deriving it.
type Decision struct {
	Line       string // the business line chosen
	Classified bool   // a fresh classification happened (not a cached binding)
	Defaulted  bool   // the classifier was undecided/unavailable; default line used
}

func (r *Router) getCached(session string) (string, bool) {
	if strings.TrimSpace(session) == "" {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[session]
	if !ok || time.Now().After(e.expireAt) {
		return "", false
	}
	return e.line, true
}

func (r *Router) putCached(session, line string) {
	if strings.TrimSpace(session) == "" {
		return
	}
	ttl := r.cfg.TTL
	if ttl <= 0 {
		ttl = 4 * time.Hour
	}
	r.mu.Lock()
	r.cache[session] = entry{line: line, expireAt: time.Now().Add(ttl)}
	r.mu.Unlock()
}

func (r *Router) janitor() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		now := time.Now()
		r.mu.Lock()
		for k, e := range r.cache {
			if now.After(e.expireAt) {
				delete(r.cache, k)
			}
		}
		r.mu.Unlock()
	}
}
