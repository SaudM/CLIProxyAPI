package api

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/lineclassifier"
)

// installLineRouter wires the optional pre-routing line classifier into the
// request handlers. It is called once at startup. The router's fixed table
// (lines, default, ttl) is read now; the runtime-editable url/key/model are
// read live through liveClassifierSettings on every request, so changes made
// via the management API take effect without a restart or cache reset.
//
// When no lines are configured the router is nil and the feature stays off.
func (s *Server) installLineRouter() {
	if s == nil || s.handlers == nil {
		return
	}
	s.cfgMu.RLock()
	lc := s.cfg.Routing.LineClassifier
	s.cfgMu.RUnlock()

	router := lineclassifier.RouterFromConfig(
		lc.Lines, lc.DefaultLine, lc.SnippetChars, lc.TimeoutMs, lc.TTLMinutes,
		s.liveClassifierSettings,
	)
	s.handlers.SetLineRouter(router)
}

// liveClassifierSettings returns the current classifier endpoint/key/model from
// the live server config, so management-API edits are picked up immediately.
func (s *Server) liveClassifierSettings() lineclassifier.Settings {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	lc := s.cfg.Routing.LineClassifier
	return lineclassifier.Settings{URL: lc.URL, Key: lc.Key, Model: lc.Model}
}
