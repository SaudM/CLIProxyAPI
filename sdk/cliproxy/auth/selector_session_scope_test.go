package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	scopeSessionOne   = "11111111-1111-1111-1111-111111111111"
	scopeSessionTwo   = "22222222-2222-2222-2222-222222222222"
	scopeSessionThree = "33333333-3333-3333-3333-333333333333"
)

func scopeAuths() []*Auth {
	return []*Auth{
		{ID: "acct-A", Provider: "claude", Status: StatusActive},
		{ID: "acct-B", Provider: "claude", Status: StatusActive},
		{ID: "acct-C", Provider: "claude", Status: StatusActive},
	}
}

// scopePick routes one Claude Code request (session id, optional agent id) and reports the
// chosen credential and whether the selector marked the pick as an existing binding.
func scopePick(t *testing.T, sel *SessionAffinitySelector, auths []*Auth, session, model, agent string) (string, bool) {
	t.Helper()
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", session)
	if agent != "" {
		headers.Set("X-Claude-Code-Agent-Id", agent)
	}
	opts := cliproxyexecutor.Options{Headers: headers, Metadata: map[string]any{}}
	auth, err := sel.Pick(context.Background(), "claude", model, opts, auths)
	if err != nil || auth == nil {
		t.Fatalf("Pick(%s, %s) = %v, %v", session, model, auth, err)
	}
	bound, _ := opts.Metadata[cliproxyexecutor.SessionAffinityBoundMetadataKey].(bool)
	return auth.ID, bound
}

func TestSessionAffinitySelector_SessionScopeKeepsEveryModelOnOneCredential(t *testing.T) {
	sel := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{TTL: time.Hour})
	auths := scopeAuths()
	home, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", "")
	if bound {
		t.Fatal("first pick of a session reported an existing binding")
	}
	// Advance the per-model round-robin for the helper model with unrelated sessions so a
	// per-model binding would visibly land elsewhere.
	scopePick(t, sel, auths, scopeSessionTwo, "claude-haiku-4-5-20251001", "")
	scopePick(t, sel, auths, scopeSessionThree, "claude-haiku-4-5-20251001", "")
	scopePick(t, sel, auths, scopeSessionTwo, "claude-sonnet-5", "")

	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-haiku-4-5-20251001", ""); got != home || !bound {
		t.Fatalf("helper model pick = %s (bound=%v), want the session's credential %s", got, bound, home)
	}
	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-sonnet-5", "agent-7"); got != home || !bound {
		t.Fatalf("subagent pick = %s (bound=%v), want the parent's credential %s", got, bound, home)
	}
	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", ""); got != home || !bound {
		t.Fatalf("main model pick after helpers = %s (bound=%v), want %s", got, bound, home)
	}
}

func TestSessionAffinitySelector_ModelScopeKeepsLegacyPerModelBindings(t *testing.T) {
	modelScoped := true
	sel := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{TTL: time.Hour, ModelScoped: &modelScoped})
	auths := scopeAuths()
	home, _ := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", "")
	scopePick(t, sel, auths, scopeSessionTwo, "claude-haiku-4-5-20251001", "")
	scopePick(t, sel, auths, scopeSessionThree, "claude-haiku-4-5-20251001", "")
	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-haiku-4-5-20251001", ""); got == home || bound {
		t.Fatalf("model scope: helper pick = %s (bound=%v), want a fresh per-model binding away from %s", got, bound, home)
	}
}

func TestSessionAffinitySelector_SubagentAffinityOffIgnoresParentHome(t *testing.T) {
	off := false
	sel := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{TTL: time.Hour, SubagentAffinity: &off})
	auths := scopeAuths()
	home, _ := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", "")
	// Move the sonnet round-robin off the parent's credential first.
	scopePick(t, sel, auths, scopeSessionTwo, "claude-sonnet-5", "")
	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-sonnet-5", "agent-7"); got == home || bound {
		t.Fatalf("subagent with affinity off = %s (bound=%v), want distribution away from %s", got, bound, home)
	}
	// The parent's own binding is untouched by the child.
	if got, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", ""); got != home || !bound {
		t.Fatalf("parent after child = %s (bound=%v), want %s", got, bound, home)
	}
}

func TestSessionAffinitySelector_SessionScopeFailureReleasesWholeSession(t *testing.T) {
	sel := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{TTL: time.Hour})
	auths := scopeAuths()
	home, _ := scopePick(t, sel, auths, scopeSessionOne, "claude-opus-5", "")
	if got, _ := scopePick(t, sel, auths, scopeSessionOne, "claude-haiku-4-5-20251001", ""); got != home {
		t.Fatalf("helper pick = %s, want %s", got, home)
	}
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", scopeSessionOne)
	sel.OnResult(Result{
		Provider: "claude",
		Model:    "claude-opus-5",
		AuthID:   home,
		Success:  false,
		Error:    &Error{Code: "upstream_error", Message: "boom", HTTPStatus: 500},
		Options:  cliproxyexecutor.Options{Headers: headers, Metadata: map[string]any{}},
	})
	// Every model of the session starts over: no binding survives the failed credential.
	if _, bound := scopePick(t, sel, auths, scopeSessionOne, "claude-haiku-4-5-20251001", ""); bound {
		t.Fatal("helper model still followed the session home after the credential failed")
	}
}
