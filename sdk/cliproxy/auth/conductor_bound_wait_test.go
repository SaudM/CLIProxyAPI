package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const boundWaitSession = "44444444-4444-4444-4444-444444444444"

// boundWaitSetup binds one session to auth-a, then holds auth-a's single concurrency
// slot and replaces the wait with a stub that releases it, so the test observes whether
// the next request waits for auth-a or migrates to auth-b.
func boundWaitSetup(t *testing.T, maxRetryInterval time.Duration) (*Manager, *limitRecordingExecutor, string, func() cliproxyexecutor.Options, *[]time.Duration) {
	t.Helper()
	executor := &limitRecordingExecutor{id: "codex"}
	m, _ := newLimitTestManager(t, executor)
	m.SetRetryConfig(0, maxRetryInterval, 0)
	m.SetSelector(NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RoundRobinSelector{}, TTL: time.Hour}))
	model := "bound-wait-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"max_concurrent": 1},
		"auth-b": {"max_concurrent": 1},
	})
	opts := func() cliproxyexecutor.Options {
		headers := http.Header{}
		headers.Set("X-Claude-Code-Session-Id", boundWaitSession)
		return cliproxyexecutor.Options{Headers: headers}
	}
	if _, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts()); err != nil {
		t.Fatalf("binding request: %v", err)
	}
	if served := executor.served(); len(served) != 1 || served[0] != "auth-a" {
		t.Fatalf("binding request served by %v, want auth-a", served)
	}
	limits := m.effectiveCredentialLimits(&Auth{ID: "auth-a", Provider: "codex", Metadata: map[string]any{"max_concurrent": 1}})
	lease, _, ok := m.limiter.tryAcquire("auth-a", "", limits)
	if !ok {
		t.Fatal("could not pre-hold auth-a's slot")
	}
	t.Cleanup(lease.Release)
	waits := &[]time.Duration{}
	m.credentialWait = func(_ context.Context, wait time.Duration) error {
		*waits = append(*waits, wait)
		lease.Release()
		return nil
	}
	return m, executor, model, opts, waits
}

func TestExecute_WaitsForSessionBoundCredentialInsteadOfMigrating(t *testing.T) {
	m, executor, model, opts, waits := boundWaitSetup(t, 5*time.Second)
	if _, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts()); err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if served := executor.served(); len(served) != 2 || served[1] != "auth-a" {
		t.Fatalf("served = %v, want the bound credential auth-a again", served)
	}
	if len(*waits) != 1 || (*waits)[0] != credentialLimitConcurrencyRetry {
		t.Fatalf("waits = %v, want one %v wait", *waits, credentialLimitConcurrencyRetry)
	}
}

func TestExecuteStream_WaitsForSessionBoundCredential(t *testing.T) {
	m, executor, model, opts, waits := boundWaitSetup(t, 5*time.Second)
	result, err := m.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts())
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	for range result.Chunks {
	}
	if served := executor.served(); len(served) != 2 || served[1] != "auth-a" {
		t.Fatalf("served = %v, want the bound credential auth-a again", served)
	}
	if len(*waits) != 1 {
		t.Fatalf("waits = %v, want exactly one", *waits)
	}
}

func TestExecute_MigratesWhenNoRetryIntervalAllowsWaiting(t *testing.T) {
	m, executor, model, opts, waits := boundWaitSetup(t, 0)
	if _, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts()); err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if served := executor.served(); len(served) != 2 || served[1] != "auth-b" {
		t.Fatalf("served = %v, want legacy migration to auth-b", served)
	}
	if len(*waits) != 0 {
		t.Fatalf("waits = %v, want none", *waits)
	}
}

func TestExecute_BoundWaitIsCappedByRetryInterval(t *testing.T) {
	m, executor, model, opts, waits := boundWaitSetup(t, 5*time.Second)
	// A refusal that would need longer than the cap (rpm window) is not waited for.
	m.credentialWait = func(_ context.Context, wait time.Duration) error {
		*waits = append(*waits, wait)
		return nil
	}
	auth, _ := m.GetByID("auth-a")
	auth.Metadata["rpm"] = 1
	if _, err := m.Update(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("update: %v", err)
	}
	// The binding request already consumed auth-a's single rpm slot; recovery is ~60s > 5s cap.
	if _, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts()); err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if served := executor.served(); len(served) != 2 || served[1] != "auth-b" {
		t.Fatalf("served = %v, want auth-b when the wait would exceed max-retry-interval", served)
	}
	if len(*waits) != 0 {
		t.Fatalf("waits = %v, want none", *waits)
	}
}
