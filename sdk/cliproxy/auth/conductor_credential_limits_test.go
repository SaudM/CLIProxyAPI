package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// limitRecordingExecutor records which auth served each call and returns a
// caller-controlled stream channel so tests can hold a stream open.
type limitRecordingExecutor struct {
	id string

	mu      sync.Mutex
	authIDs []string
	stream  chan cliproxyexecutor.StreamChunk
}

func (e *limitRecordingExecutor) Identifier() string { return e.id }

func (e *limitRecordingExecutor) record(auth *Auth) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.authIDs = append(e.authIDs, auth.ID)
}

func (e *limitRecordingExecutor) served() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.authIDs...)
}

func (e *limitRecordingExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth)
	return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
}

func (e *limitRecordingExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	e.mu.Lock()
	ch := e.stream
	e.mu.Unlock()
	if ch == nil {
		return successStreamResult(), nil
	}
	return &cliproxyexecutor.StreamResult{Headers: http.Header{}, Chunks: ch}, nil
}

func (e *limitRecordingExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *limitRecordingExecutor) CountTokens(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth)
	return cliproxyexecutor.Response{Payload: []byte(`{"input_tokens":1}`)}, nil
}

func (e *limitRecordingExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func registerLimitAuths(t *testing.T, m *Manager, model string, metadataByID map[string]map[string]any) []string {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	ids := make([]string, 0, len(metadataByID))
	priority := 100
	// Deterministic pick order: descending priority in sorted-ID order.
	for _, id := range sortedKeys(metadataByID) {
		ids = append(ids, id)
		auth := &Auth{
			ID:         id,
			Provider:   "codex",
			Status:     StatusActive,
			Attributes: map[string]string{"priority": itoa(priority)},
			Metadata:   metadataByID[id],
		}
		priority--
		reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		if _, err := m.Register(WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	t.Cleanup(func() {
		for _, id := range ids {
			reg.UnregisterClient(id)
		}
	})
	return ids
}

func sortedKeys(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func newLimitTestManager(t *testing.T, executor *limitRecordingExecutor) (*Manager, *fakeClock) {
	t.Helper()
	m := NewManager(nil, nil, nil)
	m.SetRetryConfig(0, 0, 0)
	clock := newFakeClock()
	m.limiter.now = clock.Now
	m.RegisterExecutor(executor)
	return m, clock
}

func TestExecute_SkipsCredentialOverConcurrencyLimit(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex"}
	m, _ := newLimitTestManager(t, executor)
	model := "limit-skip-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"max_concurrent": 1},
		"auth-b": nil,
	})

	// Hold auth-a's single slot so the next request must land on auth-b.
	lease, _, ok := m.limiter.tryAcquire("auth-a", "", m.effectiveCredentialLimits(&Auth{ID: "auth-a", Metadata: map[string]any{"max_concurrent": 1}}))
	if !ok {
		t.Fatalf("could not pre-hold auth-a slot")
	}
	defer lease.Release()

	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	served := executor.served()
	if len(served) != 1 || served[0] != "auth-b" {
		t.Fatalf("served = %v, want [auth-b]", served)
	}
	// auth-a's slot is still held by the test; auth-b's lease was released after Execute.
	if snap := m.limiter.snapshot("auth-b", credentialLimits{MaxConcurrent: 1}); snap.InFlight != 0 {
		t.Fatalf("auth-b inFlight after Execute = %d, want 0", snap.InFlight)
	}
}

func TestExecute_AllCredentialsOverLimitReturns429WithRetryAfter(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex"}
	m, clock := newLimitTestManager(t, executor)
	model := "limit-all-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"rpm": 1},
		"auth-b": {"rpm": 1},
	})

	// Exhaust both credentials' rpm budget.
	for _, id := range []string{"auth-a", "auth-b"} {
		lease, _, ok := m.limiter.tryAcquire(id, "", credentialLimits{RPM: 1})
		if !ok {
			t.Fatalf("pre-exhaust %s refused", id)
		}
		lease.Release()
	}
	clock.Advance(5 * time.Second)

	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err == nil {
		t.Fatalf("Execute succeeded with every credential over limit")
	}
	var limitErr *credentialLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error type = %T (%v), want *credentialLimitError", err, err)
	}
	if limitErr.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", limitErr.StatusCode())
	}
	var authErr *Error
	if !errors.As(err, &authErr) || authErr.Code != "credential_limit_exceeded" {
		t.Fatalf("inner error code = %v, want credential_limit_exceeded", authErr)
	}
	// Both were exhausted 5s ago in the same second, so recovery is 55s out.
	if got := SafeResponseHeaders(err).Get("Retry-After"); got != "55" {
		t.Fatalf("Retry-After = %q, want 55", got)
	}
	if served := executor.served(); len(served) != 0 {
		t.Fatalf("executor was invoked for %v while over limit", served)
	}
}

func TestExecute_LimitBlockedCredentialDrivesRetryWait(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex"}
	m, clock := newLimitTestManager(t, executor)
	m.SetRetryConfig(1, time.Minute, 0)
	model := "limit-wait-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"rpm": 1},
	})
	lease, _, ok := m.limiter.tryAcquire("auth-a", "", credentialLimits{RPM: 1})
	if !ok {
		t.Fatalf("pre-exhaust refused")
	}
	lease.Release()
	clock.Advance(20 * time.Second)

	// closestCooldownWait must report the limiter's recovery instant (40s) rather than
	// "retry now", otherwise the retry round would hot-loop on a limited credential.
	wait, found := m.closestCooldownWaitWithAttempted([]string{"codex"}, model, 0, authSelectionEligibility{}, "", 1, http.StatusTooManyRequests, nil)
	if !found {
		t.Fatalf("no cooldown wait found for limiter-blocked credential")
	}
	if wait < 39*time.Second || wait > 41*time.Second {
		t.Fatalf("wait = %v, want ~40s", wait)
	}
}

func TestExecuteStream_LeaseFollowsStreamLifetime(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex", stream: make(chan cliproxyexecutor.StreamChunk, 4)}
	m, _ := newLimitTestManager(t, executor)
	model := "limit-stream-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"max_concurrent": 1},
	})
	limits := credentialLimits{MaxConcurrent: 1}

	// First payload byte is required before ExecuteStream returns (bootstrap).
	executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("data: first\n\n")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	if snap := m.limiter.snapshot("auth-a", limits); snap.InFlight != 1 {
		t.Fatalf("inFlight while stream open = %d, want 1", snap.InFlight)
	}
	// A second request must be refused while the first stream is still open.
	if _, errSecond := m.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); errSecond == nil {
		t.Fatalf("second request admitted while the only slot is held by an open stream")
	}

	// Drain and close the upstream channel; the wrapper goroutine releases the lease on exit.
	close(executor.stream)
	for range result.Chunks {
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if snap := m.limiter.snapshot("auth-a", limits); snap.InFlight == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease not released after stream drained")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestExecuteStream_LeaseReleasedOnClientCancel(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex", stream: make(chan cliproxyexecutor.StreamChunk, 4)}
	m, _ := newLimitTestManager(t, executor)
	model := "limit-cancel-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"max_concurrent": 1},
	})
	limits := credentialLimits{MaxConcurrent: 1}

	executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("data: first\n\n")}
	ctx, cancel := context.WithCancel(context.Background())
	result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	// Push one more chunk so the forwarder is blocked on a downstream send nobody reads,
	// then cancel: the wrapper must exit via ctx.Done and release the lease.
	executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("data: second\n\n")}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if snap := m.limiter.snapshot("auth-a", limits); snap.InFlight == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease not released after client cancel")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = result
	close(executor.stream)
}

func TestExecuteCount_IgnoresCredentialLimits(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex"}
	m, _ := newLimitTestManager(t, executor)
	model := "limit-count-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{
		"auth-a": {"max_concurrent": 1, "rpm": 1},
	})
	lease, _, ok := m.limiter.tryAcquire("auth-a", "", credentialLimits{MaxConcurrent: 1, RPM: 1})
	if !ok {
		t.Fatalf("pre-hold refused")
	}
	defer lease.Release()

	if _, err := m.ExecuteCount(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("ExecuteCount blocked by credential limits: %v", err)
	}
	if served := executor.served(); len(served) != 1 || served[0] != "auth-a" {
		t.Fatalf("served = %v, want [auth-a]", served)
	}
}

func TestRemove_ClearsLimiterState(t *testing.T) {
	executor := &limitRecordingExecutor{id: "codex"}
	m, _ := newLimitTestManager(t, executor)
	model := "limit-remove-" + uuid.NewString()
	registerLimitAuths(t, m, model, map[string]map[string]any{"auth-a": {"rpm": 1}})
	lease, _, _ := m.limiter.tryAcquire("auth-a", "", credentialLimits{RPM: 1})
	lease.Release()
	m.Remove(context.Background(), "auth-a")
	m.limiter.mu.Lock()
	_, present := m.limiter.entries["auth-a"]
	m.limiter.mu.Unlock()
	if present {
		t.Fatalf("limiter entry survived auth removal")
	}
}
