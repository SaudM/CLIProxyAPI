package executor

import "testing"

// Anthropic-Beta lists captured from the native Claude Code 2.1.281 binary on
// 2026-09-24 (sdk-cli entrypoint, API-key auth, so no oauth/extended-cache-ttl
// entries). Each body keeps only the fields the assembly reads. That client
// also sent fallback-credit on Opus 5 and Fable requests without any fallback
// field; the beta is account-dependent, so those rows pass it as requested.
func TestClaudeCodeCLIBetas_MatchesClaudeCode2_1_281Captures(t *testing.T) {
	t.Parallel()

	const base = "claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05"
	cases := []struct {
		name      string
		body      string
		requested map[string]bool
		want      string
	}{
		{
			name: "opus-4-8 adaptive thinking",
			body: `{"model":"claude-opus-4-8","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			want: base + ",mid-conversation-system-2026-04-07,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24",
		},
		{
			name: "opus-4-8 thinking disabled keeps effort and drops redact",
			body: `{"model":"claude-opus-4-8","thinking":{"type":"disabled"},"output_config":{"effort":"max"}}`,
			want: base + ",mid-conversation-system-2026-04-07,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24",
		},
		{
			name: "opus-4-8 cli entrypoint without thinking.display redacts",
			body: `{"model":"claude-opus-4-8","thinking":{"type":"enabled","budget_tokens":31999}}`,
			want: "claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24",
		},
		{
			name:      "fable-5-1 per-turn control and fallback credit",
			body:      `{"model":"claude-fable-5-1","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			requested: map[string]bool{claudeFallbackCreditBeta: true},
			want:      base + ",mid-conversation-system-2026-04-07,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24,fallback-credit-2026-06-01",
		},
		{
			name:      "opus-5-5 per-turn control and fallback credit",
			body:      `{"model":"claude-opus-5-5","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			requested: map[string]bool{claudeFallbackCreditBeta: true},
			want:      base + ",mid-conversation-system-2026-04-07,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24,fallback-credit-2026-06-01",
		},
		{
			name:      "opus-5 fallback credit without per-turn control",
			body:      `{"model":"claude-opus-5","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			requested: map[string]bool{claudeFallbackCreditBeta: true},
			want:      base + ",mid-conversation-system-2026-04-07,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24,fallback-credit-2026-06-01",
		},
		{
			name:      "opus-5 1m context",
			body:      `{"model":"claude-opus-5","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			requested: map[string]bool{"context-1m-2025-08-07": true, claudeFallbackCreditBeta: true},
			want:      "claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24,fallback-credit-2026-06-01",
		},
		{
			name: "sonnet-5 has no tool-changes",
			body: `{"model":"claude-sonnet-5","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			want: base + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "sonnet-5 thinking disabled keeps effort",
			body: `{"model":"claude-sonnet-5","thinking":{"type":"disabled"},"output_config":{"effort":"max"}}`,
			want: base + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "opus-4-6 legacy with effort",
			body: `{"model":"claude-opus-4-6","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			want: base + ",effort-2025-11-24",
		},
		{
			name: "sonnet-4-6 legacy with effort",
			body: `{"model":"claude-sonnet-4-6","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			want: base + ",effort-2025-11-24",
		},
		{
			name: "opus-4-5 legacy with effort",
			body: `{"model":"claude-opus-4-5-20251101","thinking":{"type":"adaptive","display":"omitted"},"output_config":{"effort":"max"}}`,
			want: base + ",effort-2025-11-24",
		},
		{
			name: "sonnet-4-5 has no effort",
			body: `{"model":"claude-sonnet-4-5-20250929","thinking":{"type":"enabled","budget_tokens":31999,"display":"omitted"}}`,
			want: base,
		},
		{
			name: "sonnet-4 has no effort",
			body: `{"model":"claude-sonnet-4-20250514","thinking":{"type":"enabled","budget_tokens":31999,"display":"omitted"}}`,
			want: base,
		},
		{
			name: "haiku-4-5 appends claude-code last",
			body: `{"model":"claude-haiku-4-5","thinking":{"type":"enabled","budget_tokens":31999,"display":"omitted"}}`,
			want: "interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219",
		},
		{
			name: "haiku-4-5 thinking disabled",
			body: `{"model":"claude-haiku-4-5-20251001","thinking":{"type":"disabled"}}`,
			want: "interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219",
		},
		{
			name: "3-5-haiku predates thinking",
			body: `{"model":"claude-3-5-haiku-20241022"}`,
			want: "prompt-caching-scope-2026-01-05,claude-code-20250219",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := claudeCodeCLIBetas([]byte(tc.body), tc.requested, false); got != tc.want {
				t.Fatalf("claudeCodeCLIBetas() =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

func TestClaudeModelVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		model        string
		family       string
		major, minor int
		ok           bool
	}{
		{"claude-opus-4-5-20251101", "opus", 4, 5, true},
		{"claude-3-5-haiku-20241022", "haiku", 3, 5, true},
		{"claude-3-7-sonnet-latest", "sonnet", 3, 7, true},
		{"claude-sonnet-5", "sonnet", 5, 0, true},
		{"claude-fable-5-1[1m]", "fable", 5, 1, true},
		{"anthropic/claude-opus-5-5", "opus", 5, 5, true},
		{"gpt-5", "gpt", 5, 0, true},
		{"claude", "claude", 0, 0, false},
	}
	for _, tc := range cases {
		family, major, minor, ok := claudeModelVersion(tc.model)
		if family != tc.family || major != tc.major || minor != tc.minor || ok != tc.ok {
			t.Errorf("claudeModelVersion(%q) = %s %d.%d %v, want %s %d.%d %v", tc.model, family, major, minor, ok, tc.family, tc.major, tc.minor, tc.ok)
		}
	}
}
