package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigBytesCredentialLimits(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
credential-limits:
  rpm: 30
  tpm: 100000
  max-concurrent: 4
  providers:
    " Claude ":
      rpm: 60
    codex:
      max-concurrent: 2
claude-api-key:
  - api-key: "claude-one"
    rpm: 10
    max-concurrent: 0
codex-api-key:
  - api-key: "codex-one"
    base-url: "https://codex.example.com"
    tpm: 5000
gemini-api-key:
  - api-key: "gemini-one"
openai-compatibility:
  - name: "compat"
    base-url: "https://compat.example.com/v1"
    rpm: 7
    api-key-entries:
      - api-key: "compat-key"
vertex-api-key:
  - api-key: "vertex-one"
    max-concurrent: 3
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	limits := cfg.CredentialLimits
	if limits.RPM != 30 || limits.TPM != 100000 || limits.MaxConcurrent != 4 {
		t.Fatalf("global limits = %+v", limits)
	}
	if _, ok := limits.Providers["claude"]; !ok {
		t.Fatalf("provider key not normalized: %v", limits.Providers)
	}
	if rpm, tpm, mc := limits.Resolve("claude"); rpm != 60 || tpm != 100000 || mc != 4 {
		t.Fatalf("Resolve(claude) = (%d, %d, %d), want (60, 100000, 4)", rpm, tpm, mc)
	}
	if rpm, _, mc := limits.Resolve("CODEX"); rpm != 30 || mc != 2 {
		t.Fatalf("Resolve(CODEX) = (%d, _, %d), want (30, _, 2)", rpm, mc)
	}
	if rpm, tpm, mc := limits.Resolve("gemini"); rpm != 30 || tpm != 100000 || mc != 4 {
		t.Fatalf("Resolve(gemini) = (%d, %d, %d), want globals", rpm, tpm, mc)
	}
	// First matching key wins.
	if rpm, _, _ := limits.Resolve("unknown", "claude", "codex"); rpm != 60 {
		t.Fatalf("Resolve first-match rpm = %d, want 60", rpm)
	}

	claude := cfg.ClaudeKey[0]
	if claude.RPM == nil || *claude.RPM != 10 || claude.MaxConcurrent == nil || *claude.MaxConcurrent != 0 || claude.TPM != nil {
		t.Fatalf("claude overrides = rpm:%v tpm:%v mc:%v", claude.RPM, claude.TPM, claude.MaxConcurrent)
	}
	if cfg.CodexKey[0].TPM == nil || *cfg.CodexKey[0].TPM != 5000 {
		t.Fatalf("codex tpm = %v, want 5000", cfg.CodexKey[0].TPM)
	}
	if cfg.GeminiKey[0].RPM != nil || cfg.GeminiKey[0].TPM != nil || cfg.GeminiKey[0].MaxConcurrent != nil {
		t.Fatalf("gemini overrides should be unset")
	}
	if cfg.OpenAICompatibility[0].RPM == nil || *cfg.OpenAICompatibility[0].RPM != 7 {
		t.Fatalf("openai-compatibility rpm = %v, want 7", cfg.OpenAICompatibility[0].RPM)
	}
	if cfg.VertexCompatAPIKey[0].MaxConcurrent == nil || *cfg.VertexCompatAPIKey[0].MaxConcurrent != 3 {
		t.Fatalf("vertex max-concurrent = %v, want 3", cfg.VertexCompatAPIKey[0].MaxConcurrent)
	}
}

func TestCredentialLimitsValidationRejectsNegatives(t *testing.T) {
	cases := map[string]string{
		"global":       "credential-limits:\n  rpm: -1\n",
		"provider":     "credential-limits:\n  providers:\n    claude:\n      tpm: -5\n",
		"claude-key":   "claude-api-key:\n  - api-key: \"k\"\n    max-concurrent: -2\n",
		"codex-key":    "codex-api-key:\n  - api-key: \"k\"\n    base-url: \"https://x\"\n    rpm: -1\n",
		"gemini-key":   "gemini-api-key:\n  - api-key: \"k\"\n    tpm: -1\n",
		"compat":       "openai-compatibility:\n  - name: c\n    base-url: \"https://x/v1\"\n    rpm: -3\n",
		"vertex":       "vertex-api-key:\n  - api-key: \"k\"\n    max-concurrent: -1\n",
		"interactions": "interactions-api-key:\n  - api-key: \"k\"\n    rpm: -1\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfigBytes([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "must not be negative") {
				t.Fatalf("ParseConfigBytes error = %v, want negative-limit validation error", err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if errWrite := os.WriteFile(path, []byte(yaml), 0o600); errWrite != nil {
				t.Fatalf("write config: %v", errWrite)
			}
			if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "must not be negative") {
				t.Fatalf("LoadConfig error = %v, want negative-limit validation error", err)
			}
		})
	}
}

func TestCredentialLimitsZeroValueIsUnlimited(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("request-retry: 1\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if rpm, tpm, mc := cfg.CredentialLimits.Resolve("claude"); rpm != 0 || tpm != 0 || mc != 0 {
		t.Fatalf("default limits = (%d, %d, %d), want all zero", rpm, tpm, mc)
	}
	if err := cfg.CredentialLimits.Validate(); err != nil {
		t.Fatalf("zero-value Validate() = %v", err)
	}
}
