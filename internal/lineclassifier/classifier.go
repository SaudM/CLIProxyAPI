// Package lineclassifier routes a request to a business "line" (e.g. build /
// write / misc) before credential selection, by asking a cheap external model
// to pick ONE label from a fixed table. The chosen line is turned into a model
// name prefix (line/model) so the gateway's existing force-model-prefix routing
// sends it to that line's accounts.
//
// Design rules (kept deliberately strict):
//   - The table of lines is FIXED by configuration; the classifier may only pick
//     an existing line, never invent one (an invented label maps to no account).
//   - Only NEW sessions are classified; a session reuses its first decision, so a
//     conversation never flips lines mid-way and the classifier is called once.
//   - Any doubt (disabled, timeout, error, unknown label, empty body) falls back
//     to the default line and never blocks the request.
//   - It holds no upstream credentials and only contacts the configured endpoint.
package lineclassifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Settings is the runtime-adjustable classifier configuration. When URL or Model
// is empty, classification is OFF and every request goes to the default line.
type Settings struct {
	URL   string `yaml:"url,omitempty" json:"url,omitempty"`
	Key   string `yaml:"key,omitempty" json:"key,omitempty"`
	Model string `yaml:"model,omitempty" json:"model,omitempty"`
}

// Enabled reports whether classification should run.
func (s Settings) Enabled() bool {
	return strings.TrimSpace(s.URL) != "" && strings.TrimSpace(s.Model) != ""
}

// Classifier calls an OpenAI-compatible chat endpoint and maps the reply to one
// of the fixed lines. It is safe for concurrent use.
type Classifier struct {
	lines       []string
	defaultLine string
	snippetN    int
	timeout     time.Duration
	client      *http.Client
}

// New builds a Classifier. lines is the fixed table; defaultLine must be one of
// them; snippetChars bounds how much of the prompt is sent for classification.
func New(lines []string, defaultLine string, snippetChars int, timeout time.Duration) *Classifier {
	if snippetChars <= 0 {
		snippetChars = 200
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &Classifier{
		lines:       lines,
		defaultLine: defaultLine,
		snippetN:    snippetChars,
		timeout:     timeout,
		client:      &http.Client{Timeout: timeout},
	}
}

// Classify returns a line from the fixed table, or ("", false) on any doubt so
// the caller can fall back to the default line.
func (c *Classifier) Classify(ctx context.Context, s Settings, snippet string) (string, bool) {
	if !s.Enabled() || snippet == "" {
		return "", false
	}
	reqBody, _ := json.Marshal(map[string]any{
		"model":       s.Model,
		"temperature": 0,
		"max_tokens":  8,
		"messages": []map[string]string{
			{"role": "user", "content": c.prompt(snippet)},
		},
	})
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	url := strings.TrimRight(strings.TrimSpace(s.URL), "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	if k := strings.TrimSpace(s.Key); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	return c.parse(resp.Body)
}

func (c *Classifier) prompt(snippet string) string {
	return fmt.Sprintf(
		"You route a developer's request to exactly one work line.\n"+
			"Allowed lines (choose EXACTLY ONE label, nothing else):\n%s\n\n"+
			"Rules: reply with only the label, lowercase, no punctuation, no explanation. "+
			"If unsure, reply: %s\n\nRequest sample:\n%s",
		lineMenu(c.lines), c.defaultLine, snippet)
}

func (c *Classifier) parse(r io.Reader) (string, bool) {
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(r).Decode(&out); err != nil || len(out.Choices) == 0 {
		return "", false
	}
	label := normalizeLabel(out.Choices[0].Message.Content)
	if containsStr(c.lines, label) {
		return label, true
	}
	return "", false
}
