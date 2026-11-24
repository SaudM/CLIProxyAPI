package lineclassifier

import (
	"encoding/json"
	"strings"
)

// ExtractSnippet pulls a SMALL, bounded sample from an Anthropic Messages body:
// the system prompt plus the first user message, each truncated to n runes.
// Only this sample is ever sent to the classifier, never the full context.
func ExtractSnippet(body []byte, n int) string {
	var req struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	var b strings.Builder
	if s := flattenText(req.System); s != "" {
		b.WriteString("[system] ")
		b.WriteString(truncate(s, n))
		b.WriteString("\n")
	}
	for _, m := range req.Messages {
		if m.Role == "user" {
			b.WriteString("[user] ")
			b.WriteString(truncate(flattenText(m.Content), n))
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// flattenText accepts a plain string or an array of content blocks and returns
// concatenated text only.
func flattenText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var out []string
		for _, bl := range blocks {
			if bl.Type == "text" && bl.Text != "" {
				out = append(out, bl.Text)
			}
		}
		return strings.Join(out, " ")
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ApplyLinePrefix returns the model name pointed at the given line: "line/base".
// It is idempotent against the known line table — a model already carrying one
// of the known line prefixes is re-pointed, never stacked.
func ApplyLinePrefix(model, line string, lines []string) string {
	base := stripKnownPrefix(strings.TrimSpace(model), lines)
	if base == "" {
		return model
	}
	return line + "/" + base
}

func stripKnownPrefix(model string, lines []string) string {
	i := strings.Index(model, "/")
	if i <= 0 {
		return model
	}
	if containsStr(lines, model[:i]) {
		return model[i+1:]
	}
	return model
}

func normalizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Trim(s, ".\"'`:")
	if i := strings.LastIndexAny(s, " \n\t:"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func lineMenu(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("- ")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func trimLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
