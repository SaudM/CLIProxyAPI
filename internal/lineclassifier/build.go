package lineclassifier

import "time"

// RouterFromConfig builds a Router from the fixed config fields and a live
// settings getter. It returns nil when no lines are configured, which callers
// treat as "feature off". getSetting must return the current url/key/model.
//
// Keeping construction here means the server layer does not duplicate defaults.
func RouterFromConfig(lines []string, defaultLine string, snippetChars, timeoutMs, ttlMinutes int, getSetting func() Settings) *Router {
	clean := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for _, l := range lines {
		l = trimLower(l)
		if l != "" && !seen[l] {
			seen[l] = true
			clean = append(clean, l)
		}
	}
	if len(clean) == 0 {
		return nil // no table => feature off
	}
	def := trimLower(defaultLine)
	if !containsStr(clean, def) {
		def = clean[len(clean)-1] // default must be a real line
	}
	ttl := time.Duration(ttlMinutes) * time.Minute
	if ttlMinutes <= 0 {
		ttl = 4 * time.Hour
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeoutMs <= 0 {
		timeout = 4 * time.Second
	}
	return NewRouter(Config{
		Lines:        clean,
		DefaultLine:  def,
		SnippetChars: snippetChars,
		Timeout:      timeout,
		TTL:          ttl,
	}, getSetting)
}
