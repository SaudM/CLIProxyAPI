package helps

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	claudeClientVersionRetention   = 24 * time.Hour
	claudeClientVersionMaxPerAuth  = 16
	claudeClientVersionPruneEveryN = 256
)

// ClaudeClientVersionStat is one downstream Claude Code version seen on a credential.
type ClaudeClientVersionStat struct {
	Version   string
	Requests  int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// claudeClientVersionRegistry remembers which native Claude Code versions each credential
// served in the last 24 hours. The fingerprint report uses it to warn when clients run a
// version other than the credential baseline: their User-Agent is rewritten to the
// baseline while the system prompt keeps the client's own text.
type claudeClientVersionRegistry struct {
	mu     sync.Mutex
	byAuth map[string]map[string]*ClaudeClientVersionStat
	now    func() time.Time
	writes int
}

var claudeClientVersions = &claudeClientVersionRegistry{byAuth: make(map[string]map[string]*ClaudeClientVersionStat), now: time.Now}

// ClaudeClientVersionFromUserAgent extracts the CLI version from a Claude Code User-Agent.
func ClaudeClientVersionFromUserAgent(userAgent string) (string, bool) {
	version, ok := parseClaudeCLIVersion(userAgent)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", version.major, version.minor, version.patch), true
}

// RecordClaudeClientVersion notes that a confirmed native client with userAgent was
// served by authID. Unparsable user agents are ignored.
func RecordClaudeClientVersion(authID, userAgent string) {
	authID = strings.TrimSpace(authID)
	version, ok := ClaudeClientVersionFromUserAgent(userAgent)
	if authID == "" || !ok {
		return
	}
	r := claudeClientVersions
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	if r.writes%claudeClientVersionPruneEveryN == 0 {
		r.pruneLocked(now)
	}
	versions := r.byAuth[authID]
	if versions == nil {
		versions = make(map[string]*ClaudeClientVersionStat)
		r.byAuth[authID] = versions
	}
	stat := versions[version]
	if stat == nil {
		if len(versions) >= claudeClientVersionMaxPerAuth {
			return
		}
		stat = &ClaudeClientVersionStat{Version: version, FirstSeen: now}
		versions[version] = stat
	}
	stat.Requests++
	stat.LastSeen = now
}

// ClaudeClientVersions returns the versions seen on authID in the last 24 hours, most used first.
func ClaudeClientVersions(authID string) []ClaudeClientVersionStat {
	r := claudeClientVersions
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	versions := r.byAuth[strings.TrimSpace(authID)]
	out := make([]ClaudeClientVersionStat, 0, len(versions))
	for key, stat := range versions {
		if now.Sub(stat.LastSeen) >= claudeClientVersionRetention {
			delete(versions, key)
			continue
		}
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func (r *claudeClientVersionRegistry) pruneLocked(now time.Time) {
	for authID, versions := range r.byAuth {
		for key, stat := range versions {
			if now.Sub(stat.LastSeen) >= claudeClientVersionRetention {
				delete(versions, key)
			}
		}
		if len(versions) == 0 {
			delete(r.byAuth, authID)
		}
	}
}

func resetClaudeClientVersionsForTest(now func() time.Time) {
	r := claudeClientVersions
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byAuth = make(map[string]map[string]*ClaudeClientVersionStat)
	r.writes = 0
	if now != nil {
		r.now = now
	} else {
		r.now = time.Now
	}
}
