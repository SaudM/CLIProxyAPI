package helps

import (
	"testing"
	"time"
)

func TestClaudeClientVersionsTracksLast24Hours(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	resetClaudeClientVersionsForTest(func() time.Time { return now })
	t.Cleanup(func() { resetClaudeClientVersionsForTest(nil) })

	RecordClaudeClientVersion("auth-a", "claude-cli/2.1.274 (external, cli)")
	RecordClaudeClientVersion("auth-a", "claude-cli/2.1.274 (external, cli)")
	RecordClaudeClientVersion("auth-a", "claude-cli/2.1.301 (external, sdk-cli)")
	RecordClaudeClientVersion("auth-a", "curl/8.0")
	RecordClaudeClientVersion("", "claude-cli/2.1.274 (external, cli)")

	versions := ClaudeClientVersions("auth-a")
	if len(versions) != 2 || versions[0].Version != "2.1.274" || versions[0].Requests != 2 || versions[1].Version != "2.1.301" || versions[1].Requests != 1 {
		t.Fatalf("versions = %+v", versions)
	}
	if len(ClaudeClientVersions("auth-b")) != 0 {
		t.Fatal("unrelated credential has versions")
	}
	now = now.Add(25 * time.Hour)
	if remaining := ClaudeClientVersions("auth-a"); len(remaining) != 0 {
		t.Fatalf("versions survived retention: %+v", remaining)
	}
	if version, ok := ClaudeClientVersionFromUserAgent("claude-cli/2.1.274 (external, cli)"); !ok || version != "2.1.274" {
		t.Fatalf("ClaudeClientVersionFromUserAgent = %q, %t", version, ok)
	}
}
