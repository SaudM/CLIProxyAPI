package config

import (
	"strings"
	"testing"
)

func TestClaudeDeviceProfileValuesValidate(t *testing.T) {
	cases := []struct {
		name    string
		profile ClaudeDeviceProfileValues
		wantErr string
	}{
		{name: "empty inherits", profile: ClaudeDeviceProfileValues{}},
		{name: "platform only", profile: ClaudeDeviceProfileValues{OS: "Linux", Arch: "x64"}},
		{name: "measured tuple", profile: ClaudeDeviceProfileValues{UserAgent: "claude-cli/2.1.258 (external, cli)", PackageVersion: "0.112.1", RuntimeVersion: "v26.3.0"}},
		{name: "partial tuple", profile: ClaudeDeviceProfileValues{UserAgent: "claude-cli/2.1.258 (external, cli)"}, wantErr: "set together"},
		{name: "unmeasured version", profile: ClaudeDeviceProfileValues{UserAgent: "claude-cli/2.1.240 (external, cli)", PackageVersion: "0.112.1", RuntimeVersion: "v26.3.0"}, wantErr: "not a measured"},
		{name: "mismatched package", profile: ClaudeDeviceProfileValues{UserAgent: "claude-cli/2.1.258 (external, cli)", PackageVersion: "0.95.0", RuntimeVersion: "v26.3.0"}, wantErr: "ships package-version"},
		{name: "wrong ua shape", profile: ClaudeDeviceProfileValues{UserAgent: "claude-cli/2.1.258 (external, sdk-ts)", PackageVersion: "0.112.1", RuntimeVersion: "v26.3.0"}, wantErr: "must look like"},
		{name: "bad os", profile: ClaudeDeviceProfileValues{OS: "macos"}, wantErr: "Stainless platform"},
		{name: "bad arch", profile: ClaudeDeviceProfileValues{Arch: "amd64"}, wantErr: "Stainless architecture"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.profile.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestClaudeDeviceProfileValuesFromMetadata(t *testing.T) {
	profile, err := ClaudeDeviceProfileValuesFromMetadata(map[string]any{
		"device_profile": map[string]any{
			"user-agent":      " claude-cli/2.1.258 (external, cli) ",
			"package_version": "0.112.1",
			"runtime-version": "v26.3.0",
			"os":              "Linux",
		},
	})
	if err != nil {
		t.Fatalf("FromMetadata error = %v", err)
	}
	if profile.UserAgent != "claude-cli/2.1.258 (external, cli)" || profile.PackageVersion != "0.112.1" || profile.RuntimeVersion != "v26.3.0" || profile.OS != "Linux" || profile.Arch != "" {
		t.Fatalf("profile = %+v", profile)
	}
	if got, errAbsent := ClaudeDeviceProfileValuesFromMetadata(map[string]any{}); errAbsent != nil || !got.IsZero() {
		t.Fatalf("absent = (%+v, %v), want zero", got, errAbsent)
	}
	if _, errShape := ClaudeDeviceProfileValuesFromMetadata(map[string]any{"device_profile": "x"}); errShape == nil {
		t.Fatalf("non-object device_profile accepted")
	}
	if _, errType := ClaudeDeviceProfileValuesFromMetadata(map[string]any{"device_profile": map[string]any{"os": 1}}); errType == nil {
		t.Fatalf("non-string field accepted")
	}
}

func TestParseConfigBytesClaudeDeviceProfile(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
claude-api-key:
  - api-key: "k1"
    device-profile:
      user-agent: "claude-cli/2.1.258 (external, cli)"
      package-version: "0.112.1"
      runtime-version: "v26.3.0"
      os: "Linux"
      arch: "x64"
  - api-key: "k2"
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes error = %v", err)
	}
	if cfg.ClaudeKey[0].DeviceProfile.OS != "Linux" || cfg.ClaudeKey[0].DeviceProfile.Arch != "x64" {
		t.Fatalf("device-profile = %+v", cfg.ClaudeKey[0].DeviceProfile)
	}
	if !cfg.ClaudeKey[1].DeviceProfile.IsZero() {
		t.Fatalf("second key should have no device-profile")
	}
	if _, errBad := ParseConfigBytes([]byte("claude-api-key:\n  - api-key: \"k\"\n    device-profile:\n      user-agent: \"claude-cli/9.9.9 (external, cli)\"\n      package-version: \"0.112.1\"\n      runtime-version: \"v26.3.0\"\n")); errBad == nil || !strings.Contains(errBad.Error(), "claude-api-key[0].device-profile") {
		t.Fatalf("unmeasured tuple accepted or wrong error: %v", errBad)
	}
}
