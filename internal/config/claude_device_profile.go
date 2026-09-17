package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ClaudeDeviceProfileValues is a per-credential override of the Claude Code
// software/platform tuple presented to Anthropic. Empty fields inherit
// claude-header-defaults. The software fields (user-agent, package-version,
// runtime-version) are bound together: a Claude Code release ships one SDK
// package version and one Node runtime, so the tuple must be one that exists.
type ClaudeDeviceProfileValues struct {
	UserAgent      string `yaml:"user-agent,omitempty" json:"user-agent,omitempty"`
	PackageVersion string `yaml:"package-version,omitempty" json:"package-version,omitempty"`
	RuntimeVersion string `yaml:"runtime-version,omitempty" json:"runtime-version,omitempty"`
	OS             string `yaml:"os,omitempty" json:"os,omitempty"`
	Arch           string `yaml:"arch,omitempty" json:"arch,omitempty"`
}

// IsZero reports whether no field is set.
func (v ClaudeDeviceProfileValues) IsZero() bool {
	return strings.TrimSpace(v.UserAgent) == "" && strings.TrimSpace(v.PackageVersion) == "" &&
		strings.TrimSpace(v.RuntimeVersion) == "" && strings.TrimSpace(v.OS) == "" && strings.TrimSpace(v.Arch) == ""
}

// Trimmed returns a copy with surrounding whitespace removed from every field.
func (v ClaudeDeviceProfileValues) Trimmed() ClaudeDeviceProfileValues {
	return ClaudeDeviceProfileValues{
		UserAgent:      strings.TrimSpace(v.UserAgent),
		PackageVersion: strings.TrimSpace(v.PackageVersion),
		RuntimeVersion: strings.TrimSpace(v.RuntimeVersion),
		OS:             strings.TrimSpace(v.OS),
		Arch:           strings.TrimSpace(v.Arch),
	}
}

// ClaudeSoftwareTuple is one measured (CLI version, SDK package, Node runtime)
// combination shipped by a real Claude Code release.
type ClaudeSoftwareTuple struct {
	CLIVersion     string
	PackageVersion string
	RuntimeVersion string
}

// knownClaudeSoftwareTuples lists measured Claude Code releases. Both entries are
// native Bun 1.4.3 / BoringSSL builds that report the same SDK and runtime
// versions and emit the same TLS ClientHello (captured 2026-09-18), so the
// inference-plane uTLS spec is valid for either. Extend only from a real
// capture; a tuple no release ever produced is a detectable inconsistency, not
// diversity.
var knownClaudeSoftwareTuples = []ClaudeSoftwareTuple{
	{CLIVersion: "2.1.274", PackageVersion: "0.112.1", RuntimeVersion: "v26.3.0"},
	{CLIVersion: "2.1.273", PackageVersion: "0.112.1", RuntimeVersion: "v26.3.0"},
}

var claudeDeviceProfileUserAgentPattern = regexp.MustCompile(`^claude-cli/(\d+\.\d+\.\d+) \(external, cli\)$`)

// Stainless SDK vocabularies for the platform fields.
var (
	claudeDeviceProfileOSValues   = map[string]struct{}{"MacOS": {}, "Windows": {}, "Linux": {}, "FreeBSD": {}}
	claudeDeviceProfileArchValues = map[string]struct{}{"arm64": {}, "x64": {}, "x86": {}}
)

// KnownClaudeSoftwareTuples returns the measured release table.
func KnownClaudeSoftwareTuples() []ClaudeSoftwareTuple {
	out := make([]ClaudeSoftwareTuple, len(knownClaudeSoftwareTuples))
	copy(out, knownClaudeSoftwareTuples)
	return out
}

// ClaudeSoftwareTupleForVersion returns the measured tuple for a CLI version.
func ClaudeSoftwareTupleForVersion(cliVersion string) (ClaudeSoftwareTuple, bool) {
	cliVersion = strings.TrimSpace(cliVersion)
	for _, tuple := range knownClaudeSoftwareTuples {
		if tuple.CLIVersion == cliVersion {
			return tuple, true
		}
	}
	return ClaudeSoftwareTuple{}, false
}

// Validate rejects a partial or unmeasured software tuple and unknown platform
// values. The software triple must be either fully absent (inherit) or fully
// present and equal to a measured release; mixing one release's user-agent with
// another's package or runtime version is refused because no real client emits it.
func (v ClaudeDeviceProfileValues) Validate() error {
	v = v.Trimmed()
	hasUA, hasPkg, hasRt := v.UserAgent != "", v.PackageVersion != "", v.RuntimeVersion != ""
	switch {
	case !hasUA && !hasPkg && !hasRt:
	case hasUA && hasPkg && hasRt:
		matches := claudeDeviceProfileUserAgentPattern.FindStringSubmatch(v.UserAgent)
		if len(matches) != 2 {
			return fmt.Errorf("user-agent %q must look like \"claude-cli/<version> (external, cli)\"", v.UserAgent)
		}
		tuple, ok := ClaudeSoftwareTupleForVersion(matches[1])
		if !ok {
			return fmt.Errorf("user-agent version %s is not a measured Claude Code release (known: %s)", matches[1], knownClaudeVersionsForError())
		}
		if tuple.PackageVersion != v.PackageVersion || tuple.RuntimeVersion != v.RuntimeVersion {
			return fmt.Errorf("claude-cli/%s ships package-version %s and runtime-version %s; got %s / %s", tuple.CLIVersion, tuple.PackageVersion, tuple.RuntimeVersion, v.PackageVersion, v.RuntimeVersion)
		}
	default:
		return fmt.Errorf("user-agent, package-version and runtime-version must be set together")
	}
	if v.OS != "" {
		if _, ok := claudeDeviceProfileOSValues[v.OS]; !ok {
			return fmt.Errorf("os %q is not a Stainless platform name (MacOS, Windows, Linux, FreeBSD)", v.OS)
		}
	}
	if v.Arch != "" {
		if _, ok := claudeDeviceProfileArchValues[v.Arch]; !ok {
			return fmt.Errorf("arch %q is not a Stainless architecture name (arm64, x64, x86)", v.Arch)
		}
	}
	return nil
}

func knownClaudeVersionsForError() string {
	versions := make([]string, 0, len(knownClaudeSoftwareTuples))
	for _, tuple := range knownClaudeSoftwareTuples {
		versions = append(versions, tuple.CLIVersion)
	}
	return strings.Join(versions, ", ")
}

// ClaudeDeviceProfileValuesFromMetadata decodes the "device_profile" object of an
// auth JSON file. Keys accept both kebab and snake spelling. A missing object
// yields a zero value; a malformed one is reported so a typo cannot silently
// fall back to the global baseline.
func ClaudeDeviceProfileValuesFromMetadata(metadata map[string]any) (ClaudeDeviceProfileValues, error) {
	raw, ok := metadata["device_profile"]
	if !ok || raw == nil {
		return ClaudeDeviceProfileValues{}, nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return ClaudeDeviceProfileValues{}, fmt.Errorf("device_profile must be an object")
	}
	read := func(keys ...string) (string, error) {
		for _, key := range keys {
			value, present := object[key]
			if !present || value == nil {
				continue
			}
			text, okText := value.(string)
			if !okText {
				return "", fmt.Errorf("device_profile.%s must be a string", key)
			}
			return strings.TrimSpace(text), nil
		}
		return "", nil
	}
	var values ClaudeDeviceProfileValues
	var errRead error
	if values.UserAgent, errRead = read("user_agent", "user-agent"); errRead != nil {
		return ClaudeDeviceProfileValues{}, errRead
	}
	if values.PackageVersion, errRead = read("package_version", "package-version"); errRead != nil {
		return ClaudeDeviceProfileValues{}, errRead
	}
	if values.RuntimeVersion, errRead = read("runtime_version", "runtime-version"); errRead != nil {
		return ClaudeDeviceProfileValues{}, errRead
	}
	if values.OS, errRead = read("os"); errRead != nil {
		return ClaudeDeviceProfileValues{}, errRead
	}
	if values.Arch, errRead = read("arch"); errRead != nil {
		return ClaudeDeviceProfileValues{}, errRead
	}
	return values, nil
}

// ValidateClaudeDeviceProfiles validates every claude-api-key device-profile override.
func (cfg *Config) ValidateClaudeDeviceProfiles() error {
	if cfg == nil {
		return nil
	}
	for index := range cfg.ClaudeKey {
		if errValidate := cfg.ClaudeKey[index].DeviceProfile.Validate(); errValidate != nil {
			return fmt.Errorf("claude-api-key[%d].device-profile: %w", index, errValidate)
		}
	}
	return nil
}
