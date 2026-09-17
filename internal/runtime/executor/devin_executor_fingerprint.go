package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity Devin requests carry for this credential.
func (e *DevinExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	_, _, deviceSeed := devinAuthCredentials(auth)
	report := fingerprintBase(e.cfg, auth, fingerprintModeSuppressed)
	report["user_agent"] = ""
	report["client"] = map[string]any{
		"name":    helps.DevinDefaultClientName,
		"version": helps.DevinDefaultClientVersion,
		"binary":  "devin-cli",
	}
	device := map[string]any{"id_source": "random-per-request"}
	if deviceSeed != "" {
		device["id_source"] = "seeded"
		fingerprintOverrides(report)["device_seed"] = cliproxyauth.MaskIdentifier(deviceSeed)
	} else {
		fingerprintAddWarning(report, "device fingerprint is regenerated on every request; set device_seed to keep it stable")
	}
	report["device"] = device
	report["session"] = "derived"
	fingerprintSetTransport(report, "go", "auto")
	return report
}
