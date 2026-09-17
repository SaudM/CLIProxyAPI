package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DescribeFingerprint reports the identity Kimi requests carry for this credential.
func (e *KimiExecutor) DescribeFingerprint(auth *cliproxyauth.Auth) map[string]any {
	if e == nil || auth == nil {
		return nil
	}
	report := fingerprintBase(e.cfg, auth, fingerprintModeFixed)
	report["user_agent"] = "CLIProxyAPI/" + buildinfo.Version
	report["client"] = map[string]any{
		"x-msh-platform": "CLIProxyAPI",
		"x-msh-version":  buildinfo.Version,
	}
	device := map[string]any{
		"name":  getKimiHostname(),
		"model": getKimiDeviceModel(),
	}
	switch {
	case resolveKimiDeviceIDFromAuth(auth) != "":
		device["id"] = cliproxyauth.MaskIdentifier(resolveKimiDeviceIDFromAuth(auth))
		device["id_source"] = "credential"
	case resolveKimiDeviceIDFromStorage(auth) != "":
		device["id"] = cliproxyauth.MaskIdentifier(resolveKimiDeviceIDFromStorage(auth))
		device["id_source"] = "storage"
	default:
		fallback := getKimiDeviceID()
		device["id"] = cliproxyauth.MaskIdentifier(fallback)
		if fallback == "cli-proxy-api-device" {
			device["id_source"] = "fallback-literal"
			fingerprintAddWarning(report, "device id falls back to the literal cli-proxy-api-device shared by every credential without one")
		} else {
			device["id_source"] = "host-kimi-cli"
		}
	}
	report["device"] = device
	report["session"] = "none"
	fingerprintSetTransport(report, "go", "auto")
	fingerprintAddWarning(report, "User-Agent and X-Msh-Platform identify CLIProxyAPI to Kimi")
	fingerprintAddWarning(report, "X-Msh-Device-Name is the proxy server hostname and X-Msh-Device-Model is the proxy host OS/arch")
	return report
}
