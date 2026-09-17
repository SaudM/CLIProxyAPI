package management

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPatchAuthFileFields_ShapeOverrides(t *testing.T) {
	h, manager := newLimitsTestHandler(t)
	h.cfg.ProxyPool = []config.ProxyPoolEntry{{URL: "socks5://u:p@10.0.0.1:443", Label: "jp-1", Timezone: "Asia/Tokyo"}}

	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","rpd":600,"tpd":15000000,"max-sessions":4,"active-hours":" 08:30-01:00 ","proxy-pool-label":"JP-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", rec.Code, rec.Body.String())
	}
	updated, _ := manager.GetByID("limits.json")
	if rpd, ok := updated.RPDOverride(); !ok || rpd != 600 {
		t.Fatalf("rpd override = (%d, %t)", rpd, ok)
	}
	if tpd, ok := updated.TPDOverride(); !ok || tpd != 15000000 {
		t.Fatalf("tpd override = (%d, %t)", tpd, ok)
	}
	if sessions, ok := updated.MaxSessionsOverride(); !ok || sessions != 4 {
		t.Fatalf("max_sessions override = (%d, %t)", sessions, ok)
	}
	if hours, ok := updated.ActiveHoursOverride(); !ok || hours != "08:30-01:00" {
		t.Fatalf("active_hours override = (%q, %t)", hours, ok)
	}
	if updated.ProxyPoolLabel() != "JP-1" {
		t.Fatalf("proxy_pool_label = %q", updated.ProxyPoolLabel())
	}
	payload := credentialLimitStatusPayload(manager.CredentialLimitStatus(updated))
	if payload["rpd"].(gin.H)["limit"] != 600 || payload["active_hours"].(gin.H)["window"] != "08:30-01:00" || payload["max_sessions"].(gin.H)["limit"] != 4 {
		t.Fatalf("status payload = %v", payload)
	}

	for _, body := range []string{
		`{"name":"limits.json","active_hours":"25:00-01:00"}`,
		`{"name":"limits.json","active_hours":7}`,
		`{"name":"limits.json","rpd":-1}`,
		`{"name":"limits.json","proxy_pool_label":"nope"}`,
	} {
		if rec := patchAuthFileFields(t, h, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("patch %s status = %d, want 400", body, rec.Code)
		}
	}

	if rec := patchAuthFileFields(t, h, `{"name":"limits.json","active_hours":"","proxy_pool_label":"","rpd":null}`); rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d body = %s", rec.Code, rec.Body.String())
	}
	cleared, _ := manager.GetByID("limits.json")
	if hours, ok := cleared.ActiveHoursOverride(); !ok || hours != "" {
		t.Fatalf("empty active_hours should stay as an explicit always-on override: (%q, %t)", hours, ok)
	}
	if cleared.ProxyPoolLabel() != "" {
		t.Fatalf("proxy_pool_label not cleared: %q", cleared.ProxyPoolLabel())
	}
	if _, ok := cleared.RPDOverride(); ok {
		t.Fatal("rpd override not cleared")
	}
}
