package vault

import (
	"strings"
	"testing"
)

func TestRDPSettingsPreserveLegacyDefaultsAndNormalize(t *testing.T) {
	d, err := NormalizeRDPSettings(nil)
	if err != nil || d != DefaultRDPSettings() {
		t.Fatal(err)
	}
	s := d
	s.Domain = " DOMAIN "
	s.ScreenSize = " 1280X720 "
	s.GatewayHostname = " edge.example "
	s.GatewayCredentialID = " ABCDEFAB-ABCD-ABCD-ABCD-ABCDEFABCDEF "
	s.RedirectDrives = " c, d "
	got, err := NormalizeRDPSettings(&s)
	if err != nil || got.Domain != "DOMAIN" || got.ScreenSize != "1280X720" || got.GatewayHostname != "edge.example" || got.GatewayCredentialID != "abcdefab-abcd-abcd-abcd-abcdefabcdef" || got.RedirectDrives != "C,D" {
		t.Fatal("normalization", got, err)
	}
	s = d
	s.ScreenSize = ""
	got, err = NormalizeRDPSettings(&s)
	if err != nil || got.ScreenSize != d.ScreenSize {
		t.Fatal(err)
	}
	for _, size := range []string{"fitToWindow", "full screen", "full connection content", "640x480", "16384x16384"} {
		if !ValidRDPScreenSize(size) {
			t.Fatal(size)
		}
	}
	for _, size := range []string{"639x480", "640x479", "16385x480", "640x16385", "bad", "12x99"} {
		if ValidRDPScreenSize(size) {
			t.Fatal(size)
		}
	}
	if NormalizeRDPDriveList(" ALL ") != "all" || NormalizeRDPDriveList(" ") != "" || ValidRDPHost("bad host") || ValidRDPText("bad\n", 10) {
		t.Fatal("text validation")
	}
}
func TestRDPSettingsRejectAndRepairCorruptPersistedOptions(t *testing.T) {
	mutations := []func(*RDPSettings){func(s *RDPSettings) { s.Domain = "bad\nvalue" }, func(s *RDPSettings) { s.ScreenSize = "bad" }, func(s *RDPSettings) { s.ColorDepth = 0 }, func(s *RDPSettings) { s.AudioMode = 3 }, func(s *RDPSettings) { s.AudioCaptureMode = 2 }, func(s *RDPSettings) { s.KeyboardHookMode = 3 }, func(s *RDPSettings) { s.ConnectionSpeed = 0 }, func(s *RDPSettings) { s.ServerAuthentication = 3 }, func(s *RDPSettings) { s.GatewayUsageMethod = 4 }, func(s *RDPSettings) { s.GatewayHostname = "bad host" }, func(s *RDPSettings) { s.GatewayCredentialID = "bad" }, func(s *RDPSettings) { s.RedirectDrives = "bad" }, func(s *RDPSettings) { s.RedirectDrives = strings.Repeat("A,", 64) + "A" }}
	for i, mutate := range mutations {
		s := DefaultRDPSettings()
		mutate(&s)
		if _, err := NormalizeRDPSettings(&s); err == nil {
			t.Fatal("invalid settings accepted", i)
		}
		repaired := NormalizePersistedRDPSettings(s)
		if repaired != DefaultRDPSettings() {
			t.Fatal("persisted fallback mismatch", i, repaired)
		}
	}
	s := DefaultRDPSettings()
	s.GatewayUsageMethod = 1
	if _, err := NormalizeRDPSettings(&s); err == nil {
		t.Fatal("required gateway missing")
	}
	if NormalizePersistedRDPSettings(s) != DefaultRDPSettings() {
		t.Fatal("missing gateway not repaired")
	}
}

func TestRDPExternalPreferenceIsScopedToWindows(t *testing.T) {
	settings := DefaultRDPSettings()
	settings.UseExternalClient = true
	for _, platform := range []string{"windows", "darwin", "linux"} {
		native := RDPSettingsForPlatform(settings, platform)
		if native.UseExternalClient != (platform == "windows") {
			t.Fatal(platform)
		}
		native.UseExternalClient = true
		if native != settings {
			t.Fatal("platform changed unrelated settings")
		}
	}
	if !settings.UseExternalClient {
		t.Fatal("platform projection mutated original")
	}
}
