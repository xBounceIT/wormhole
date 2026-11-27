package updateauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeDarwinPublisher(t *testing.T) {
	unsigned := openDarwinTestImage(t, filepath.Join(t.TempDir(), "unsigned.dmg"))
	defer unsigned.Close()
	if err := VerifyPublisher(unsigned, "AB7CDEFGH9"); err != ErrPublisherUntrusted {
		t.Fatalf("unsigned disk image was accepted: %v", err)
	}
	path := os.Getenv("WORMHOLE_TEST_NOTARIZED_DMG")
	if path == "" {
		return
	}
	team := os.Getenv("WORMHOLE_TEST_NOTARIZED_TEAM_ID")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := VerifyPublisher(file, team); err != nil {
		t.Fatalf("notarized fixture failed verification: %v", err)
	}
	other := "AB7CDEFGH9"
	if team == other {
		other = "CD7CDEFGH9"
	}
	if err := VerifyPublisher(file, other); err != ErrPublisherUntrusted {
		t.Fatalf("notarized disk image accepted under wrong Team ID: %v", err)
	}
}
