package ospolicy

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"howett.net/plist"
)

func TestManagedManifestPolicyDigest(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, value := range []string{digest, strings.ToUpper(digest) + "\r\n"} {
		if got, err := parseManagedUpdateDigest([]byte(value)); err != nil || got != digest {
			t.Fatalf("unexpected digest %q: %v", got, err)
		}
	}
	for _, invalid := range []string{"", digest[:63], digest + "00", strings.Repeat("zz", 32), digest + "  file", digest + "\x00"} {
		if got, err := parseManagedUpdateDigest([]byte(invalid)); err != vault.ErrPolicy || got != "" {
			t.Fatalf("invalid policy accepted: %q %v", got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if approval, err := ReadManagedUpdate(ctx); err != context.Canceled || approval != (ManagedUpdate{}) {
		t.Fatal(approval, err)
	}
	// Read the machine source without changing its configuration.
	approval, err := ReadManagedUpdate(context.Background())
	if err != nil && err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err == nil && approval.Digest != "" {
		if canonical, err := parseManagedUpdateDigest([]byte(approval.Digest)); err != nil || canonical != approval.Digest || approval.Directory == "" {
			t.Fatal("machine approval was not canonical")
		}
	}
}

func TestMachinePolicyFormats(t *testing.T) {
	for _, p := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
		got, err := parseJSON([]byte(` { "profile": "` + string(p) + `" } `))
		if err != nil || got != p {
			t.Fatal(got, err)
		}
		for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
			raw, err := plist.Marshal(map[string]string{"Profile": string(p)}, format)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsePlist(raw)
			if err != nil || got != p {
				t.Fatal(format, got, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := ReadFloor(ctx); p != "" || err != context.Canceled {
		t.Fatal(p, err)
	}
	// Reads the real machine source without changing it. Managed hosts may have
	// any of the four floors; a denied/damaged policy must remain a fixed error.
	p, err := ReadFloor(context.Background())
	if err != nil && err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err == nil {
		if _, err := profile(string(p)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMachinePolicyRejectsAmbiguityAndUnboundedInputs(t *testing.T) {
	for _, raw := range []string{"", "null", "{", "{}", `{"Profile":"default"}`, `{"profile":null}`, `{"profile":3}`, `{"profile":"future"}`, `{"profile":"Default"}`, `{"profile":"default","profile":"paranoid"}`, `{"profile":"default","extra":true}`, `{"profile":"default"} []`, strings.Repeat("x", maxPolicyBytes+1)} {
		if p, err := parseJSON([]byte(raw)); p != "" || err != vault.ErrPolicy {
			t.Fatal("JSON accepted", raw, p, err)
		}
	}
	for _, raw := range []string{"", "{Profile=default;}", "<plist>", `<plist><dict/></plist>`, `<plist><dict><key>Profile</key><string>future</string></dict></plist>`, `<plist><dict><key>profile</key><string>default</string></dict></plist>`, `<plist><dict><key>Profile</key><string>default</string><key>Profile</key><string>paranoid</string></dict></plist>`, `<plist><dict><key>Profile</key><array><string>default</string></array></dict></plist>`, `<plist><dict><key attr="x">Profile</key><string>default</string></dict></plist>`, `<plist xmlns="evil"><dict><key>Profile</key><string>default</string></dict></plist>`, `<plist><dict><key>Profile</key><string>default</string></dict></plist>extra`, strings.Repeat("x", maxPolicyBytes+1)} {
		if p, err := parsePlist([]byte(raw)); p != "" || err != vault.ErrPolicy {
			t.Fatal("plist accepted", p, err)
		}
	}
	for _, value := range []any{map[string]string{"Profile": "default", "extra": "standard"}, map[string]int{"Profile": 1}, []string{"default"}, map[string]any{"Profile": map[string]string{"value": "default"}}} {
		raw, err := plist.Marshal(value, plist.BinaryFormat)
		if err != nil {
			t.Fatal(err)
		}
		if p, err := parsePlist(raw); p != "" || err != vault.ErrPolicy {
			t.Fatal("binary shape accepted", p, err)
		}
	}
}

func TestBinaryPolicyPreflightRejectsLengthsReferencesAndDuplicateObjects(t *testing.T) {
	raw, err := plist.Marshal(map[string]string{"Profile": "default"}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	for size := range len(raw) {
		if _, err := parsePlist(raw[:size]); err == nil {
			t.Fatal("truncation", size)
		}
	}
	trailer := len(raw) - 32
	for _, mutate := range []func([]byte){
		func(b []byte) { b[7] = '9' }, func(b []byte) { b[trailer+6] = 0 }, func(b []byte) { b[trailer+7] = 9 },
		func(b []byte) { binary.BigEndian.PutUint64(b[trailer+8:], ^uint64(0)) },
		func(b []byte) { binary.BigEndian.PutUint64(b[trailer+16:], 3) },
		func(b []byte) { binary.BigEndian.PutUint64(b[trailer+24:], ^uint64(0)) },
		func(b []byte) { b[8] = 0xd2 }, func(b []byte) { b[9] = 0 }, func(b []byte) { b[10] = b[9] },
		func(b []byte) { b[9] = 255 }, func(b []byte) { b[11] = 0x5f },
		func(b []byte) { table := int(binary.BigEndian.Uint64(b[trailer+24:])); b[table+1] = b[table] },
		func(b []byte) { table := int(binary.BigEndian.Uint64(b[trailer+24:])); b[table] = 0 },
		func(b []byte) { table := int(binary.BigEndian.Uint64(b[trailer+24:])); b[table] = byte(table) },
	} {
		candidate := bytes.Clone(raw)
		mutate(candidate)
		if _, err := parsePlist(candidate); err != vault.ErrPolicy {
			t.Fatal("malformed binary accepted", err)
		}
	}
}

func TestXMLPolicyRejectsUnknownVersionAndAttributes(t *testing.T) {
	for _, attrs := range []string{`version="2.0"`, `version="1.0" extra="value"`, `future="value"`, `version="1.0" version="1.0"`} {
		raw := []byte(`<plist ` + attrs + `><dict><key>Profile</key><string>default</string></dict></plist>`)
		if _, err := parsePlist(raw); err != vault.ErrPolicy {
			t.Fatal("unsupported attributes accepted", err)
		}
	}
}

func FuzzMachinePolicy(f *testing.F) {
	f.Add([]byte(`{"profile":"standard"}`))
	f.Add([]byte("bplist00" + strings.Repeat("\x00", 40)))
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		raw, err := plist.Marshal(map[string]string{"Profile": "hardened"}, format)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxPolicyBytes {
			return
		}
		for _, parse := range []func([]byte) (vault.Profile, error){parseJSON, parsePlist} {
			p, err := parse(raw)
			if err != nil && (err != vault.ErrPolicy || p != "") {
				t.Fatal("partial policy on failure")
			}
			if err == nil {
				if _, err := profile(string(p)); err != nil {
					t.Fatal("invalid profile")
				}
			}
		}
	})
}
