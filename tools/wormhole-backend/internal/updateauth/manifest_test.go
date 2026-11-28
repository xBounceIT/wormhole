package updateauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestRoundTrip(t *testing.T) {
	m, key := manifestFixture(t)
	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	public, err := ParsePublicKey(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	// This digest freezes the canonical fields, order and domain separator.
	const fixtureDigest = "723c5c479f08647ad256d6396e8ff77c1e6ff35a45af3d4b4e7468cb6914c6ac"
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != fixtureDigest {
		t.Fatalf("canonical manifest changed: %x", sum)
	}
	got, err := Verify(raw, public)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ os, arch, name string }{
		{"darwin", "x64", "Wormhole-3.2.1-mac-universal-setup.dmg"},
		{"darwin", "arm64", "Wormhole-3.2.1-mac-universal-setup.dmg"},
		{"windows", "x64", "Wormhole-3.2.1-win-x64-setup.exe"},
		{"windows", "arm64", "Wormhole-3.2.1-win-arm64-setup.exe"},
		{"linux", "x64", "Wormhole-3.2.1-x86_64.AppImage"},
		{"linux", "arm64", "Wormhole-3.2.1-arm64.AppImage"},
	} {
		artifact, ok := got.ArtifactFor(c.os, c.arch)
		if !ok || artifact.Name != c.name || artifact.Size != 42 || artifact.SHA256 != strings.Repeat("ab", 32) {
			t.Errorf("unexpected artifact for %s/%s: %+v", c.os, c.arch, artifact)
		}
	}
	if _, ok := got.ArtifactFor("linux", "386"); ok {
		t.Fatal("selected an unsupported target")
	}
	for _, pin := range []string{"", strings.Repeat("0", 64), strings.ToUpper(keyHex), keyHex + "\n"} {
		if _, err := ParsePublicKey(pin); err == nil {
			t.Fatal("accepted a non-canonical pin")
		}
	}
}

func TestManifestRejectsAmbiguousAndTamperedInputs(t *testing.T) {
	m, key := manifestFixture(t)
	public := key.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	raw, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		data []byte
		key  ed25519.PublicKey
		want error
	}{
		{"empty", nil, public, ErrManifest},
		{"oversized", bytes.Repeat([]byte{' '}, MaxManifestBytes+1), public, ErrManifest},
		{"short key", raw, public[:8], ErrManifest},
		{"wrong key", raw, other, ErrSignature},
		{"whitespace", append([]byte{' '}, raw...), public, ErrManifest},
		{"unknown field", append([]byte(`{"extra":0,`), raw[1:]...), public, ErrManifest},
		{"duplicate field", bytes.Replace(raw, []byte(`"formatVersion":1`), []byte(`"formatVersion":1,"formatVersion":1`), 1), public, ErrManifest},
		{"short signature", []byte(`{"manifest":{},"signature":"AA=="}`), public, ErrManifest},
		{"changed digest", bytes.Replace(raw, []byte(m.Artifacts[0].SHA256), []byte(strings.Repeat("cd", 32)), 1), public, ErrSignature},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Verify(c.data, c.key); !errors.Is(err, c.want) {
				t.Fatalf("Verify returned %v, want %v", err, c.want)
			}
		})
	}
	if _, err := Sign(m, key[:8]); !errors.Is(err, ErrSignature) {
		t.Fatalf("invalid signing key: %v", err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"repository": func(m *Manifest) { m.Repository = "fork/wormhole" },
		"format":     func(m *Manifest) { m.FormatVersion++ },
		"tag":        func(m *Manifest) { m.ReleaseTag = "v03.2.1" },
		"incomplete": func(m *Manifest) { m.Artifacts = m.Artifacts[1:] },
		"target":     func(m *Manifest) { m.Artifacts[1] = m.Artifacts[2] },
		"name":       func(m *Manifest) { m.Artifacts[0].Name = "../" + m.Artifacts[0].Name },
		"empty file": func(m *Manifest) { m.Artifacts[0].Size = 0 },
		"large file": func(m *Manifest) { m.Artifacts[0].Size = MaxInstallerBytes + 1 },
		"digest":     func(m *Manifest) { m.Artifacts[0].SHA256 = strings.Repeat("AB", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad, _ := manifestFixture(t)
			mutate(&bad)
			if _, err := Sign(bad, key); !errors.Is(err, ErrManifest) {
				t.Fatalf("signed invalid manifest: %v", err)
			}
			payload, err := json.Marshal(envelope{bad, make([]byte, ed25519.SignatureSize)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(payload, public); !errors.Is(err, ErrManifest) {
				t.Fatalf("Verify did not reject the invalid manifest: %v", err)
			}
		})
	}
	if _, err := NewManifest("v3.2.1/sibling"); !errors.Is(err, ErrManifest) {
		t.Fatalf("unexpected tag result: %v", err)
	}
}

func TestSystemManifestBindsEachLinuxPackageAndKeepsThePublicInstaller(t *testing.T) {
	legacy, key := manifestFixture(t)
	m, err := NewSystemManifest(legacy.ReleaseTag)
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Artifacts {
		m.Artifacts[i].Size = 42
		m.Artifacts[i].SHA256 = strings.Repeat("ab", 32)
	}
	raw, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	verified, err := Verify(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ arch, format, suffix string }{
		{"x64", "deb", "amd64.deb"}, {"x64", "rpm", "x86_64.rpm"},
		{"arm64", "deb", "arm64.deb"}, {"arm64", "rpm", "aarch64.rpm"},
	} {
		asset, ok := verified.LinuxPackage(tc.arch, tc.format)
		if !ok || asset.Name != "Wormhole-3.2.1-linux-"+tc.suffix {
			t.Fatal(tc, asset)
		}
		if _, ok := legacy.LinuxPackage(tc.arch, tc.format); ok {
			t.Fatal("legacy manifest supplied a system package")
		}
		current, _ := verified.ArtifactFor("linux", tc.arch)
		previous, _ := legacy.ArtifactFor("linux", tc.arch)
		if current != previous {
			t.Fatal("public installer changed", current, previous)
		}
	}
	for _, tc := range [][2]string{{"386", "deb"}, {"x64", "AppImage"}} {
		if _, ok := verified.LinuxPackage(tc[0], tc[1]); ok {
			t.Fatal(tc)
		}
	}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain, err := json.Marshal(envelope{Manifest: m, Signature: ed25519.Sign(key, append([]byte(domain), payload...))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(wrongDomain, pub); !errors.Is(err, ErrSignature) {
		t.Fatal("an old-domain signature was admitted", err)
	}
	m.Artifacts[len(m.Artifacts)-1].Name = m.Artifacts[len(m.Artifacts)-2].Name
	if _, err := Sign(m, key); !errors.Is(err, ErrManifest) {
		t.Fatal("mislabelled package signed", err)
	}
}

func manifestFixture(t *testing.T) (Manifest, ed25519.PrivateKey) {
	t.Helper()
	m, err := NewManifest("v3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Artifacts {
		m.Artifacts[i].Size = 42
		m.Artifacts[i].SHA256 = strings.Repeat("ab", 32)
	}
	return m, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
}

func TestDigestRequiresARegularFlatArtifact(t *testing.T) {
	dir := t.TempDir()
	data := []byte("test installer")
	for name, body := range map[string][]byte{"file": data, "empty": nil} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	size, digest, err := Digest(root, "file")
	sha := sha256.Sum256(data)
	if err != nil || size != int64(len(data)) || digest != hex.EncodeToString(sha[:]) {
		t.Fatalf("unexpected artifact digest: %d %s %v", size, digest, err)
	}
	for _, name := range []string{"", "./file", `folder\..\file`, "file:stream", "folder", "empty", "missing"} {
		if _, _, err := Digest(root, name); !errors.Is(err, ErrArtifact) {
			t.Errorf("accepted %q: %v", name, err)
		}
	}
	t.Run("symbolic link", func(t *testing.T) {
		if err := os.Symlink("file", filepath.Join(dir, "link")); err != nil {
			t.Skipf("cannot create a symlink: %v", err)
		}
		if _, _, err := Digest(root, "link"); !errors.Is(err, ErrArtifact) {
			t.Fatalf("accepted a link: %v", err)
		}
	})
}
