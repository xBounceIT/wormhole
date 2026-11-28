package updateauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsPublisherCertificatePin(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth} {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Unix(1, 0), NotAfter: time.Unix(60, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
		if err != nil {
			t.Fatal(err)
		}
		context := windows.CertContext{EncodingType: windows.X509_ASN_ENCODING, Length: uint32(len(der)), EncodedCert: &der[0]}
		got, err := pinWindowsCertificate(&context)
		if usage == x509.ExtKeyUsageCodeSigning {
			if err != nil || got != sha256.Sum256(spki) {
				t.Fatalf("unexpected signer pin (%x, %v)", got, err)
			}
		} else if err != ErrPublisherUntrusted {
			t.Fatal("certificate without code-signing usage was accepted")
		}
	}
	for _, cert := range []windows.CertContext{
		{EncodingType: windows.X509_ASN_ENCODING, EncodedCert: &spki[0], Length: uint32(len(spki))},
		{EncodingType: windows.X509_ASN_ENCODING, EncodedCert: &spki[0], Length: maxPublisherCertBytes + 1},
		{EncodingType: windows.X509_ASN_ENCODING},
		{},
	} {
		if _, err := pinWindowsCertificate(&cert); err != ErrPublisherUntrusted {
			t.Fatalf("invalid DER data accepted: %v", err)
		}
	}
}

func TestWindowsPublisherRefusesUnsignedAndUnavailable(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsPublisher(f, PublisherPin{}); err != ErrPublisherUnavailable {
		t.Fatalf("missing pin: %v", err)
	}
	pin := sha256.Sum256([]byte("test publisher"))
	if err := VerifyWindowsPublisher(f, pin); err != ErrPublisherUntrusted {
		t.Fatalf("unsigned test binary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsPublisher(f, pin); err != ErrPublisherUntrusted {
		t.Fatalf("closed file handle: %v", err)
	}
}

func TestWindowsPublisherSignedFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_AUTHENTICODE_INSTALLER")
	if path == "" {
		t.Skip("requires an independently pinned Windows-signed fixture")
	}
	pin, err := ParsePublisherPin(os.Getenv("WORMHOLE_TEST_AUTHENTICODE_SPKI"))
	if err != nil {
		t.Fatal(err)
	}
	verify := func(path string, pin PublisherPin, want error) {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := VerifyWindowsPublisher(f, pin); err != want {
			t.Fatalf("publisher verification: got %v, want %v", err, want)
		}
	}
	verify(path, pin, nil)
	other := pin
	other[0] ^= 1
	verify(path, other, ErrPublisherUntrusted)
	image, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	section := image.Section(".text")
	_ = image.Close()
	data, err := os.ReadFile(path)
	if err != nil || section == nil || section.Offset == 0 || uint64(section.Offset) >= uint64(len(data)) {
		t.Fatalf("fixture lacks executable section: %v", err)
	}
	data[section.Offset] ^= 1
	altered := filepath.Join(t.TempDir(), "tampered.exe")
	if err := os.WriteFile(altered, data, 0o600); err != nil {
		t.Fatal(err)
	}
	verify(altered, pin, ErrPublisherUntrusted)
}

func TestWindowsPublisherLocksInstallerBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "installer.exe")
	if err := os.WriteFile(path, []byte("unchanged installer bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := OpenArtifact(root, "installer.exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	locked, err := LockWindowsInstaller(file)
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		_ = locked.Close()
		t.Fatal("installer allowed a writer during verification")
	}
	if err := os.Rename(path, filepath.Join(dir, "renamed.exe")); err == nil {
		_ = locked.Close()
		t.Fatal("installer could be renamed during verification")
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if locked, err := LockWindowsInstaller(file); err != ErrArtifact {
		if locked != nil {
			_ = locked.Close()
		}
		t.Fatalf("existing writer allowed verification: %v", err)
	}
}
