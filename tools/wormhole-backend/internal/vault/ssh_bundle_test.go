package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func sshPayloadFixture() SSHBundlePayload {
	return SSHBundlePayload{Username: "alice-🧪", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), AutoSudo: true,
		Password: []byte("password"), PrivateKey: []byte("key"), Passphrase: []byte("passphrase"), Certificate: []byte("certificate")}
}

func TestSSHBundleBinaryRoundTripAndBorrow(t *testing.T) {
	p := sshPayloadFixture()
	raw, err := EncodeSSHBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSSHBundle(raw)
	if err != nil || got.Username != p.Username || got.Fingerprint != p.Fingerprint || !got.AutoSudo || !bytes.Equal(got.Password, p.Password) || !bytes.Equal(got.PrivateKey, p.PrivateKey) || !bytes.Equal(got.Passphrase, p.Passphrase) || !bytes.Equal(got.Certificate, p.Certificate) {
		t.Fatal("round trip failed", err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := DecodeSSHBundle(raw[:n]); err == nil {
			t.Fatal("accepted truncated field", n)
		}
	}
	Wipe(raw)
	for _, v := range [][]byte{got.Password, got.PrivateKey, got.Passphrase, got.Certificate} {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("secret is not a borrowed frame slice")
		}
	}
}

func TestSSHBundleBinaryRejectsInvalidAndOversized(t *testing.T) {
	for _, mutate := range []func(*SSHBundlePayload){func(p *SSHBundlePayload) { p.Username = "" }, func(p *SSHBundlePayload) { p.Username = "bad\n" }, func(p *SSHBundlePayload) { p.Username = "\xff" }, func(p *SSHBundlePayload) { p.Username = strings.Repeat("x", 2049) }, func(p *SSHBundlePayload) { p.Fingerprint = "" }, func(p *SSHBundlePayload) { p.Fingerprint += "=" }, func(p *SSHBundlePayload) { p.Password = nil; p.PrivateKey = nil }, func(p *SSHBundlePayload) { p.PrivateKey = make([]byte, MaxSecretBytes) }} {
		p := sshPayloadFixture()
		mutate(&p)
		if out, err := EncodeSSHBundle(p); err == nil || out != nil {
			t.Fatal("invalid payload encoded")
		}
	}
	p := sshPayloadFixture()
	p.AutoSudo = false
	raw, _ := EncodeSSHBundle(p)
	for _, mutate := range []func([]byte) []byte{func(b []byte) []byte { b[0] = 2; return b }, func(b []byte) []byte { b[1] = 2; return b }, func(b []byte) []byte { binary.BigEndian.PutUint32(b[2:], 0xffffffff); return b }, func(b []byte) []byte { return append(b, 0) }, func(b []byte) []byte { b[6] = 0; return b }, func(b []byte) []byte { return make([]byte, MaxSecretBytes+1) }} {
		if _, err := DecodeSSHBundle(mutate(bytes.Clone(raw))); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	p.PrivateKey = make([]byte, MaxSecretBytes-len(raw)+len(p.PrivateKey))
	raw, err := EncodeSSHBundle(p)
	if err != nil || len(raw) != MaxSecretBytes {
		t.Fatal("exact limit", len(raw), err)
	}
	if _, err := DecodeSSHBundle(raw); err != nil {
		t.Fatal(err)
	}
}
func TestSSHFileOnlyPayloadVersionAndBorrow(t *testing.T) {
	p := sshPayloadFixture()
	p.AutoSudo = false
	p.SFTPOnly = true
	raw, err := EncodeSSHBundle(p)
	if err != nil || raw[0] != 2 || raw[1] != 2 {
		t.Fatal("missing versioned file mode", err)
	}
	got, err := DecodeSSHBundle(raw)
	if err != nil || !got.SFTPOnly || got.AutoSudo {
		t.Fatal("file mode lost", err)
	}
	Wipe(raw)
	if !bytes.Equal(got.Password, make([]byte, len(got.Password))) {
		t.Fatal("file credentials not borrowed")
	}
	p.AutoSudo = true
	if _, err := EncodeSSHBundle(p); err != ErrPolicy {
		t.Fatal("SFTP auto-sudo accepted", err)
	}
	for _, header := range [][2]byte{{1, 2}, {2, 0}, {2, 1}, {2, 3}, {3, 2}} {
		p.AutoSudo = false
		raw, _ = EncodeSSHBundle(p)
		raw[0], raw[1] = header[0], header[1]
		if _, err := DecodeSSHBundle(raw); err == nil {
			t.Fatal("noncanonical mode version accepted", header)
		}
	}
}
