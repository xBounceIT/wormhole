package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func manualSSHContext() SSHManualContext {
	b := manualVNCBinding()
	b.Protocol, b.Port = "ssh", 22
	return SSHManualContext{Binding: b, Mode: "account", FileID: uuid.NewString(), Revision: strings.Repeat("a", 64), Fingerprint: sshPayloadFixture().Fingerprint}
}

func TestSSHManualEnvelopeBindingsAndNoSavedFallback(t *testing.T) {
	for _, protocol := range []string{"ssh", "sftp"} {
		for _, routed := range []bool{false, true} {
			for _, mode := range []string{"account", "passphrase"} {
				c := manualSSHContext()
				c.Binding.Protocol, c.Mode, c.SFTPOnly = protocol, mode, protocol == "sftp"
				if routed {
					c.Binding.TunnelConfigID = uuid.NewString()
					c.Route = &TunnelBundleBinding{BundleBinding: c.Binding, FileID: c.FileID, Kind: 6, RowVersion: 2, ConfigurationVersion: 1}
					c.Endpoint = "127.0.0.1:2345"
				}
				key, _ := ecdh.X25519().GenerateKey(rand.Reader)
				inputs := []SSHBundlePayload{{Username: "例\\user", Fingerprint: c.Fingerprint, Password: []byte("temporary-password")}, {Username: "u", Fingerprint: c.Fingerprint, PrivateKey: []byte("temporary-key"), Passphrase: []byte("key-password"), Certificate: []byte("certificate")}}
				if mode == "passphrase" {
					inputs = []SSHBundlePayload{{}, {Passphrase: []byte("explicit-override")}}
				}
				for _, input := range inputs {
					inner, err := SealManualSSHCredentials(key.PublicKey().Bytes(), c, input)
					if err != nil {
						t.Fatal(err)
					}
					base := SSHBundlePayload{Fingerprint: c.Fingerprint, SFTPOnly: c.SFTPOnly, AutoSudo: !c.SFTPOnly}
					if mode == "passphrase" {
						base.Username, base.PrivateKey, base.Certificate = "saved-user", []byte("saved-key"), []byte("saved-certificate")
					}
					c.AutoSudo = base.AutoSudo
					// Native flags are part of the authenticated document context.
					inner, err = SealManualSSHCredentials(key.PublicKey().Bytes(), c, input)
					if err != nil {
						t.Fatal(err)
					}
					a := SSHManualAuthorization{Mode: mode, FileID: c.FileID, Revision: c.Revision, Base: base, Manual: inner}
					outer, err := EncodeSSHManualAuthorization(a)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = DecodeSSHBundle(outer); err == nil {
						t.Fatal("manual authorization became saved credentials")
					}
					decoded, err := DecodeSSHManualAuthorization(outer)
					roundTrip, encodeErr := EncodeSSHManualAuthorization(decoded)
					if err != nil || encodeErr != nil || !bytes.Equal(roundTrip, outer) {
						t.Fatal("authorization changed", err)
					}
					Wipe(roundTrip)
					raw, err := OpenManualSSHCredentials(key.Bytes(), c, decoded.Manual)
					if err != nil {
						t.Fatal(err)
					}
					payload, err := DecodeSSHManualCredentials(c, raw)
					if err != nil || !bytes.Equal(payload.Password, input.Password) || !bytes.Equal(payload.Passphrase, input.Passphrase) || !bytes.Equal(payload.PrivateKey, input.PrivateKey) || payload.Username != input.Username {
						t.Fatal("manual input changed", err)
					}
					Wipe(raw)
					for _, secret := range [][]byte{payload.Password, payload.PrivateKey, payload.Passphrase, payload.Certificate} {
						if !bytes.Equal(secret, make([]byte, len(secret))) {
							t.Fatal("decoded secret not borrowed")
						}
					}
					for _, edit := range []func(*SSHManualContext){func(v *SSHManualContext) {
						v.Mode = "passphrase"
						if mode == "passphrase" {
							v.Mode = "account"
						}
					}, func(v *SSHManualContext) { v.Fingerprint = "SHA256:" + strings.Repeat("A", 42) + "E" }, func(v *SSHManualContext) { v.FileID = uuid.NewString() }, func(v *SSHManualContext) { v.Revision = strings.Repeat("b", 64) }, func(v *SSHManualContext) { v.Binding.SessionID = uuid.NewString() }, func(v *SSHManualContext) { v.AutoSudo = !v.AutoSudo }, func(v *SSHManualContext) { v.SFTPOnly = !v.SFTPOnly }} {
						bad := c
						edit(&bad)
						if _, err = OpenManualSSHCredentials(key.Bytes(), bad, inner); err == nil {
							t.Fatal("context substitution")
						}
					}
					if _, err = OpenBundle(key.Bytes(), c.Binding, inner); err == nil {
						t.Fatal("purpose substitution")
					}
					if routed {
						bad := c
						bad.Endpoint = "127.0.0.1:2346"
						if _, err = OpenManualSSHCredentials(key.Bytes(), bad, inner); err == nil {
							t.Fatal("endpoint substitution")
						}
					}
					Wipe(outer)
					if !bytes.Equal(decoded.Manual.Ciphertext, make([]byte, len(decoded.Manual.Ciphertext))) {
						t.Fatal("envelope not borrowed")
					}
				}
			}
		}
	}
}

func TestSSHManualRejectsMalformedAndMixedAuthority(t *testing.T) {
	c := manualSSHContext()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	p := SSHBundlePayload{Username: "user", Fingerprint: c.Fingerprint, Password: []byte("password")}
	inner, err := SealManualSSHCredentials(key.PublicKey().Bytes(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	base := SSHManualAuthorization{Mode: "account", FileID: c.FileID, Revision: c.Revision, Base: SSHBundlePayload{Fingerprint: c.Fingerprint}, Manual: inner}
	for _, edit := range []func(*SSHManualContext){func(v *SSHManualContext) { v.Mode = "bad" }, func(v *SSHManualContext) { v.Binding.Protocol = "rdp" }, func(v *SSHManualContext) { v.FileID = "bad" }, func(v *SSHManualContext) { v.FileID = uuid.Nil.String() }, func(v *SSHManualContext) { v.Revision = "AA" }, func(v *SSHManualContext) { v.Revision = strings.Repeat("A", 64) }, func(v *SSHManualContext) { v.Fingerprint = "bad" }, func(v *SSHManualContext) { v.Binding.NodeID = "bad" }} {
		bad := c
		edit(&bad)
		if _, err = SealManualSSHCredentials(key.PublicKey().Bytes(), bad, p); err == nil {
			t.Fatal("invalid context")
		}
		if _, err = OpenManualSSHCredentials(key.Bytes(), bad, inner); err == nil {
			t.Fatal("invalid open context")
		}
	}
	for _, edit := range []func(*SSHBundlePayload){func(v *SSHBundlePayload) { v.Username = "" }, func(v *SSHBundlePayload) { v.Fingerprint = "bad" }, func(v *SSHBundlePayload) { v.AutoSudo = true }, func(v *SSHBundlePayload) { v.SFTPOnly = true }, func(v *SSHBundlePayload) { v.Password = make([]byte, 16385) }, func(v *SSHBundlePayload) { v.Passphrase = []byte("unexpected") }, func(v *SSHBundlePayload) { v.PrivateKey = []byte("mixed") }, func(v *SSHBundlePayload) { v.PrivateKey = make([]byte, 1024*1024+1) }} {
		bad := p
		edit(&bad)
		if _, err = SealManualSSHCredentials(key.PublicKey().Bytes(), c, bad); err == nil {
			t.Fatal("invalid account")
		}
		if raw, e := EncodeSSHBundle(bad); e == nil {
			if _, err = DecodeSSHManualCredentials(c, raw); err == nil {
				t.Fatal("invalid decoded account")
			}
		}
	}
	pass := c
	pass.Mode = "passphrase"
	if _, err = SealManualSSHCredentials(key.PublicKey().Bytes(), pass, p); err == nil {
		t.Fatal("account in passphrase envelope")
	}
	if _, err = SealManualSSHCredentials(key.PublicKey().Bytes(), pass, SSHBundlePayload{Passphrase: make([]byte, 16385)}); err == nil {
		t.Fatal("oversized passphrase")
	}
	for _, edit := range []func(*SSHManualAuthorization){func(v *SSHManualAuthorization) { v.Mode = "bad" }, func(v *SSHManualAuthorization) { v.FileID = "bad" }, func(v *SSHManualAuthorization) { v.Revision = "bad" }, func(v *SSHManualAuthorization) { v.Base.Username = "saved" }, func(v *SSHManualAuthorization) { v.Base.Password = []byte("saved") }, func(v *SSHManualAuthorization) { v.Base.Passphrase = []byte("saved") }, func(v *SSHManualAuthorization) { v.Base.Fingerprint = "bad" }, func(v *SSHManualAuthorization) { v.Base.PrivateKey = []byte("saved") }, func(v *SSHManualAuthorization) { v.Base.SFTPOnly = true; v.Base.AutoSudo = true }, func(v *SSHManualAuthorization) { v.Mode = "passphrase" }, func(v *SSHManualAuthorization) { v.Manual = SealedBundle{} }, func(v *SSHManualAuthorization) { v.Manual.Ciphertext = make([]byte, 21) }, func(v *SSHManualAuthorization) { v.Manual.Ciphertext = make([]byte, MaxSSHManualCiphertext+1) }} {
		bad := base
		edit(&bad)
		if _, err = EncodeSSHManualAuthorization(bad); err == nil {
			t.Fatal("mixed/invalid authority")
		}
	}
	outer, _ := EncodeSSHManualAuthorization(base)
	for i := 0; i < len(outer); i++ {
		if _, err = DecodeSSHManualAuthorization(outer[:i]); err == nil {
			t.Fatal("truncated outer", i)
		}
	}
	for _, edit := range []func([]byte) []byte{func(v []byte) []byte { v[0] = 1; return v }, func(v []byte) []byte { v[1] = 0; return v }, func(v []byte) []byte { v[2] = 3; return v }, func(v []byte) []byte { binary.BigEndian.PutUint32(v[3:7], 0xffffffff); return v }, func(v []byte) []byte { return append(v, 0) }} {
		if _, err = DecodeSSHManualAuthorization(edit(bytes.Clone(outer))); err == nil {
			t.Fatal("malformed outer")
		}
	}
	for _, v := range [][]byte{nil, {1, 1}, {1, 2, 0, 0, 0, 1}, append([]byte{1, 2, 0, 0, 0, 0}, 0)} {
		if _, err = DecodeSSHManualCredentials(pass, v); err == nil {
			t.Fatal("malformed passphrase")
		}
	}
	if _, err = DecodeSSHManualCredentials(c, []byte("bad")); err == nil {
		t.Fatal("malformed account")
	}
	if _, err = OpenManualSSHCredentials(key.Bytes(), c, SealedBundle{}); err == nil {
		t.Fatal("bad envelope")
	}
	info, _ := c.info()
	bad, _ := sealBundlePayload(key.PublicKey().Bytes(), info, bytes.Repeat([]byte("bad"), 20))
	if _, err = OpenManualSSHCredentials(key.Bytes(), c, bad); err == nil {
		t.Fatal("authenticated malformed input")
	}
	inner.Ciphertext[0] ^= 1
	if _, err = OpenManualSSHCredentials(key.Bytes(), c, inner); err == nil {
		t.Fatal("tampered ciphertext")
	}
	if _, err = SealManualSSHCredentials(make([]byte, 32), c, p); err == nil {
		t.Fatal("invalid public key")
	}
}
