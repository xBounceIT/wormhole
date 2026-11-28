package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"github.com/google/uuid"
	"math"
	"strings"
	"testing"
)

func tunnelBindingFixture() TunnelBundleBinding {
	return TunnelBundleBinding{BundleBinding: BundleBinding{WorkspaceID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: uuid.NewString(), Protocol: "ssh", Host: "host.example", Port: 22, TunnelConfigID: uuid.NewString(), Epoch: 1}, FileID: uuid.NewString(), Kind: 1, RowVersion: 3, ConfigurationVersion: 2}
}
func TestTunnelBundleRoundTripBindingAndDomain(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := tunnelBindingFixture()
	plain := []byte(`{"ProfileOvpn":"private-route"}`)
	sealed, err := SealTunnelBundle(key.PublicKey().Bytes(), b, plain)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := OpenTunnelBundle(key.Bytes(), b, sealed)
	if err != nil || !bytes.Equal(raw, plain) {
		t.Fatal("round trip", err)
	}
	Wipe(raw)
	for _, change := range []func(*TunnelBundleBinding){
		func(b *TunnelBundleBinding) { b.WorkspaceID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.FileID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.SessionID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.RequestID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.NodeID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.TunnelConfigID = uuid.NewString() }, func(b *TunnelBundleBinding) { b.Protocol = "sftp" }, func(b *TunnelBundleBinding) { b.Host = "other.example" }, func(b *TunnelBundleBinding) { b.Port++ }, func(b *TunnelBundleBinding) { b.Epoch++ }, func(b *TunnelBundleBinding) { b.Kind++ }, func(b *TunnelBundleBinding) { b.RowVersion++ }, func(b *TunnelBundleBinding) { b.ConfigurationVersion = 1 },
	} {
		bad := b
		change(&bad)
		if value, e := OpenTunnelBundle(key.Bytes(), bad, sealed); e == nil || value != nil {
			t.Fatal("binding substitution")
		}
	}
	if _, e := OpenBundle(key.Bytes(), b.BundleBinding, sealed); e == nil {
		t.Fatal("tunnel accepted as protocol")
	}
	protocol, _ := SealBundle(key.PublicKey().Bytes(), b.BundleBinding, plain)
	if _, e := OpenTunnelBundle(key.Bytes(), b, protocol); e == nil {
		t.Fatal("protocol accepted as tunnel")
	}
	for kind := uint16(0); kind <= 9; kind++ {
		for _, protocol := range []string{"ssh", "sftp", "rdp", "vnc", "http", "https"} {
			b.Kind, b.Protocol = kind, protocol
			s, e := SealTunnelBundle(key.PublicKey().Bytes(), b, plain)
			if e != nil {
				t.Fatal(e)
			}
			p, e := OpenTunnelBundle(key.Bytes(), b, s)
			if e != nil || !bytes.Equal(p, plain) {
				t.Fatal(e)
			}
			Wipe(p)
		}
	}
	b.RowVersion = math.MaxInt64
	b.ConfigurationVersion = b.RowVersion
	encoded, _ := json.Marshal(b)
	if !bytes.Contains(encoded, []byte(`"rowVersion":"9223372036854775807"`)) || !bytes.Contains(encoded, []byte(`"configurationVersion":"9223372036854775807"`)) {
		t.Fatal("lossy JSON revision")
	}
}
func TestTunnelBundleRejectsInvalidContextAndEnvelope(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := tunnelBindingFixture()
	plain := []byte("settings")
	sealed, _ := SealTunnelBundle(key.PublicKey().Bytes(), b, plain)
	for _, change := range []func(*TunnelBundleBinding){
		func(b *TunnelBundleBinding) { b.WorkspaceID = "bad" }, func(b *TunnelBundleBinding) { b.FileID = uuid.Nil.String() }, func(b *TunnelBundleBinding) { b.SessionID = "" }, func(b *TunnelBundleBinding) { b.RequestID = "bad" }, func(b *TunnelBundleBinding) { b.NodeID = "bad" }, func(b *TunnelBundleBinding) { b.TunnelConfigID = "" }, func(b *TunnelBundleBinding) { b.Protocol = "serial" }, func(b *TunnelBundleBinding) { b.UseExternalClient = true }, func(b *TunnelBundleBinding) { b.Port = 0 }, func(b *TunnelBundleBinding) { b.Host = "" }, func(b *TunnelBundleBinding) { b.Host = "bad host" }, func(b *TunnelBundleBinding) { b.Host = "bad\x00" }, func(b *TunnelBundleBinding) { b.Host = "\xff" }, func(b *TunnelBundleBinding) { b.Host = strings.Repeat("x", MaxContextBytes+1) }, func(b *TunnelBundleBinding) { b.Kind = 10 }, func(b *TunnelBundleBinding) { b.RowVersion = 0 }, func(b *TunnelBundleBinding) { b.RowVersion = math.MaxInt64 + 1 }, func(b *TunnelBundleBinding) { b.ConfigurationVersion = 0 }, func(b *TunnelBundleBinding) { b.ConfigurationVersion = 4 }, func(b *TunnelBundleBinding) { b.Epoch = 0 }, func(b *TunnelBundleBinding) { b.Epoch = 1 << 53 },
	} {
		bad := b
		change(&bad)
		if _, e := SealTunnelBundle(key.PublicKey().Bytes(), bad, plain); e == nil {
			t.Fatal("bad context sealed")
		}
		if _, e := OpenTunnelBundle(key.Bytes(), bad, sealed); e == nil {
			t.Fatal("bad context opened")
		}
	}
	for _, p := range [][]byte{nil, {}, make([]byte, MaxSecretBytes+1)} {
		if _, e := SealTunnelBundle(key.PublicKey().Bytes(), b, p); e == nil {
			t.Fatal("bad size")
		}
	}
	for _, pub := range [][]byte{nil, make([]byte, 32)} {
		if _, e := SealTunnelBundle(pub, b, plain); e == nil {
			t.Fatal("invalid recipient")
		}
	}
	for _, change := range []func(*SealedBundle){func(s *SealedBundle) { s.FormatVersion++ }, func(s *SealedBundle) { s.FormatVersion = 0 }, func(s *SealedBundle) { s.SuiteID = 0 }, func(s *SealedBundle) { s.Enc = nil }, func(s *SealedBundle) { s.Ciphertext = nil }, func(s *SealedBundle) { s.Ciphertext = make([]byte, MaxSecretBytes+17) }, func(s *SealedBundle) { s.Ciphertext = bytes.Clone(s.Ciphertext); s.Ciphertext[0] ^= 1 }} {
		bad := sealed
		change(&bad)
		if p, e := OpenTunnelBundle(key.Bytes(), b, bad); e == nil || p != nil {
			t.Fatal("bad envelope")
		}
	}
	if _, e := OpenTunnelBundle(nil, b, sealed); e == nil {
		t.Fatal("invalid private key")
	}
	info, _ := b.info()
	empty, _ := sealBundlePayload(key.PublicKey().Bytes(), info, nil)
	if _, e := OpenTunnelBundle(key.Bytes(), b, empty); e != ErrFormat {
		t.Fatal("empty payload", e)
	}
	max := make([]byte, MaxSecretBytes)
	s, e := SealTunnelBundle(key.PublicKey().Bytes(), b, max)
	if e != nil {
		t.Fatal(e)
	}
	p, e := OpenTunnelBundle(key.Bytes(), b, s)
	if e != nil || len(p) != MaxSecretBytes {
		t.Fatal("max", e)
	}
	Wipe(p)
}
