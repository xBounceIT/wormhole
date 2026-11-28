package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"testing"
)

func authFixture() TunnelAuthenticationBinding {
	b := tunnelBindingFixture()
	b.Kind = 9
	return TunnelAuthenticationBinding{Route: b, ChallengeID: uuid.NewString(), UsernameRequired: true}
}
func TestTunnelAuthenticationFrameAndPurpose(t *testing.T) {
	b := authFixture()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	s, err := SealTunnelAuthentication(key.PublicKey().Bytes(), b, []byte("user"), []byte("fresh password"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := OpenTunnelAuthentication(key.Bytes(), b, s)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(raw)
	p, err := DecodeTunnelAuthentication(raw, true)
	if err != nil || string(p.Username) != "user" || string(p.Password) != "fresh password" {
		t.Fatal("frame", err)
	}
	for _, change := range []func(*TunnelAuthenticationBinding){func(v *TunnelAuthenticationBinding) { v.ChallengeID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.UsernameRequired = false }, func(v *TunnelAuthenticationBinding) { v.Route.WorkspaceID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.FileID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.NodeID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.SessionID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.RequestID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.Host = "other" }, func(v *TunnelAuthenticationBinding) { v.Route.Port++ }, func(v *TunnelAuthenticationBinding) { v.Route.Protocol = "rdp" }, func(v *TunnelAuthenticationBinding) { v.Route.Epoch++ }, func(v *TunnelAuthenticationBinding) { v.Route.TunnelConfigID = uuid.NewString() }, func(v *TunnelAuthenticationBinding) { v.Route.RowVersion++ }, func(v *TunnelAuthenticationBinding) { v.Route.ConfigurationVersion++ }} {
		changed := b
		change(&changed)
		if raw, err := OpenTunnelAuthentication(key.Bytes(), changed, s); err == nil || raw != nil {
			t.Fatal("context substitution")
		}
	}
	if _, err := OpenTunnelBundle(key.Bytes(), b.Route, s); err == nil {
		t.Fatal("factor opened as configuration")
	}
	config, _ := SealTunnelBundle(key.PublicKey().Bytes(), b.Route, []byte("configuration"))
	if _, err := OpenTunnelAuthentication(key.Bytes(), b, config); err == nil {
		t.Fatal("configuration opened as factor")
	}
	for _, invalid := range []TunnelAuthenticationBinding{{Route: b.Route, ChallengeID: "bad"}, {Route: b.Route, ChallengeID: uuid.Nil.String()}, {Route: tunnelBindingFixture(), ChallengeID: b.ChallengeID}, {ChallengeID: b.ChallengeID}} {
		if _, err := SealTunnelAuthentication(key.PublicKey().Bytes(), invalid, []byte("u"), []byte("p")); err == nil {
			t.Fatal("invalid binding")
		}
	}
	b.UsernameRequired = false
	s, err = SealTunnelAuthentication(key.PublicKey().Bytes(), b, nil, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = OpenTunnelAuthentication(key.Bytes(), b, s)
	if err != nil {
		t.Fatal(err)
	}
	Wipe(raw)
	if _, err := SealTunnelAuthentication(key.PublicKey().Bytes(), b, []byte("override"), []byte("password")); err == nil {
		t.Fatal("fixed identity changed")
	}
	for _, invalid := range []SealedBundle{{}, {FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, 26)}, {FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, MaxTunnelAuthenticationCiphertext+1)}} {
		if _, err := OpenTunnelAuthentication(key.Bytes(), b, invalid); err == nil {
			t.Fatal("unbounded envelope")
		}
	}
	info, _ := b.info()
	malformed, _ := sealBundlePayload(key.PublicKey().Bytes(), info, make([]byte, 11))
	if raw, err := OpenTunnelAuthentication(key.Bytes(), b, malformed); err == nil || raw != nil {
		t.Fatal("invalid authenticated plaintext")
	}
}
func TestTunnelAuthenticationFrameBounds(t *testing.T) {
	for _, v := range []struct {
		u, p     []byte
		required bool
	}{{nil, nil, false}, {[]byte(" "), []byte("p"), true}, {[]byte("u\n"), []byte("p"), true}, {[]byte("u"), []byte{255}, true}, {nil, []byte("p\x00"), false}, {bytes.Repeat([]byte("u"), 4097), []byte("p"), true}, {nil, bytes.Repeat([]byte("p"), 4097), false}} {
		if raw, err := EncodeTunnelAuthentication(v.u, v.p, v.required); err == nil || raw != nil {
			t.Fatal("invalid input")
		}
	}
	raw, err := EncodeTunnelAuthentication([]byte("user"), []byte("password"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func([]byte) []byte{func(b []byte) []byte { return nil }, func(b []byte) []byte { return b[:10] }, func(b []byte) []byte { b[0] = 2; return b }, func(b []byte) []byte { b[1] = 2; return b }, func(b []byte) []byte { binary.BigEndian.PutUint32(b[2:6], 0xffffffff); return b }, func(b []byte) []byte { return append(b, 0) }, func(b []byte) []byte { return make([]byte, MaxTunnelAuthenticationCiphertext) }} {
		if _, err := DecodeTunnelAuthentication(change(bytes.Clone(raw)), true); err == nil {
			t.Fatal("invalid frame")
		}
	}
	if _, err := DecodeTunnelAuthentication(raw, false); err == nil {
		t.Fatal("username shape changed")
	}
	max := bytes.Repeat([]byte("x"), 4096)
	encoded, err := EncodeTunnelAuthentication(max, max, true)
	if err != nil {
		t.Fatal(err)
	}
	Wipe(encoded)
}
