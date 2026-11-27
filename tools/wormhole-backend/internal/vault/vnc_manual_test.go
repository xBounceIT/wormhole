package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
)

func manualVNCBinding() BundleBinding {
	return BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), Protocol: "vnc", Host: "server.example", Port: 5900, Epoch: 1}
}
func TestVNCManualPurposeAndAuthorization(t *testing.T) {
	for _, routed := range []bool{false, true} {
		b := manualVNCBinding()
		var route *TunnelBundleBinding
		endpoint := ""
		if routed {
			b.TunnelConfigID = uuid.NewString()
			route = &TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 2, ConfigurationVersion: 1}
			endpoint = "127.0.0.1:2345"
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, password := range [][]byte{nil, []byte("one-use-password"), {0, 255, 1}, bytes.Repeat([]byte("x"), MaxVNCPasswordBytes)} {
			inner, err := SealManualVNCPassword(key.PublicKey().Bytes(), b, route, endpoint, password)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := EncodeVNCManualAuthorization(inner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeVNCBundle(auth); err == nil {
				t.Fatal("manual authorization interpreted as saved password")
			}
			borrowed, err := DecodeVNCManualAuthorization(auth)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := OpenManualVNCPassword(key.Bytes(), b, route, endpoint, borrowed)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := DecodeVNCBundle(plaintext)
			if err != nil || !payload.PasswordProvided || !bytes.Equal(payload.Password, password) {
				t.Fatal("manual password lost", err)
			}
			Wipe(plaintext)
			// A purpose swap cannot open a manual password as a saved credential.
			if _, err := OpenBundle(key.Bytes(), b, inner); err == nil {
				t.Fatal("purpose substitution")
			}
			bad := b
			bad.Host = "redirect.example"
			if _, err := OpenManualVNCPassword(key.Bytes(), bad, route, endpoint, inner); err == nil {
				t.Fatal("target substitution")
			}
			if routed {
				if _, err := OpenManualVNCPassword(key.Bytes(), b, route, "127.0.0.1:2346", inner); err == nil {
					t.Fatal("endpoint substitution")
				}
			}
			Wipe(auth)
			if !bytes.Equal(borrowed.Enc, make([]byte, 32)) || !bytes.Equal(borrowed.Ciphertext, make([]byte, len(borrowed.Ciphertext))) {
				t.Fatal("decoder copied borrowed ciphertext")
			}
		}
	}
}
func TestVNCManualBoundsAndContexts(t *testing.T) {
	b := manualVNCBinding()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	good, _ := SealManualVNCPassword(key.PublicKey().Bytes(), b, nil, "", nil)
	raw, _ := EncodeVNCManualAuthorization(good)
	for i := 0; i < len(raw); i++ {
		if _, err := DecodeVNCManualAuthorization(raw[:i]); err == nil {
			t.Fatal("truncated authorization accepted")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), func() []byte { x := bytes.Clone(raw); x[0] = 1; return x }(), func() []byte { x := bytes.Clone(raw); binary.BigEndian.PutUint32(x[33:37], 0); return x }(), make([]byte, 38+MaxVNCManualCiphertext)} {
		if _, err := DecodeVNCManualAuthorization(bad); err == nil {
			t.Fatal("invalid authorization accepted")
		}
	}
	for _, change := range []func(*SealedBundle){func(s *SealedBundle) { s.FormatVersion = 2 }, func(s *SealedBundle) { s.SuiteID = 3 }, func(s *SealedBundle) { s.Enc = nil }, func(s *SealedBundle) { s.Ciphertext = make([]byte, 21) }, func(s *SealedBundle) { s.Ciphertext = make([]byte, MaxVNCManualCiphertext+1) }} {
		bad := good
		change(&bad)
		if _, err := EncodeVNCManualAuthorization(bad); err == nil {
			t.Fatal("invalid envelope encoded")
		}
		if _, err := OpenManualVNCPassword(key.Bytes(), b, nil, "", bad); err == nil {
			t.Fatal("invalid envelope opened")
		}
	}
	for _, change := range []func(*BundleBinding){func(b *BundleBinding) { b.WorkspaceID = "bad" }, func(b *BundleBinding) { b.NodeID = uuid.Nil.String() }, func(b *BundleBinding) { b.Protocol = "ssh" }, func(b *BundleBinding) { b.UseExternalClient = true }, func(b *BundleBinding) { b.Host = "bad host" }, func(b *BundleBinding) { b.Host = "" }, func(b *BundleBinding) { b.Port = 0 }, func(b *BundleBinding) { b.Epoch = 0 }, func(b *BundleBinding) { b.Epoch = 9007199254740992 }, func(b *BundleBinding) { b.TunnelConfigID = uuid.NewString() }} {
		bad := b
		change(&bad)
		if _, err := SealManualVNCPassword(key.PublicKey().Bytes(), bad, nil, "", nil); err == nil {
			t.Fatal("bad context sealed")
		}
		if _, err := OpenManualVNCPassword(key.Bytes(), bad, nil, "", good); err == nil {
			t.Fatal("bad context opened")
		}
	}
	if _, err := SealManualVNCPassword(key.PublicKey().Bytes(), b, nil, "127.0.0.1:1", nil); err == nil {
		t.Fatal("direct endpoint accepted")
	}
	if _, err := SealManualVNCPassword(key.PublicKey().Bytes(), b, nil, "", make([]byte, MaxVNCPasswordBytes+1)); err == nil {
		t.Fatal("oversized password accepted")
	}
	route := TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 1, ConfigurationVersion: 1}
	if _, err := SealManualVNCPassword(key.PublicKey().Bytes(), b, &route, "127.0.0.1:1", nil); err == nil {
		t.Fatal("route without tunnel accepted")
	}
	route.TunnelConfigID = uuid.NewString()
	if _, err := SealManualVNCPassword(key.PublicKey().Bytes(), b, &route, "127.0.0.1:1", nil); err == nil {
		t.Fatal("mismatched route accepted")
	}
	rawAbsent, _ := EncodeVNCBundle(VNCBundlePayload{})
	defer Wipe(rawAbsent)
	info, _ := manualVNCInfo(b, nil, "")
	absent, _ := sealBundlePayload(key.PublicKey().Bytes(), info, rawAbsent)
	if _, err := OpenManualVNCPassword(key.Bytes(), b, nil, "", absent); err == nil {
		t.Fatal("manual envelope omitted explicit password")
	}
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenManualVNCPassword(wrong.Bytes(), b, nil, "", good); err == nil {
		t.Fatal("wrong recipient accepted")
	}
}

func TestVNCManualCanonicalPurposeFields(t *testing.T) {
	b := BundleBinding{WorkspaceID: "11111111-1111-4111-8111-111111111111", NodeID: "22222222-2222-4222-8222-222222222222", SessionID: "33333333-3333-4333-8333-333333333333", RequestID: "44444444-4444-4444-8444-444444444444", Protocol: "vnc", Host: "café.example", Port: 5900, Epoch: 3}
	for _, routed := range []bool{false, true} {
		var route *TunnelBundleBinding
		endpoint := ""
		fields := []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID, "vnc", "café.example", "5900", "", "3", "", "", "", "", ""}
		if routed {
			b.TunnelConfigID = "55555555-5555-4555-8555-555555555555"
			endpoint = "127.0.0.1:2345"
			route = &TunnelBundleBinding{BundleBinding: b, FileID: "66666666-6666-4666-8666-666666666666", Kind: 6, RowVersion: 2, ConfigurationVersion: 1}
			fields[7] = b.TunnelConfigID
			copy(fields[9:], []string{route.FileID, "6", "2", "1", endpoint})
		}
		var expected bytes.Buffer
		expected.WriteString("wormhole/v1/vnc-manual-password")
		for _, field := range fields {
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(len([]byte(field))))
			expected.Write(size[:])
			expected.WriteString(field)
		}
		info, err := manualVNCInfo(b, route, endpoint)
		if err != nil || !bytes.Equal(info, expected.Bytes()) {
			t.Fatal("manual purpose field order/UTF-8 framing drift", err)
		}
	}
}
