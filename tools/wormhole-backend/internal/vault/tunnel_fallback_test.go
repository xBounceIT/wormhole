package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"math"
	"testing"

	"github.com/google/uuid"
)

func tunnelFallbackFixture() TunnelFallbackBinding {
	p := tunnelBindingFixture()
	p.Kind = 9
	f := p
	f.Kind, f.TunnelConfigID, f.RequestID = 2, uuid.NewString(), uuid.NewString()
	f.RowVersion, f.ConfigurationVersion = 11, 5
	return TunnelFallbackBinding{Primary: p, Fallback: f}
}

func TestTunnelFallbackBindsBothSourcesAndIndependentPurpose(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := tunnelFallbackFixture()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"Host":"ssl.example","Password":"synthetic-secret"}`)
	sealed, err := SealTunnelFallback(key.PublicKey().Bytes(), b, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTunnelFallback(key.Bytes(), b, sealed)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("fallback round trip", err)
	}
	Wipe(opened)
	for _, mutate := range []func(*TunnelBundleBinding){
		func(b *TunnelBundleBinding) { b.RequestID = uuid.NewString() },
		func(b *TunnelBundleBinding) { b.TunnelConfigID = uuid.NewString() },
		func(b *TunnelBundleBinding) { b.RowVersion++ },
		func(b *TunnelBundleBinding) { b.ConfigurationVersion-- },
	} {
		for _, primary := range []bool{false, true} {
			bad := b
			if primary {
				mutate(&bad.Primary)
			} else {
				mutate(&bad.Fallback)
			}
			if value, err := OpenTunnelFallback(key.Bytes(), bad, sealed); err == nil || value != nil {
				t.Fatal("source identity/revision substitution admitted")
			}
		}
	}
	// Changing a common field coherently in both sources is still substitution.
	for _, mutate := range []func(*TunnelFallbackBinding){
		func(b *TunnelFallbackBinding) {
			b.Primary.WorkspaceID = uuid.NewString()
			b.Fallback.WorkspaceID = b.Primary.WorkspaceID
		},
		func(b *TunnelFallbackBinding) {
			b.Primary.FileID = uuid.NewString()
			b.Fallback.FileID = b.Primary.FileID
		},
		func(b *TunnelFallbackBinding) {
			b.Primary.NodeID = uuid.NewString()
			b.Fallback.NodeID = b.Primary.NodeID
		},
		func(b *TunnelFallbackBinding) {
			b.Primary.SessionID = uuid.NewString()
			b.Fallback.SessionID = b.Primary.SessionID
		},
		func(b *TunnelFallbackBinding) { b.Primary.Protocol, b.Fallback.Protocol = "sftp", "sftp" },
		func(b *TunnelFallbackBinding) { b.Primary.Host, b.Fallback.Host = "other.example", "other.example" },
		func(b *TunnelFallbackBinding) { b.Primary.Port++; b.Fallback.Port++ },
		func(b *TunnelFallbackBinding) { b.Primary.Epoch++; b.Fallback.Epoch++ },
	} {
		bad := b
		mutate(&bad)
		if _, err := bad.info(); err != nil {
			t.Fatal("substitution fixture is not a valid context", err)
		}
		if value, err := OpenTunnelFallback(key.Bytes(), bad, sealed); err == nil || value != nil {
			t.Fatal("common context substitution admitted")
		}
	}
	for _, route := range []TunnelBundleBinding{b.Primary, b.Fallback} {
		if _, err := OpenTunnelBundle(key.Bytes(), route, sealed); err == nil {
			t.Fatal("fallback opened as ordinary tunnel")
		}
		ordinary, err := SealTunnelBundle(key.PublicKey().Bytes(), route, plain)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenTunnelFallback(key.Bytes(), b, ordinary); err == nil {
			t.Fatal("ordinary tunnel opened as fallback")
		}
	}
	if _, err := OpenRoutedBundle(key.Bytes(), b.Primary, "127.0.0.1:12345", sealed); err == nil {
		t.Fatal("fallback opened as credential bundle")
	}
	b.Primary.RowVersion, b.Primary.ConfigurationVersion = math.MaxInt64, math.MaxInt64-1
	b.Fallback.RowVersion, b.Fallback.ConfigurationVersion = math.MaxInt64, math.MaxInt64-1
	raw, err := json.Marshal(b)
	if err != nil || bytes.Count(raw, []byte(`"rowVersion":"9223372036854775807"`)) != 2 {
		t.Fatal("fallback revisions lost precision", err)
	}
	large, err := SealTunnelFallback(key.PublicKey().Bytes(), b, bytes.Repeat([]byte{1}, MaxSecretBytes))
	if err != nil {
		t.Fatal("maximum frame refused", err)
	}
	value, err := OpenTunnelFallback(key.Bytes(), b, large)
	if err != nil || len(value) != MaxSecretBytes {
		t.Fatal("maximum frame did not round trip", err)
	}
	Wipe(value)
}

func TestTunnelFallbackRejectsMismatchedSourcesAndMalformedPackets(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := tunnelFallbackFixture()
	plain := []byte("settings")
	sealed, err := SealTunnelFallback(key.PublicKey().Bytes(), b, plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TunnelFallbackBinding){
		func(b *TunnelFallbackBinding) { b.Primary.RequestID = "bad" },
		func(b *TunnelFallbackBinding) { b.Fallback.RequestID = "bad" },
		func(b *TunnelFallbackBinding) { b.Primary.Kind = 2 },
		func(b *TunnelFallbackBinding) { b.Fallback.Kind = 9 },
		func(b *TunnelFallbackBinding) { b.Fallback.TunnelConfigID = b.Primary.TunnelConfigID },
		func(b *TunnelFallbackBinding) { b.Fallback.RequestID = b.Primary.RequestID },
		func(b *TunnelFallbackBinding) { b.Fallback.WorkspaceID = uuid.NewString() },
		func(b *TunnelFallbackBinding) { b.Fallback.FileID = uuid.NewString() },
		func(b *TunnelFallbackBinding) { b.Fallback.NodeID = uuid.NewString() },
		func(b *TunnelFallbackBinding) { b.Fallback.SessionID = uuid.NewString() },
		func(b *TunnelFallbackBinding) { b.Fallback.Protocol = "sftp" },
		func(b *TunnelFallbackBinding) { b.Fallback.Host = "other.example" },
		func(b *TunnelFallbackBinding) { b.Fallback.Port++ },
		func(b *TunnelFallbackBinding) { b.Fallback.Epoch++ },
		func(b *TunnelFallbackBinding) { b.Fallback.ConfigurationVersion = 0 },
	} {
		bad := b
		mutate(&bad)
		if _, err := SealTunnelFallback(key.PublicKey().Bytes(), bad, plain); err == nil {
			t.Fatal("invalid source pair sealed")
		}
		if bad.Validate() == nil {
			t.Fatal("invalid public fallback context")
		}
		if value, err := OpenTunnelFallback(key.Bytes(), bad, sealed); err == nil || value != nil {
			t.Fatal("invalid source pair opened")
		}
	}
	for _, value := range [][]byte{nil, {}, make([]byte, MaxSecretBytes+1)} {
		if _, err := SealTunnelFallback(key.PublicKey().Bytes(), b, value); err == nil {
			t.Fatal("invalid configuration length sealed")
		}
	}
	for _, public := range [][]byte{nil, make([]byte, 32)} {
		if _, err := SealTunnelFallback(public, b, plain); err == nil {
			t.Fatal("invalid recipient accepted")
		}
	}
	for _, private := range [][]byte{nil, make([]byte, 32)} {
		if value, err := OpenTunnelFallback(private, b, sealed); err == nil || value != nil {
			t.Fatal("wrong recipient opened fallback")
		}
	}
	for _, mutate := range []func(*SealedBundle){
		func(s *SealedBundle) { s.FormatVersion++ },
		func(s *SealedBundle) { s.SuiteID++ },
		func(s *SealedBundle) { s.Enc = nil },
		func(s *SealedBundle) { s.Ciphertext = nil },
		func(s *SealedBundle) { s.Ciphertext = make([]byte, MaxSecretBytes+17) },
		func(s *SealedBundle) { s.Ciphertext = bytes.Clone(s.Ciphertext); s.Ciphertext[0] ^= 1 },
	} {
		bad := sealed
		mutate(&bad)
		if value, err := OpenTunnelFallback(key.Bytes(), b, bad); err == nil || value != nil {
			t.Fatal("malformed fallback opened")
		}
	}
	info, _ := b.info()
	empty, err := sealBundlePayload(key.PublicKey().Bytes(), info, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := OpenTunnelFallback(key.Bytes(), b, empty); err == nil || value != nil {
		t.Fatal("authenticated empty configuration accepted")
	}
}
