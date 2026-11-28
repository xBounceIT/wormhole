package vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
)

func TestSerialBundleBindsNativeRecipientAndFormat(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(),
		RequestID: uuid.NewString(), Protocol: "serial", Host: "COM21", Epoch: 1}
	settings := DefaultSerialSettings()
	sealed, err := SealSerialConnection(key.PublicKey().Bytes(), b, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(key.Bytes(), b, sealed.Bundle); err == nil {
		t.Fatal("serial settings opened outside the serial domain")
	}
	for _, edit := range []func(*BundleBinding){
		func(b *BundleBinding) { b.Protocol = "rdp" }, func(b *BundleBinding) { b.NodeID = uuid.Nil.String() },
		func(b *BundleBinding) { b.Host = "COM21\n" }, func(b *BundleBinding) { b.Port = 80 },
		func(b *BundleBinding) { b.TunnelConfigID = uuid.NewString() },
		func(b *BundleBinding) { b.Epoch++ }, func(b *BundleBinding) { b.SessionID = uuid.NewString() },
	} {
		edited := b
		edit(&edited)
		if _, err := OpenSerialConnection(key.Bytes(), edited, sealed.Bundle); err == nil {
			t.Fatal("a changed binding authorized serial access")
		}
	}
	if _, err := SealSerialConnection(make([]byte, 12), b, settings); err == nil {
		t.Fatal("invalid recipient accepted")
	}
	info, err := serialBundleInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{{2, 0, 0, 37, 128, 8, 1, 0, 0}, {1, 0, 0, 37, 128, 0, 1, 0, 0}} {
		bad, err := sealBundlePayload(key.PublicKey().Bytes(), info, raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSerialConnection(key.Bytes(), b, bad); err == nil {
			t.Fatal("invalid serial settings accepted")
		}
	}
}
