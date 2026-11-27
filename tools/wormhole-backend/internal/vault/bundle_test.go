package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"testing"
)

func testBundleBinding() BundleBinding {
	return BundleBinding{WorkspaceID: "workspace", SessionID: "session", RequestID: "request", NodeID: "node", Protocol: "ssh", Host: "server", Port: 22, Epoch: 1}
}

func TestBundleInteropAndDestinationBinding(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBundleBinding()
	secret := []byte("protocol-password")
	bundle, err := SealBundle(priv.PublicKey().Bytes(), binding, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenBundle(priv.Bytes(), binding, bundle)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("bundle: %v", err)
	}
	// Interoperate with a separate standard-library HPKE recipient.
	pk, _ := hpke.NewDHKEMPrivateKey(priv)
	info, _ := binding.info()
	r, err := hpke.NewRecipient(bundle.Enc, pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	got, err = r.Open(nil, bundle.Ciphertext)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("HPKE interop: %v", err)
	}
	for name, mutate := range map[string]func(*BundleBinding){
		"workspace": func(b *BundleBinding) { b.WorkspaceID = "other" }, "session": func(b *BundleBinding) { b.SessionID = "other" },
		"request": func(b *BundleBinding) { b.RequestID = "other" }, "node": func(b *BundleBinding) { b.NodeID = "other" },
		"protocol": func(b *BundleBinding) { b.Protocol = "rdp" }, "host": func(b *BundleBinding) { b.Host = "attacker" },
		"port": func(b *BundleBinding) { b.Port++ }, "route": func(b *BundleBinding) { b.TunnelConfigID = "other" },
		"external": func(b *BundleBinding) { b.UseExternalClient = true }, "epoch": func(b *BundleBinding) { b.Epoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			b := binding
			mutate(&b)
			if _, err := OpenBundle(priv.Bytes(), b, bundle); err != ErrAuthentication {
				t.Fatalf("modified destination accepted: %v", err)
			}
		})
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenBundle(other.Bytes(), binding, bundle); err != ErrAuthentication {
		t.Fatal("wrong recipient")
	}
	for _, mutate := range []func(*SealedBundle){func(b *SealedBundle) { b.FormatVersion = 0 }, func(b *SealedBundle) { b.FormatVersion++ }, func(b *SealedBundle) { b.SuiteID = 1 }, func(b *SealedBundle) { b.Enc = nil }, func(b *SealedBundle) { b.Ciphertext = nil }, func(b *SealedBundle) { b.Enc = make([]byte, 32) }} {
		b := bundle
		mutate(&b)
		if _, err := OpenBundle(priv.Bytes(), binding, b); err == nil {
			t.Fatal("malformed bundle accepted")
		}
	}
	if _, err := SealBundle(nil, binding, nil); err != ErrFormat {
		t.Fatal("bad public key")
	}
	if _, err := SealBundle(make([]byte, 32), binding, nil); err != ErrAuthentication {
		t.Fatal("low order public key")
	}
	if _, err := SealBundle(priv.PublicKey().Bytes(), BundleBinding{}, nil); err != ErrFormat {
		t.Fatal("empty binding")
	}
	if _, err := SealBundle(priv.PublicKey().Bytes(), binding, make([]byte, MaxSecretBytes+1)); err != ErrFormat {
		t.Fatal("oversize bundle")
	}
	if _, err := OpenBundle(nil, binding, bundle); err != ErrFormat {
		t.Fatal("bad private key")
	}
	binding.Epoch = 0
	if _, err := OpenBundle(priv.Bytes(), binding, bundle); err != ErrFormat {
		t.Fatal("missing epoch")
	}
}
