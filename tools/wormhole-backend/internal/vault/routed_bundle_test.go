package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestRoutedBundleBindsLeaseEndpointAndPurpose(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := tunnelBindingFixture()
	endpoint := "127.0.0.1:12345"
	plain := []byte("native-credential")
	s, err := SealRoutedBundle(key.PublicKey().Bytes(), b, endpoint, plain)
	if err != nil {
		t.Fatal(err)
	}
	value, err := OpenRoutedBundle(key.Bytes(), b, endpoint, s)
	if err != nil || !bytes.Equal(value, plain) {
		t.Fatal(err)
	}
	Wipe(value)
	if _, err := OpenRoutedBundle(key.Bytes(), b, "127.0.0.1:12346", s); err == nil {
		t.Fatal("endpoint substitution")
	}
	changed := b
	changed.ConfigurationVersion++
	if _, err := OpenRoutedBundle(key.Bytes(), changed, endpoint, s); err == nil {
		t.Fatal("configuration substitution")
	}
	if _, err := OpenBundle(key.Bytes(), b.BundleBinding, s); err == nil {
		t.Fatal("direct downgrade")
	}
	if _, err := OpenTunnelBundle(key.Bytes(), b, s); err == nil {
		t.Fatal("tunnel purpose confusion")
	}
	direct, _ := SealBundle(key.PublicKey().Bytes(), b.BundleBinding, plain)
	if _, err := OpenRoutedBundle(key.Bytes(), b, endpoint, direct); err == nil {
		t.Fatal("direct accepted as routed")
	}
	for _, endpoint := range []string{"", "127.0.0.1:0", "127.0.0.1:01", "127.0.0.1:+1", "127.0.0.1:65536", "localhost:22", "10.0.0.1:22", "[::1]:22", "127.0.0.1:22\n"} {
		if ValidRouteEndpoint(endpoint) {
			t.Fatal(endpoint)
		}
		if _, err := SealRoutedBundle(key.PublicKey().Bytes(), b, endpoint, plain); err == nil {
			t.Fatal(endpoint)
		}
		if _, err := OpenRoutedBundle(key.Bytes(), b, endpoint, s); err == nil {
			t.Fatal(endpoint)
		}
	}
	bad := b
	bad.FileID = "bad"
	if _, err := SealRoutedBundle(key.PublicKey().Bytes(), bad, endpoint, plain); err == nil {
		t.Fatal("bad binding")
	}
	if _, err := OpenRoutedBundle(key.Bytes(), bad, endpoint, s); err == nil {
		t.Fatal("bad binding")
	}
	s.FormatVersion++
	if _, err := OpenRoutedBundle(key.Bytes(), b, endpoint, s); err != ErrNewerFormat {
		t.Fatal(err)
	}
	if _, err := SealRoutedBundle(key.PublicKey().Bytes(), b, endpoint, make([]byte, MaxSecretBytes+1)); err != ErrFormat {
		t.Fatal(err)
	}
}
