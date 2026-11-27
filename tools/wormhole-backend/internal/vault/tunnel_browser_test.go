package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"github.com/google/uuid"
	"testing"
)

func browserFixture() TunnelBrowserBinding {
	r := tunnelBindingFixture()
	r.Kind = 9
	return TunnelBrowserBinding{Route: r, ChallengeID: uuid.NewString(), StartURL: "https://vpn.test:1001/saml?state=public", CallbackURL: "http://127.0.0.1:12345/", IgnoreCertificateErrors: true}
}
func TestTunnelBrowserTokenPurpose(t *testing.T) {
	b := browserFixture()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	token := bytes.Repeat([]byte("aB"), 16)
	s, err := SealTunnelBrowserToken(key.PublicKey().Bytes(), b, token)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := OpenTunnelBrowserToken(key.Bytes(), b, s)
	if err != nil || !bytes.Equal(raw, append([]byte{1, 1}, token...)) {
		t.Fatal("roundtrip", err)
	}
	Wipe(raw)
	for _, change := range []func(*TunnelBrowserBinding){func(c *TunnelBrowserBinding) { c.ChallengeID = uuid.NewString() }, func(c *TunnelBrowserBinding) { c.StartURL += "x" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "http://127.0.0.1:12346/" }, func(c *TunnelBrowserBinding) { c.IgnoreCertificateErrors = false }, func(c *TunnelBrowserBinding) { c.Route.NodeID = uuid.NewString() }, func(c *TunnelBrowserBinding) { c.Route.ConfigurationVersion++ }} {
		c := b
		change(&c)
		if _, err := OpenTunnelBrowserToken(key.Bytes(), c, s); err == nil {
			t.Fatal("substitution accepted")
		}
	}
	if _, err := OpenTunnelAuthentication(key.Bytes(), TunnelAuthenticationBinding{Route: b.Route, ChallengeID: b.ChallengeID}, s); err == nil {
		t.Fatal("password purpose reused")
	}
	if _, err := OpenTunnelBundle(key.Bytes(), b.Route, s); err == nil {
		t.Fatal("bundle purpose reused")
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := SealTunnelBrowserToken(key.PublicKey().Bytes(), b, make([]byte, n)); err == nil {
			t.Fatal("token size")
		}
	}
	for _, n := range []int{0, 49, 51} {
		invalid := s
		invalid.Ciphertext = make([]byte, n)
		if _, err := OpenTunnelBrowserToken(key.Bytes(), b, invalid); err == nil {
			t.Fatal("cipher size")
		}
	}
	info, _ := b.info()
	bad, _ := sealBundlePayload(key.PublicKey().Bytes(), info, make([]byte, 34))
	if raw, err := OpenTunnelBrowserToken(key.Bytes(), b, bad); err == nil || raw != nil {
		t.Fatal("malformed authenticated frame")
	}
	for _, change := range []func(*TunnelBrowserBinding){func(c *TunnelBrowserBinding) { c.Route.Kind = 1 }, func(c *TunnelBrowserBinding) { c.Route.Port = 0 }, func(c *TunnelBrowserBinding) { c.ChallengeID = "bad" }, func(c *TunnelBrowserBinding) { c.ChallengeID = uuid.Nil.String() }, func(c *TunnelBrowserBinding) { c.StartURL = "http://vpn.test/saml" }, func(c *TunnelBrowserBinding) { c.StartURL = "https://u:p@vpn.test/saml" }, func(c *TunnelBrowserBinding) { c.StartURL = "https://vpn.test/other" }, func(c *TunnelBrowserBinding) { c.StartURL = "https://vpn.test/saml#fragment" }, func(c *TunnelBrowserBinding) {
		c.StartURL = "https://vpn.test/saml?x=" + string(bytes.Repeat([]byte{'a'}, 4096))
	}, func(c *TunnelBrowserBinding) { c.StartURL = "%" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "http://localhost:12345/" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "http://127.0.0.1:0/" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "http://127.0.0.1:012345/" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "http://127.0.0.1:12345/?" }, func(c *TunnelBrowserBinding) { c.CallbackURL = "%" }} {
		c := b
		change(&c)
		if _, err := SealTunnelBrowserToken(key.PublicKey().Bytes(), c, token); err == nil {
			t.Fatal("invalid binding")
		}
		if _, err := OpenTunnelBrowserToken(key.Bytes(), c, s); err == nil {
			t.Fatal("invalid open binding")
		}
	}
}
