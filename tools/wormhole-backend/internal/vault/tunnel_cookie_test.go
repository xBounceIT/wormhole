package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"testing"
)

func cookieFixture() TunnelCookieBinding {
	r := tunnelBindingFixture()
	r.Kind = 2
	return TunnelCookieBinding{Route: r, ChallengeID: uuid.NewString(), StartURL: "https://vpn.test/remote/saml/start?realm=staff", IgnoreCertificateErrors: true}
}
func TestFortinetCallbackBinding(t *testing.T) {
	cookie := cookieFixture()
	callback := cookie
	callback.UseSamlCallback = true
	callback.StartURL = "https://vpn.test/remote/saml/start?redirect=1"
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	value := bytes.Repeat([]byte(","), 4096)
	sealed, err := SealTunnelCookie(key.PublicKey().Bytes(), callback, value)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := OpenTunnelCookie(key.Bytes(), callback, sealed)
	if err != nil || !bytes.Equal(raw[6:], value) {
		t.Fatal("callback roundtrip", err)
	}
	if _, err := OpenTunnelCookie(key.Bytes(), cookie, sealed); err == nil {
		t.Fatal("cookie accepted callback")
	}
	for _, invalid := range [][]byte{nil, append(value, 'x'), []byte("a b"), {0x80}} {
		if _, err := SealTunnelCookie(key.PublicKey().Bytes(), callback, invalid); err == nil {
			t.Fatal("invalid callback credential")
		}
	}
	callback.StartURL = cookie.StartURL
	if _, err := callback.info(); err == nil {
		t.Fatal("callback accepted cookie start URL")
	}
	cookie.StartURL = "https://vpn.test/remote/saml/start?redirect=1"
	if _, err := cookie.info(); err == nil {
		t.Fatal("cookie accepted callback start URL")
	}
}

func TestTunnelCookieFramePurposeAndBounds(t *testing.T) {
	b := cookieFixture()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, cookie := range [][]byte{[]byte("one-use-cookie+/="), bytes.Repeat([]byte("a"), MaxTunnelCookieBytes)} {
		sealed, err := SealTunnelCookie(key.PublicKey().Bytes(), b, cookie)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := OpenTunnelCookie(key.Bytes(), b, sealed)
		if err != nil || !bytes.Equal(raw[6:], cookie) || binary.BigEndian.Uint32(raw[2:6]) != uint32(len(cookie)) {
			t.Fatal("roundtrip", err)
		}
		Wipe(raw)
		for _, change := range []func(*TunnelCookieBinding){func(c *TunnelCookieBinding) { c.ChallengeID = uuid.NewString() }, func(c *TunnelCookieBinding) { c.StartURL += "x" }, func(c *TunnelCookieBinding) { c.IgnoreCertificateErrors = false }, func(c *TunnelCookieBinding) { c.Route.FileID = uuid.NewString() }, func(c *TunnelCookieBinding) { c.Route.ConfigurationVersion++ }} {
			other := b
			change(&other)
			if _, err := OpenTunnelCookie(key.Bytes(), other, sealed); err == nil {
				t.Fatal("context substitution")
			}
		}
		if _, err := OpenTunnelBundle(key.Bytes(), b.Route, sealed); err == nil {
			t.Fatal("configuration purpose reused")
		}
	}
	for _, cookie := range [][]byte{nil, []byte("bad value"), []byte("bad;value"), []byte("bad,value"), []byte("bad\"value"), []byte("bad\\value"), []byte("bad\nvalue"), []byte("é"), bytes.Repeat([]byte("a"), MaxTunnelCookieBytes+1)} {
		if ValidTunnelCookie(cookie) {
			t.Fatal("invalid octets")
		}
		if _, err := SealTunnelCookie(key.PublicKey().Bytes(), b, cookie); err == nil {
			t.Fatal("invalid input")
		}
	}
	sealed, _ := SealTunnelCookie(key.PublicKey().Bytes(), b, []byte("cookie"))
	for _, n := range []int{0, 22, 16407} {
		s := sealed
		s.Ciphertext = make([]byte, n)
		if _, err := OpenTunnelCookie(key.Bytes(), b, s); err == nil {
			t.Fatal("cipher bound")
		}
	}
	info, _ := b.info()
	for _, plain := range [][]byte{make([]byte, 7), {1, 1, 0, 0, 0, 2, 'x'}, {1, 1, 0, 0, 0, 1, ' '}} {
		s, _ := sealBundlePayload(key.PublicKey().Bytes(), info, plain)
		if raw, err := OpenTunnelCookie(key.Bytes(), b, s); err == nil || raw != nil {
			t.Fatal("malformed authenticated frame")
		}
	}
	for _, change := range []func(*TunnelCookieBinding){func(c *TunnelCookieBinding) { c.Route.Kind = 9 }, func(c *TunnelCookieBinding) { c.Route.Port = 0 }, func(c *TunnelCookieBinding) { c.ChallengeID = "bad" }, func(c *TunnelCookieBinding) { c.ChallengeID = uuid.Nil.String() }, func(c *TunnelCookieBinding) { c.StartURL = "%" }, func(c *TunnelCookieBinding) { c.StartURL = "http://vpn.test/remote/saml/start" }, func(c *TunnelCookieBinding) { c.StartURL = "https://u:p@vpn.test/remote/saml/start" }, func(c *TunnelCookieBinding) { c.StartURL = "https://vpn.test/other" }, func(c *TunnelCookieBinding) { c.StartURL += "#x" }, func(c *TunnelCookieBinding) { c.StartURL += "\n" }, func(c *TunnelCookieBinding) { c.StartURL += "x=" + string(bytes.Repeat([]byte{'a'}, 4096)) }} {
		bad := b
		change(&bad)
		if _, err := SealTunnelCookie(key.PublicKey().Bytes(), bad, []byte("c")); err == nil {
			t.Fatal("invalid binding")
		}
		if _, err := OpenTunnelCookie(key.Bytes(), bad, sealed); err == nil {
			t.Fatal("invalid open binding")
		}
	}
}
