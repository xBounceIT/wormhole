package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func manualRDPBinding() BundleBinding {
	b := manualVNCBinding()
	b.Protocol = "rdp"
	b.Port = 3389
	return b
}
func TestRDPManualEnvelopeAndAuthority(t *testing.T) {
	for _, routed := range []bool{false, true} {
		b := manualRDPBinding()
		var route *TunnelBundleBinding
		endpoint := ""
		if routed {
			b.TunnelConfigID = uuid.NewString()
			route = &TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 2, ConfigurationVersion: 1}
			endpoint = "127.0.0.1:2345"
		}
		key, _ := ecdh.X25519().GenerateKey(rand.Reader)
		for _, password := range [][]byte{nil, []byte("temporary-secret"), bytes.Repeat([]byte("𐀀"), 4096)} {
			input := RDPManualCredentials{Username: "例\\ RDP user", Domain: "領域", Password: password}
			inner, err := SealManualRDPCredentials(key.PublicKey().Bytes(), b, route, endpoint, input)
			if err != nil {
				t.Fatal(err)
			}
			settings, _ := NormalizeRDPSettings(nil)
			base := RDPBundlePayload{Settings: settings}
			auth, err := EncodeRDPManualAuthorization(base, inner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeRDPBundle(auth); err == nil {
				t.Fatal("manual authorization became saved credentials")
			}
			decoded, envelope, err := DecodeRDPManualAuthorization(auth)
			if err != nil || decoded.Username != "" || decoded.PasswordProvided {
				t.Fatal("manual base changed", err)
			}
			raw, err := OpenManualRDPCredentials(key.Bytes(), b, route, endpoint, envelope)
			if err != nil {
				t.Fatal(err)
			}
			p, err := DecodeRDPManualCredentials(raw)
			if err != nil || p.Username != input.Username || p.Domain != input.Domain || !bytes.Equal(p.Password, password) {
				t.Fatal("manual account changed", err)
			}
			Wipe(raw)
			if !bytes.Equal(p.Password, make([]byte, len(password))) {
				t.Fatal("manual password not borrowed")
			}
			if _, err = OpenBundle(key.Bytes(), b, inner); err == nil {
				t.Fatal("purpose swap")
			}
			bad := b
			bad.Host = "changed.example"
			if _, err = OpenManualRDPCredentials(key.Bytes(), bad, route, endpoint, inner); err == nil {
				t.Fatal("target substitution")
			}
			if routed {
				if _, err = OpenManualRDPCredentials(key.Bytes(), b, route, "127.0.0.1:2346", inner); err == nil {
					t.Fatal("route endpoint swap")
				}
			}
			Wipe(auth)
			if !bytes.Equal(envelope.Enc, make([]byte, 32)) || !bytes.Equal(envelope.Ciphertext, make([]byte, len(envelope.Ciphertext))) {
				t.Fatal("envelope not borrowed")
			}
		}
	}
}
func TestRDPManualCodecRejectsMalformedAndSavedFallback(t *testing.T) {
	valid := RDPManualCredentials{Username: "user", Password: []byte("secret")}
	for _, p := range []RDPManualCredentials{{}, {Username: "x\n"}, {Username: string([]byte{255})}, {Username: strings.Repeat("x", 514)}, {Username: strings.Repeat("𐀀", 513)}, {Username: "u", Domain: strings.Repeat("d", 514)}, {Username: "u", Password: []byte{255}}, {Username: "u", Password: []byte("bad\x00")}, {Username: "u", Password: bytes.Repeat([]byte("x"), 4097)}} {
		if _, err := EncodeRDPManualCredentials(p); err == nil {
			t.Fatal("invalid manual input")
		}
	}
	raw, err := EncodeRDPManualCredentials(valid)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(raw); i++ {
		if _, err := DecodeRDPManualCredentials(raw[:i]); err == nil {
			t.Fatal("truncation accepted", i)
		}
	}
	for _, edit := range []func([]byte){func(b []byte) { b[0] = 2 }, func(b []byte) { b[1] = 0 }, func(b []byte) { b[2] = 255 }, func(b []byte) { b[6] = 255 }} {
		bad := bytes.Clone(raw)
		edit(bad)
		if _, err = DecodeRDPManualCredentials(bad); err == nil {
			t.Fatal("bad frame accepted")
		}
	}
	if _, err = DecodeRDPManualCredentials(append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("trailing bytes")
	}
	b := manualRDPBinding()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	inner, _ := SealManualRDPCredentials(key.PublicKey().Bytes(), b, nil, "", valid)
	settings, _ := NormalizeRDPSettings(nil)
	base := RDPBundlePayload{Settings: settings}
	for _, change := range []func(*RDPBundlePayload){func(p *RDPBundlePayload) { p.Username = "saved" }, func(p *RDPBundlePayload) { p.Settings.Domain = "saved" }, func(p *RDPBundlePayload) { p.PasswordProvided = true }, func(p *RDPBundlePayload) { p.Password = []byte("saved") }, func(p *RDPBundlePayload) { p.Settings.ColorDepth = -1 }} {
		p := base
		change(&p)
		if _, err = EncodeRDPManualAuthorization(p, inner); err == nil {
			t.Fatal("saved fallback accepted")
		}
	}
	auth, _ := EncodeRDPManualAuthorization(base, inner)
	for i := 0; i < len(auth); i++ {
		if _, _, err = DecodeRDPManualAuthorization(auth[:i]); err == nil {
			t.Fatal("outer truncation", i)
		}
	}
	for _, edit := range []func([]byte){func(b []byte) { b[0] = 1 }, func(b []byte) { binary.BigEndian.PutUint32(b[1:5], 0) }, func(b []byte) { b[1] = 255 }, func(b []byte) { b[5] = 99 }, func(b []byte) { b[len(b)-len(inner.Ciphertext)-1]++ }} {
		bad := bytes.Clone(auth)
		edit(bad)
		if _, _, err = DecodeRDPManualAuthorization(bad); err == nil {
			t.Fatal("bad authorization accepted")
		}
	}
	// A syntactically valid saved frame with a primary secret cannot be smuggled
	// inside the options frame, even under a manual version header.
	saved := base
	saved.PasswordProvided = true
	saved.Password = []byte("must-not-fallback")
	savedRaw, _ := EncodeRDPBundle(saved)
	bad := []byte{2}
	bad = binary.BigEndian.AppendUint32(bad, uint32(len(savedRaw)))
	bad = append(bad, savedRaw...)
	bad = append(bad, auth[5+int(binary.BigEndian.Uint32(auth[1:5])):]...)
	if _, _, err = DecodeRDPManualAuthorization(bad); err == nil {
		t.Fatal("saved primary inside manual authority")
	}
	for _, s := range []SealedBundle{{}, {FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM, Enc: make([]byte, 32), Ciphertext: make([]byte, 29)}, {FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM, Enc: make([]byte, 32), Ciphertext: make([]byte, MaxRDPManualCiphertext+1)}} {
		if _, err = EncodeRDPManualAuthorization(base, s); err == nil {
			t.Fatal("invalid envelope")
		}
		if _, err = OpenManualRDPCredentials(key.Bytes(), b, nil, "", s); err == nil {
			t.Fatal("invalid envelope open")
		}
	}
	inner.Ciphertext[0] ^= 1
	if _, err = OpenManualRDPCredentials(key.Bytes(), b, nil, "", inner); err == nil {
		t.Fatal("cipher mutation")
	}
	info, _ := manualRDPInfo(b, nil, "")
	badInner, _ := sealBundlePayload(key.PublicKey().Bytes(), info, []byte("invalid frame"))
	if _, err = OpenManualRDPCredentials(key.Bytes(), b, nil, "", badInner); err == nil {
		t.Fatal("authenticated malformed input")
	}
	for _, change := range []func(*BundleBinding){func(b *BundleBinding) { b.Host = "bad host" }, func(b *BundleBinding) { b.Protocol = "vnc" }, func(b *BundleBinding) { b.WorkspaceID = "bad" }, func(b *BundleBinding) { b.Epoch = 0 }, func(b *BundleBinding) { b.UseExternalClient = true }, func(b *BundleBinding) { b.TunnelConfigID = uuid.NewString() }} {
		bad := b
		change(&bad)
		if _, err = SealManualRDPCredentials(key.PublicKey().Bytes(), bad, nil, "", valid); err == nil {
			t.Fatal("bad context")
		}
	}
	if _, err = SealManualRDPCredentials(nil, b, nil, "", valid); err == nil {
		t.Fatal("invalid public key")
	}
	if _, err = SealManualRDPCredentials(key.PublicKey().Bytes(), b, nil, "", RDPManualCredentials{}); err == nil {
		t.Fatal("invalid plaintext")
	}
	if _, err = OpenManualRDPCredentials(nil, b, nil, "", inner); err == nil {
		t.Fatal("invalid private key")
	}
}

func TestRDPManualBOMCountsAsCodePoint(t *testing.T) {
	for _, field := range []string{"username", "domain", "password"} {
		limit := 513
		if field == "password" {
			limit = 4096
		}
		for _, extra := range []bool{false, true} {
			count := limit - 1
			if extra {
				count++
			}
			value := "\ufeff" + strings.Repeat("a", count)
			input := RDPManualCredentials{Username: "u"}
			switch field {
			case "username":
				input.Username = value
			case "domain":
				input.Domain = value
			case "password":
				input.Password = []byte(value)
			}
			frame, err := EncodeRDPManualCredentials(input)
			if extra {
				if err == nil {
					t.Fatal("BOM excluded from limit", field)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeRDPManualCredentials(frame)
			if err != nil || decoded.Username != input.Username || decoded.Domain != input.Domain || !bytes.Equal(decoded.Password, input.Password) {
				t.Fatal("BOM removed", field, err)
			}
			Wipe(frame)
		}
	}
}
