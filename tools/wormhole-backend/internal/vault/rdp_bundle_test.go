package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestRDPBundleRoundTripAndBorrowedSecrets(t *testing.T) {
	for _, gateway := range []bool{false, true} {
		for _, present := range []bool{false, true} {
			p := RDPBundlePayload{Settings: DefaultRDPSettings(), Username: "user", PasswordProvided: present}
			if present {
				p.Password = []byte("secret-🔒")
			}
			if gateway {
				p.Settings.GatewayUsageMethod = 1
				p.Settings.GatewayHostname = "gateway.example"
				p.GatewayUsername = "edge"
				p.GatewayDomain = "DOMAIN"
				p.GatewayPasswordProvided = true
				p.GatewayPassword = []byte{}
			}
			raw, err := EncodeRDPBundle(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeRDPBundle(raw)
			if err != nil || got.Settings != p.Settings || got.Username != p.Username || got.GatewayUsername != p.GatewayUsername || got.GatewayDomain != p.GatewayDomain || got.PasswordProvided != p.PasswordProvided || got.GatewayPasswordProvided != p.GatewayPasswordProvided || !bytes.Equal(got.Password, p.Password) {
				t.Fatal("RDP payload changed", err)
			}
			Wipe(raw)
			if !bytes.Equal(got.Password, make([]byte, len(got.Password))) {
				t.Fatal("decoded password not borrowed")
			}
		}
	}
	p := RDPBundlePayload{Settings: DefaultRDPSettings(), PasswordProvided: true}
	raw, err := EncodeRDPBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRDPBundle(raw)
	if err != nil || !got.PasswordProvided || len(got.Password) != 0 {
		t.Fatal("explicit empty lost")
	}
}
func TestRDPBundleRejectsMalformedAndAmbiguousFrames(t *testing.T) {
	p := RDPBundlePayload{Settings: DefaultRDPSettings(), Username: "user", PasswordProvided: true, Password: []byte("secret")}
	good, _ := EncodeRDPBundle(p)
	for n := 0; n < len(good); n++ {
		if _, err := DecodeRDPBundle(good[:n]); err == nil {
			t.Fatal("truncated frame", n)
		}
	}
	for _, mode := range []string{"version", "flags", "length", "extra", "json", "unknown", "duplicate", "absent-password", "oversize"} {
		raw := bytes.Clone(good)
		switch mode {
		case "version":
			raw[0] = 2
		case "flags":
			raw[1] = 4
		case "length":
			binary.BigEndian.PutUint32(raw[2:], 0xffffffff)
		case "extra":
			raw = append(raw, 0)
		case "absent-password":
			raw[1] = 0
		case "oversize":
			raw = make([]byte, MaxRDPBundleBytes+1)
		default:
			// Rebuild the public field only; malformed settings must not be ignored.
			fields := make([][]byte, 6)
			rest := good[2:]
			for i := range fields {
				n := int(binary.BigEndian.Uint32(rest))
				rest = rest[4:]
				fields[i] = rest[:n]
				rest = rest[n:]
			}
			if mode == "json" {
				fields[3] = []byte("{")
			} else if mode == "unknown" {
				fields[3] = append([]byte(`{"unknown":true,`), fields[3][1:]...)
			} else {
				fields[3] = append([]byte(`{"colorDepth":16,`), fields[3][1:]...)
			}
			raw = []byte{1, 1}
			for _, f := range fields {
				raw = binary.BigEndian.AppendUint32(raw, uint32(len(f)))
				raw = append(raw, f...)
			}
		}
		if _, err := DecodeRDPBundle(raw); err == nil {
			t.Fatal(mode)
		}
	}
	for _, mutate := range []func(*RDPBundlePayload){
		func(p *RDPBundlePayload) { p.PasswordProvided = false }, func(p *RDPBundlePayload) { p.Password = []byte{0xff} }, func(p *RDPBundlePayload) { p.Password = []byte("line\nsecret") }, func(p *RDPBundlePayload) { p.Password = []byte{0} }, func(p *RDPBundlePayload) { p.Password = bytes.Repeat([]byte("x"), 4097) }, func(p *RDPBundlePayload) { p.Username = strings.Repeat("x", 2049) }, func(p *RDPBundlePayload) { p.Username = "bad\ruser" }, func(p *RDPBundlePayload) { p.Settings.Domain = string([]byte{0xff}) }, func(p *RDPBundlePayload) { p.Settings.Domain = " spaced " }, func(p *RDPBundlePayload) { p.Settings.UseExternalClient = true }, func(p *RDPBundlePayload) { p.GatewayPasswordProvided = true }, func(p *RDPBundlePayload) { p.GatewayUsername = "unused" }, func(p *RDPBundlePayload) {
			p.Settings.GatewayUsageMethod = 1
			p.Settings.GatewayHostname = "gateway"
			p.Settings.GatewayUseSameCreds = true
			p.GatewayPasswordProvided = true
		},
	} {
		bad := p
		mutate(&bad)
		if _, err := EncodeRDPBundle(bad); err == nil {
			t.Fatal("unsafe payload accepted")
		}
	}
	// A well-framed object with invalid native policy must also fail on decode.
	settings := p.Settings
	settings.UseExternalClient = true
	public, _ := json.Marshal(settings)
	raw := []byte{1, 0}
	for _, f := range [][]byte{nil, nil, nil, public, nil, nil} {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(f)))
		raw = append(raw, f...)
	}
	if _, err := DecodeRDPBundle(raw); err != ErrPolicy {
		t.Fatal(err)
	}
}
func TestRDPRoutePreservesMandatoryCertificatePolicy(t *testing.T) {
	for _, level := range []int{0, 1, 2} {
		s := DefaultRDPSettings()
		s.ServerAuthentication = level
		if ValidateRDPRoute(s, false) != nil {
			t.Fatal("direct refused")
		}
		if (ValidateRDPRoute(s, true) == nil) != (level != 1) {
			t.Fatal("certificate policy weakened", level)
		}
	}
	s := DefaultRDPSettings()
	s.GatewayUsageMethod = 1
	if ValidateRDPRoute(s, true) != ErrPolicy {
		t.Fatal("gateway route accepted")
	}
	s = DefaultRDPSettings()
	s.UseExternalClient = true
	if ValidateRDPRoute(s, false) != ErrPolicy {
		t.Fatal("external credential delivery accepted")
	}
}
