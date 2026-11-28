package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func rdpReferenceFixture(bindings []uint16) []byte {
	out := make([]byte, 68)
	binary.LittleEndian.PutUint32(out, 0x574f454d)
	binary.LittleEndian.PutUint32(out[4:], 1)
	copy(out[8:], []byte{0, 4, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46})
	out[32], out[40], out[48] = 1, 2, 3
	security := []uint16{10, 0xffff, 0, 0}
	binary.LittleEndian.PutUint16(out[64:], uint16(len(bindings)+len(security)))
	binary.LittleEndian.PutUint16(out[66:], uint16(len(bindings)))
	for _, v := range append(append([]uint16{}, bindings...), security...) {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}

func TestRdpDispatchReferenceAllowsOnlyLocalStandardAutomation(t *testing.T) {
	local := []uint16{0x10, 'l', 'o', 'c', 'a', 'l', 0, 0}
	good := rdpReferenceFixture(local)
	out, err := localRdpDispatchReference(good)
	if err != nil || !bytes.Equal(out, good) {
		t.Fatal(err)
	}
	compact := bytes.Clone(good[:68])
	clear(compact[64:])
	if decoded, err := localRdpDispatchReference(compact); err != nil || !bytes.Equal(decoded, compact) {
		t.Fatal("compact local reference", err)
	}
	// Local-only rewrite removes network bindings instead of allowing COM to choose
	// an alternate TCP/named-pipe transport when the local endpoint is unavailable.
	mixed := rdpReferenceFixture(append([]uint16{7, 'r', 'e', 'm', 'o', 't', 'e', 0}, local...))
	filtered, err := localRdpDispatchReference(mixed)
	if err != nil || !bytes.Equal(filtered, good) {
		t.Fatal("remote COM binding retained", err)
	}
	filtered[48] ^= 1
	if bytes.Equal(filtered, mixed) {
		t.Fatal("borrowed mutable reference")
	}
	for _, mode := range []string{"short", "large", "magic", "custom", "handler", "extended", "iid", "count", "offset", "no-local", "string-termination", "string-long", "extra", "security-short", "security-termination", "security-long", "oxid", "oid", "ipid"} {
		raw := bytes.Clone(good)
		switch mode {
		case "short":
			raw = raw[:67]
		case "large":
			raw = make([]byte, 32769)
		case "magic":
			raw[0] ^= 1
		case "custom":
			binary.LittleEndian.PutUint32(raw[4:], 4)
		case "handler":
			binary.LittleEndian.PutUint32(raw[4:], 2)
		case "extended":
			binary.LittleEndian.PutUint32(raw[4:], 8)
		case "iid":
			raw[8] ^= 1
		case "count":
			binary.LittleEndian.PutUint16(raw[64:], 1)
		case "offset":
			binary.LittleEndian.PutUint16(raw[66:], 0xffff)
		case "no-local":
			raw = rdpReferenceFixture([]uint16{7, 'x', 0, 0})
		case "string-termination":
			raw = rdpReferenceFixture([]uint16{0x10, 'x'})
		case "string-long":
			bindings := append([]uint16{0x10}, make([]uint16, 1025)...)
			for i := 1; i < len(bindings); i++ {
				bindings[i] = 'x'
			}
			raw = rdpReferenceFixture(append(bindings, 0, 0))
		case "extra":
			raw = append(raw, 0, 0)
		case "security-short":
			binary.LittleEndian.PutUint16(raw[66:], uint16(len(local)+3))
		case "security-termination":
			raw[len(raw)-2] = 1
		case "oxid":
			clear(raw[32:40])
		case "oid":
			clear(raw[40:48])
		case "ipid":
			clear(raw[48:64])
		case "security-long":
			raw = rdpReferenceFixture(local)
			raw = raw[:68+len(local)*2]
			security := []uint16{10, 0xffff}
			for i := 0; i < 1025; i++ {
				security = append(security, 'x')
			}
			security = append(security, 0, 0)
			for _, v := range security {
				raw = binary.LittleEndian.AppendUint16(raw, v)
			}
			binary.LittleEndian.PutUint16(raw[64:], uint16(len(local)+len(security)))
		}
		if _, err := localRdpDispatchReference(raw); err != errRdpNativeReference {
			t.Fatal(mode, err)
		}
	}
	for n := 0; n < len(good); n++ {
		if _, err := localRdpDispatchReference(good[:n]); err == nil {
			t.Fatal("truncated reference", n)
		}
	}
}

func TestRdpCredentialEncodingUsesMutableUTF16(t *testing.T) {
	for _, text := range []string{"", "ordinary", "密码", "secret-🔒"} {
		actual, err := rdpCredentialUTF16([]byte(text))
		if err != nil || string(utf16.Decode(actual)) != text {
			t.Fatal(err)
		}
		clear(actual)
	}
	for _, bad := range [][]byte{{0}, {0xff}, make([]byte, 65537)} {
		if _, err := rdpCredentialUTF16(bad); err != errRdpNativeReference {
			t.Fatal("invalid credential encoding", err)
		}
	}
}
