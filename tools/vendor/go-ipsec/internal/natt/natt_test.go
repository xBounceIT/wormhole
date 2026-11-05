package natt

import (
	"bytes"
	"net/netip"
	"testing"
)

// TestDetectionHashIPv6 is finding #15: DetectionHash hashes the full 16-byte
// address for an IPv6 endpoint (not a zeroed v4), so NAT detection is correct on
// an IPv6 transport.
func TestDetectionHashIPv6(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1")
	h := DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, v6, 4500)
	if len(h) != 20 {
		t.Fatalf("v6 hash length = %d, want 20", len(h))
	}
	if !bytes.Equal(h, DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, v6, 4500)) {
		t.Fatal("v6 DetectionHash not deterministic")
	}
	if bytes.Equal(h, DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, netip.MustParseAddr("2001:db8::2"), 4500)) {
		t.Fatal("v6 hash insensitive to address")
	}
	if bytes.Equal(h, DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, netip.MustParseAddr("192.0.2.1"), 4500)) {
		t.Fatal("v6 hash collides with a v4 hash")
	}
}

func TestDetectionHash(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	h1 := DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, ip, 4500)
	if len(h1) != 20 {
		t.Fatalf("hash length = %d, want 20 (SHA1)", len(h1))
	}
	// Deterministic.
	h2 := DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, ip, 4500)
	if !bytes.Equal(h1, h2) {
		t.Fatal("DetectionHash not deterministic")
	}
	// Sensitive to each input.
	if bytes.Equal(h1, DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, ip, 500)) {
		t.Fatal("hash insensitive to port")
	}
	if bytes.Equal(h1, DetectionHash(0, 0x99AABBCCDDEEFF00, ip, 4500)) {
		t.Fatal("hash insensitive to SPIi")
	}
	if bytes.Equal(h1, DetectionHash(0x1122334455667788, 0x99AABBCCDDEEFF00, netip.MustParseAddr("192.0.2.2"), 4500)) {
		t.Fatal("hash insensitive to IP")
	}
}

func TestClassify(t *testing.T) {
	// IKE: non-ESP marker prefix.
	ike := WrapIKE([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	kind, payload := Classify(ike)
	if kind != KindIKE || !bytes.Equal(payload, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("IKE classify failed: kind=%v payload=%x", kind, payload)
	}
	// ESP: non-zero SPI first word.
	esp := []byte{0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB}
	if kind, _ := Classify(esp); kind != KindESP {
		t.Fatalf("ESP classify failed: %v", kind)
	}
	// Keepalive: single 0xFF.
	if kind, _ := Classify([]byte{KeepaliveByte}); kind != KindKeepalive {
		t.Fatalf("keepalive classify failed: %v", kind)
	}
	// Short junk.
	if kind, _ := Classify([]byte{0x01, 0x02}); kind != KindUnknown {
		t.Fatalf("short datagram should be unknown: %v", kind)
	}
}
