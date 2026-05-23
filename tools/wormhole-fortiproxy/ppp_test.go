package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildEncapFrame_Roundtrip(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	frame, err := buildEncapFrame(pppProtoLCP, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frame) != fortinetEncapHeaderSz+2+len(payload) {
		t.Errorf("len(frame)=%d want %d", len(frame), fortinetEncapHeaderSz+2+len(payload))
	}
	total := binary.BigEndian.Uint16(frame[0:2])
	if int(total) != len(frame) {
		t.Errorf("total len field=%d want %d", total, len(frame))
	}
	magic := binary.BigEndian.Uint16(frame[2:4])
	if magic != fortinetEncapMagic {
		t.Errorf("magic=%#x want %#x", magic, fortinetEncapMagic)
	}
	payloadLen := binary.BigEndian.Uint16(frame[4:6])
	if int(payloadLen) != 2+len(payload) {
		t.Errorf("payload len field=%d want %d", payloadLen, 2+len(payload))
	}
	proto := binary.BigEndian.Uint16(frame[6:8])
	if proto != pppProtoLCP {
		t.Errorf("proto=%#x want %#x", proto, pppProtoLCP)
	}
	if !bytes.Equal(frame[8:], payload) {
		t.Errorf("payload mismatch")
	}
}

func TestBuildEncapFrame_RejectsOversize(t *testing.T) {
	// Payload large enough that header + 2-byte PPP proto field + payload exceeds uint16
	// (0xFFFF). Without the size guard the length fields would silently wrap and corrupt
	// the wire framing — locked here so a future regression is caught.
	const tooBig = 0x10000 // 65536 bytes
	_, err := buildEncapFrame(pppProtoIPv4, make([]byte, tooBig))
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestBuildEncapFrame_MaxBoundary(t *testing.T) {
	// Exactly at the boundary: payload = 0xFFFF - 6 - 2 = 65527.
	max := 0xFFFF - fortinetEncapHeaderSz - 2
	frame, err := buildEncapFrame(pppProtoIPv4, make([]byte, max))
	if err != nil {
		t.Fatalf("max boundary should succeed; got error: %v", err)
	}
	if len(frame) != 0xFFFF {
		t.Errorf("expected frame len 0xFFFF, got %d", len(frame))
	}
	// One byte over should fail.
	_, err = buildEncapFrame(pppProtoIPv4, make([]byte, max+1))
	if err == nil {
		t.Fatal("max+1 should fail; got nil")
	}
}

func TestExtractIPCPAddress_LegitimateOption(t *testing.T) {
	// Simple IPCP body with just the IP-Address option (type=3, len=6).
	body := []byte{0x03, 0x06, 10, 0, 0, 5}
	addr, ok := extractIPCPAddress(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if addr.String() != "10.0.0.5" {
		t.Errorf("got %v want 10.0.0.5", addr)
	}
}

func TestExtractIPCPAddress_AfterOtherOption(t *testing.T) {
	// RFC 1877 Primary-DNS option (type=129, len=6) followed by IP-Address (type=3, len=6).
	body := []byte{
		0x81, 0x06, 8, 8, 8, 8, // Primary-DNS = 8.8.8.8
		0x03, 0x06, 10, 0, 0, 5, // IP-Address = 10.0.0.5
	}
	addr, ok := extractIPCPAddress(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if addr.String() != "10.0.0.5" {
		t.Errorf("got %v want 10.0.0.5", addr)
	}
}

func TestExtractIPCPAddress_IgnoresFalsePositiveInOtherOptionValue(t *testing.T) {
	// W14: an unrelated option (type=0x81 Primary-DNS, len=6) whose payload happens to
	// contain the byte sequence 0x03, 0x06, 0x01, 0x01 would have been picked up by a
	// sliding-window scan as a fake IP-Address option. Proper option-walking skips past
	// the whole DNS option and never sees its value bytes as a new (type, len) pair, so
	// we correctly return ok=false (no real IP-Address option in this body).
	body := []byte{
		0x81, 0x06, 0x03, 0x06, 0x01, 0x01,
	}
	addr, ok := extractIPCPAddress(body)
	if ok {
		t.Fatalf("expected ok=false (no real IP-Address option); got addr=%v", addr)
	}
}

func TestExtractIPCPAddress_AbortsOnMalformedLength(t *testing.T) {
	// l=1 < 2 is malformed; we abort rather than blindly skipping one byte (which would
	// shift the parser onto value bytes and resurface the same false-positive problem
	// the sliding-window approach had).
	body := []byte{0x01, 0x01, 0x03, 0x06, 10, 0, 0, 5}
	_, ok := extractIPCPAddress(body)
	if ok {
		t.Fatal("expected ok=false on malformed-length prefix")
	}
}
