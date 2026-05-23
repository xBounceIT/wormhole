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
