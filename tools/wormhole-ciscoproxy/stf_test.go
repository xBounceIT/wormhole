package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildSTFFrame_Shape(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	frame, err := buildSTFFrame(acData, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) != stfHeaderSz+len(payload) {
		t.Fatalf("frame length: got %d want %d", len(frame), stfHeaderSz+len(payload))
	}
	if !bytes.Equal(frame[0:4], []byte{'S', 'T', 'F', 0x01}) {
		t.Fatalf("magic: got %v", frame[0:4])
	}
	if binary.BigEndian.Uint16(frame[4:6]) != uint16(len(payload)) {
		t.Fatalf("payload length field: got %d want %d", binary.BigEndian.Uint16(frame[4:6]), len(payload))
	}
	if frame[6] != acData || frame[7] != 0 {
		t.Fatalf("type/reserved bytes: got %d %d", frame[6], frame[7])
	}
	if !bytes.Equal(frame[8:], payload) {
		t.Fatalf("payload not copied verbatim")
	}
}

func TestBuildSTFFrame_EmptyPayloadControl(t *testing.T) {
	frame, err := buildSTFFrame(acDPDResp, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) != stfHeaderSz {
		t.Fatalf("control frame length: got %d want %d", len(frame), stfHeaderSz)
	}
	if binary.BigEndian.Uint16(frame[4:6]) != 0 {
		t.Fatal("control frame should carry zero payload length")
	}
	if frame[6] != acDPDResp {
		t.Fatalf("type: got %d want %d", frame[6], acDPDResp)
	}
}

func TestBuildSTFFrame_RejectsOversized(t *testing.T) {
	if _, err := buildSTFFrame(acData, make([]byte, cstpMaxPayloadLen+1)); err == nil {
		t.Fatal("expected an error for a payload past the framing cap")
	}
}
