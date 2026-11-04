package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("WORMHOLE_FRAMEBUFFER_TEST_HELPER") != "1" {
		return
	}
	var count uint32
	if binary.Read(os.Stdin, binary.BigEndian, &count) != nil {
		os.Exit(1)
	}
	for i := uint32(0); i < count; i++ {
		var length uint32
		if binary.Read(os.Stdin, binary.BigEndian, &length) != nil || length > rdpMaxCommandBytes {
			os.Exit(2)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(os.Stdin, data); err != nil {
			os.Exit(3)
		}
		if string(data) == "/f" || string(data) == "/multimon" {
			os.Exit(4)
		}
	}
	_ = binary.Write(os.Stdout, binary.BigEndian, [7]uint32{1})
	_ = binary.Write(os.Stdout, binary.BigEndian, [7]uint32{2, 1, 1, 0, 0, 1, 1})
	_, _ = os.Stdout.Write([]byte{255, 0, 0, 255})
	_ = binary.Write(os.Stdout, binary.BigEndian, [7]uint32{3, 1})
	os.Exit(0)
}

func framebufferPacket(header [7]uint32, pixels []byte) []byte {
	var buffer bytes.Buffer
	_ = binary.Write(&buffer, binary.BigEndian, header)
	buffer.Write(pixels)
	return buffer.Bytes()
}

func TestFramebufferTilesValidateBeforeAllocation(t *testing.T) {
	pixels := []byte{0, 255, 0, 255}
	event, err := readRdpFramebufferEvent(bytes.NewReader(framebufferPacket([7]uint32{2, 800, 600, 5, 7, 1, 1}, pixels)))
	if err != nil || event.Type != "frame" || !bytes.Equal(event.Frame.RGBA, pixels) || event.Frame.X != 5 {
		t.Fatalf("frame=%+v err=%v", event, err)
	}
	for _, header := range [][7]uint32{
		{2, 0, 1, 0, 0, 1, 1}, {2, 16385, 1, 0, 0, 1, 1}, {2, 16384, 16384, 0, 0, 1, 1},
		{2, 1, 1, 0, 0, 0, 1}, {2, 256, 256, 0, 0, 129, 1}, {2, 1, 1, 1, 0, 1, 1}, {2, 1, 1, 0, 1, 1, 1},
		{2, 1, 1, 0xffffffff, 0, 1, 1}, {42},
	} {
		if _, err := readRdpFramebufferEvent(bytes.NewReader(framebufferPacket(header, nil))); err == nil {
			t.Fatalf("accepted %v", header)
		}
	}
	for _, data := range [][]byte{{}, {2}, framebufferPacket([7]uint32{2, 1, 1, 0, 0, 1, 1}, []byte{1})} {
		if _, err := readRdpFramebufferEvent(bytes.NewReader(data)); err == nil {
			t.Fatal("accepted truncated packet")
		}
	}
	for kind, name := range map[uint32]string{1: "connected", 3: "frameEnd"} {
		event, err := readRdpFramebufferEvent(bytes.NewReader(framebufferPacket([7]uint32{kind, 1}, nil)))
		if err != nil || event.Type != name {
			t.Fatalf("event=%+v err=%v", event, err)
		}
	}
	event, err = readRdpFramebufferEvent(bytes.NewReader(framebufferPacket([7]uint32{4, 4, 5}, []byte("hostSHA:1"))))
	if err != nil || event.Certificate.Host != "host" || event.Certificate.Fingerprint != "SHA:1" {
		t.Fatal("certificate notice was not decoded")
	}
	for _, data := range [][]byte{
		framebufferPacket([7]uint32{4, 0, 5}, nil), framebufferPacket([7]uint32{4, 4097, 5}, nil),
		framebufferPacket([7]uint32{4, 1, 0}, nil), framebufferPacket([7]uint32{4, 1, 4097}, nil),
		framebufferPacket([7]uint32{4, 1, 1}, []byte{0xff, 0xff}), framebufferPacket([7]uint32{4, 1, 1}, nil),
	} {
		if _, err := readRdpFramebufferEvent(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid certificate notice accepted")
		}
	}
}

func TestFramebufferInputAndGeometryContract(t *testing.T) {
	commands := []rdpCommand{
		{Op: "certificate", CertificateAccepted: true}, {Op: "certificate", CertificateAccepted: false},
		{Op: "input", Input: &rdpInput{Kind: "pointer", X: 100, Y: 200, Flags: 0x9000}},
		{Op: "input", Input: &rdpInput{Kind: "key", Code: 0x11d, Down: true}},
		{Op: "input", Input: &rdpInput{Kind: "unicode", Code: 0x20ac}},
		{Op: "input", Input: &rdpInput{Kind: "release"}}, {Op: "input", Input: &rdpInput{Kind: "painted", Code: 1}},
		{Op: "resize", Bounds: rdpBounds{Width: 800, Height: 600}}, {Op: "show"}, {Op: "hide"}, {Op: "focus"},
	}
	for _, command := range commands {
		data, err := encodeRdpFramebufferCommand(command)
		if err != nil || len(data) != 20 {
			t.Fatalf("command=%+v err=%v", command, err)
		}
		writer := &rdpRecordingWriteCloser{}
		process := &rdpProcess{stdin: writer}
		if err := process.writeFramebuffer(command); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(writer.Bytes(), data) {
			t.Fatal("native command framing changed")
		}
	}
	for _, command := range []rdpCommand{{Op: "input"}, {Op: "invalid"}, {Op: "resize"}, {Op: "input", Input: &rdpInput{Kind: "key", Code: 512}}} {
		if _, err := encodeRdpFramebufferCommand(command); err == nil {
			t.Fatal("invalid command accepted")
		}
		if err := (&rdpProcess{}).writeFramebuffer(command); err == nil {
			t.Fatal("invalid command written")
		}
	}
	for _, input := range []rdpInput{{Kind: "unknown"}, {Kind: "pointer", X: -1}, {Kind: "pointer", Flags: 1}, {Kind: "unicode", Code: 65536}, {Kind: "key", Code: 0}} {
		if input.valid() {
			t.Fatalf("invalid input accepted %+v", input)
		}
	}
	for _, flags := range []int{0x0800, 0x1000, 0x2000, 0x4000, 0x9000, 0xa000, 0xc000, 0x0278, 0x0388} {
		if !(rdpInput{Kind: "pointer", Flags: flags}).valid() {
			t.Fatalf("flags %x rejected", flags)
		}
	}
}

func TestFramebufferSettingsUseOnlyPrivatePipe(t *testing.T) {
	var buffer bytes.Buffer
	args := []string{"/v:rdp.example", "/p:private-password"}
	if err := writeRdpFramebufferStart(&buffer, args); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(buffer.Bytes()) != 2 || !bytes.Contains(buffer.Bytes(), []byte("private-password")) {
		t.Fatal("settings framing failed")
	}
	if err := writeRdpFramebufferStart(io.Discard, make([]string, 257)); err == nil {
		t.Fatal("argument count was not bounded")
	}
	if err := writeRdpFramebufferStart(io.Discard, []string{strings.Repeat("x", rdpMaxCommandBytes)}); err == nil {
		t.Fatal("settings size was not bounded")
	}
	if err := writeRdpFramebufferStart(rdpFailingWriter{}, args); err == nil {
		t.Fatal("write error swallowed")
	}
}

type rdpFailingWriter struct{}

func TestFramebufferWriteTimeoutAndClosedPipe(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	process := &rdpProcess{stdin: writer}
	err := process.framebufferWrite(func() error { _, err := writer.Write([]byte("blocked")); return err }, 10*time.Millisecond)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked write: %v", err)
	}
	if err := (&rdpProcess{}).writeFramebuffer(rdpCommand{Op: "show"}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := process.writeFramebuffer(rdpCommand{Op: "show"}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestFramebufferStrictCertificateAndResize(t *testing.T) {
	for _, policy := range []int{0, 1, 2} {
		args, err := buildFramebufferArguments(rdpCommand{Profile: rdpProfile{Host: "host", ServerAuthentication: &policy, FullScreen: true, UseAllMonitors: true}})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "/cert:deny") != (policy == 1) || strings.Contains(joined, "/cert-ignore") != (policy == 0) {
			t.Fatal(joined)
		}
		for _, arg := range args {
			if arg == "/f" || arg == "/multimon" {
				t.Fatal("external window option", arg)
			}
		}
	}
	data, err := encodeRdpFramebufferCommand(rdpCommand{Op: "resize", Bounds: rdpBounds{Width: 16384, Height: 16384}})
	if err != nil || binary.BigEndian.Uint32(data[4:]) != 8192 || binary.BigEndian.Uint32(data[8:]) != 8192 {
		t.Fatal("oversized display layout", err)
	}
	if _, err := readRdpFramebufferEvent(bytes.NewReader(framebufferPacket([7]uint32{3}, nil))); err == nil {
		t.Fatal("missing sequence accepted")
	}
	if (rdpInput{Kind: "painted"}).valid() {
		t.Fatal("missing acknowledgement sequence accepted")
	}
}

func (rdpFailingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestFramebufferHostLifecycle(t *testing.T) {
	t.Setenv("WORMHOLE_FREERDP_HOST", os.Args[0])
	t.Setenv("WORMHOLE_FRAMEBUFFER_TEST_HELPER", "1")
	if locateRdpFramebufferHost() != os.Args[0] {
		t.Fatal("host override ignored")
	}
	controller := &rdpController{processes: make(map[string]*rdpProcess)}
	controller.startFramebufferRdp(rdpCommand{SessionID: "canvas", LifecycleID: "attempt", RequestID: "start", Profile: rdpProfile{Host: "rdp.example", FullScreen: true, UseAllMonitors: true}})
	waitForRdpProcessExit(t, controller, "canvas")
	t.Setenv("WORMHOLE_FREERDP_HOST", filepath.Join(t.TempDir(), "missing-host"))
	controller.startFramebufferRdp(rdpCommand{SessionID: "missing", Profile: rdpProfile{Host: "rdp.example"}})
	controller.startFramebufferRdp(rdpCommand{SessionID: "invalid", Profile: rdpProfile{Host: ""}})
	if len(controller.processes) != 0 {
		t.Fatal("failed start retained process")
	}
	t.Setenv("WORMHOLE_FREERDP_HOST", "")
	if locateRdpFramebufferHost() == "" {
		t.Fatal("bundled host path missing")
	}
}

func TestFramebufferForwardRejectsStaleInput(t *testing.T) {
	writer := &rdpRecordingWriteCloser{}
	process := &rdpProcess{sessionID: "canvas", lifecycleID: "new", backend: "freerdp", framebuffer: true, stdin: writer}
	controller := &rdpController{processes: map[string]*rdpProcess{"canvas": process}}
	controller.handle(rdpCommand{SessionID: "canvas", LifecycleID: "new", Op: "input", Input: &rdpInput{Kind: "release"}})
	controller.forward(rdpCommand{SessionID: "canvas", LifecycleID: "old", Op: "input", Input: &rdpInput{Kind: "key", Code: 1, Down: true}})
	controller.forward(rdpCommand{SessionID: "canvas", LifecycleID: "new", Op: "input"})
	if writer.Len() != 20 || binary.BigEndian.Uint32(writer.Bytes()) != 7 {
		t.Fatal("stale or invalid input reached the native session")
	}
}
