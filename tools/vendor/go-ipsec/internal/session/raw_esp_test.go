package session

import (
	"bytes"
	"context"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/transport"
	"testing"
	"time"
)

func TestRawESPUsesSeparateTransport(t *testing.T) {
	control, controlPeer := transport.MemoryPair()
	raw, rawPeer := transport.MemoryPair()
	s := New(Config{DisableNATT: true})
	s.conn = control
	s.rawESP = raw
	defer s.Close()
	defer controlPeer.Close()
	defer rawPeer.Close()
	payloads := ikemsg.Payloads{}
	s.appendNATDetection(&payloads)
	s.migrateNATT()
	if len(payloads) != 0 || s.NATTMode() || !s.RawESP() {
		t.Fatal("NAT-T enabled on raw profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	esp := []byte{1, 2, 3, 4}
	if err := s.SendESP(ctx, esp); err != nil {
		t.Fatal(err)
	}
	wire, err := rawPeer.Recv(ctx)
	if err != nil || !bytes.Equal(wire, esp) {
		t.Fatal("ESP did not use IP protocol transport", err)
	}
	if err = rawPeer.Send(ctx, esp); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecvESP(ctx); err != nil || !bytes.Equal(got, esp) {
		t.Fatal(err)
	}
	ike := []byte{4, 5, 6}
	if err = s.sendDatagram(ctx, ike); err != nil {
		t.Fatal(err)
	}
	if got, err := controlPeer.Recv(ctx); err != nil || !bytes.Equal(got, ike) {
		t.Fatal("raw-mode IKE was framed for NAT-T")
	}
	if err = controlPeer.Send(ctx, ike); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RecvRaw(ctx); err != nil || !bytes.Equal(got, ike) {
		t.Fatal(err)
	}
	if err = s.SendKeepalive(ctx); err != nil {
		t.Fatal(err)
	}
	probe, stop := context.WithTimeout(ctx, time.Millisecond)
	defer stop()
	if _, err := controlPeer.Recv(probe); err == nil {
		t.Fatal("NAT keepalive sent while disabled")
	}
	s.Close()
	s.rawESP = nil
	if s.SendESP(ctx, esp) == nil {
		t.Fatal("closed raw transport used UDP")
	}
}
