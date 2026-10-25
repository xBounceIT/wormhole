package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func FuzzForcepointWireInputs(f *testing.F) {
	f.Add(fpTestWire(fpVersionResponse, []byte{0, 9, 0, 1, 0, 0, 0, 0}))
	f.Add(fpTestNetwork(fpTestAttributes, fpTestPolicy))
	f.Add([]byte(fpTestPolicy))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		_, _, _ = readForcepointFrame(bytes.NewReader(data))
		_, _ = parseForcepointNetwork(data)
		_ = validateForcepointPolicy(data)
	})
}

func TestForcepointRejectsAmbiguousSecurityCheckAttributes(t *testing.T) {
	for _, check := range []string{
		`<antivirus enabled="1" enabled="0"/>`,
		`<antivirus enabled="0" enabled="0"/>`,
		`<antivirus xmlns:x="urn:other" enabled="1" x:enabled="0"/>`,
		`<antivirus xmlns:x="urn:other" x:enabled="0"/>`,
	} {
		if err := validateForcepointPolicy([]byte(`<client-config><security-checks>` + check + `</security-checks></client-config>`)); err == nil {
			t.Fatalf("accepted ambiguous security check: %s", check)
		}
	}
}

func TestForcepointQueuedIPv4CannotCrossAuthenticationBoundary(t *testing.T) {
	for _, mode := range []string{"paused", "expired"} {
		t.Run(mode, func(t *testing.T) {
			sess, output := fpTestSession()
			sess.expires.Store(time.Now().Add(time.Hour).UnixNano())
			// A packet passed the writer's initial check, but is queued behind
			// another write when the reader suspends or expires authentication.
			sess.writeMu.Lock()
			started := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				if sess.paused.Load() {
					panic("test packet did not reach the write queue")
				}
				close(started)
				result <- sess.write(fpIPv4, make([]byte, 20))
			}()
			<-started
			if mode == "paused" {
				sess.pause()
			} else {
				sess.expires.Store(time.Now().Add(-time.Second).UnixNano())
			}
			sess.writeMu.Unlock()
			err := <-result
			if mode == "expired" && err == nil {
				t.Error("expired authentication did not terminate the writer")
			}
			if output.Len() != 0 {
				t.Fatal("queued IPv4 packet crossed the authentication boundary")
			}
		})
	}
}

func TestForcepointExpiredInboundDataClosesBeforeNextKeepalive(t *testing.T) {
	networkStack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1390)
	if err != nil {
		t.Fatal(err)
	}
	defer networkStack.Close()
	client, peer := net.Pipe()
	defer peer.Close()
	sess := &forcepointSession{conn: client, cfg: fpTestConfig(), configured: true}
	sess.lastReply.Store(time.Now().UnixNano())
	sess.expires.Store(time.Now().Add(-time.Second).UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runForcepoint(ctx, sess, endpoint, time.Hour)
		close(done)
	}()
	defer func() { cancel(); _ = peer.Close(); <-done }()
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write(fpTestWire(fpIPv4, make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expired inbound data waited for the next keepalive before teardown")
	}
}

func TestForcepointNetworkSnapshotRemainsImmutableDuringReconfiguration(t *testing.T) {
	sess, _ := fpTestSession()
	network, err := parseForcepointNetwork(fpTestNetwork(fpTestAttributes, fpTestPolicy))
	if err != nil {
		t.Fatal(err)
	}
	sess.network, sess.configured = network, true
	start, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		<-start
		// Startup may still read the initial snapshot to construct its dialer
		// while the transport reader receives an immediate configuration update.
		for range 1000 {
			_ = newNetstackDialer(nil, sess.network.address, sess.network.dns)
		}
	}()
	close(start)
	for range 1000 {
		sess.configuring = true
		if err := sess.handleFrame(fpControl, fpTestControl(fpIPResponse, fpTestNetwork(fpTestAttributes, fpTestPolicy))); err != nil {
			t.Error(err)
			break
		}
	}
	<-done
}
