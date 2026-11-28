package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRdpNativeHandoffConsumesOnceAndWipesEveryExit(t *testing.T) {
	failure := errors.New("setter failed")
	for _, mode := range []string{"success", "error", "panic", "nil", "closed"} {
		t.Run(mode, func(t *testing.T) {
			password, gateway := []byte("native-primary"), []byte("native-gateway")
			h := newRdpNativeHandoff(password, gateway, true, true)
			h.start(time.Second, func() { t.Error("late native credential timeout") })
			defer h.close()
			var calls int
			apply := func(ref, p, g []byte, primary, secondary bool) error {
				calls++
				if string(ref) != "local-reference" || !bytes.Equal(p, password) || !bytes.Equal(g, gateway) || !primary || !secondary {
					t.Fatal("credential handoff context")
				}
				if mode == "error" {
					return failure
				}
				if mode == "panic" {
					panic(failure)
				}
				return nil
			}
			switch mode {
			case "nil":
				apply = nil
			case "closed":
				h.close()
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() != failure {
							t.Fatal("setter panic lost")
						}
					}()
					_ = h.consume([]byte("local-reference"), apply)
				}()
			} else {
				err := h.consume([]byte("local-reference"), apply)
				if (err == nil) != (mode == "success") || (mode == "error" && err != failure) {
					t.Fatal(mode, err)
				}
			}
			if h.applied() != (mode == "success") {
				t.Fatal("handoff state")
			}
			if !bytes.Equal(password, make([]byte, len(password))) || !bytes.Equal(gateway, make([]byte, len(gateway))) {
				t.Fatal("native buffers retained")
			}
			if err := h.consume(nil, func([]byte, []byte, []byte, bool, bool) error { t.Fatal("credential replay"); return nil }); err != errRdpNativeHandoff {
				t.Fatal(err)
			}
			if calls != func() int {
				if mode == "nil" || mode == "closed" {
					return 0
				}
				return 1
			}() {
				t.Fatal("setter count")
			}
		})
	}
	var absent *rdpNativeHandoff
	if !absent.applied() {
		t.Fatal("metadata-only native session")
	}
	absent.close()
	if err := absent.consume(nil, nil); err != errRdpNativeHandoff {
		t.Fatal(err)
	}
}

func TestRdpNativeHandoffCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"pending-timeout", "inflight-timeout", "concurrent", "close"} {
		t.Run(mode, func(t *testing.T) {
			secret := []byte("temporary-password")
			h := newRdpNativeHandoff(secret, nil, true, false)
			interrupted := make(chan struct{})
			var count atomic.Int32
			h.start(25*time.Millisecond, func() {
				if count.Add(1) == 1 {
					close(interrupted)
				}
			})
			defer h.close()
			switch mode {
			case "pending-timeout":
				select {
				case <-interrupted:
				case <-time.After(time.Second):
					t.Fatal("timeout did not interrupt")
				}
				h.close()
				if err := h.consume(nil, func([]byte, []byte, []byte, bool, bool) error { t.Fatal("expired setter"); return nil }); err != errRdpNativeHandoff {
					t.Fatal(err)
				}
			case "inflight-timeout":
				err := h.consume(nil, func([]byte, []byte, []byte, bool, bool) error {
					select {
					case <-interrupted:
					case <-time.After(time.Second):
						t.Fatal("inflight COM call not interrupted")
					}
					return nil
				})
				if err != errRdpNativeHandoff {
					t.Fatal("expired call succeeded", err)
				}
			case "concurrent":
				h.close()
				h = newRdpNativeHandoff(secret, nil, true, false)
				h.start(time.Second, func() { t.Error("late timeout") })
				var group sync.WaitGroup
				var setters atomic.Int32
				for i := 0; i < 12; i++ {
					group.Add(1)
					go func() {
						defer group.Done()
						err := h.consume(nil, func([]byte, []byte, []byte, bool, bool) error { setters.Add(1); return nil })
						if err != nil && err != errRdpNativeHandoff {
							t.Error(err)
						}
					}()
				}
				group.Wait()
				if setters.Load() != 1 {
					t.Fatal("double credential delivery")
				}
				h.close()
			case "close":
				h.close()
				h.start(time.Millisecond, func() { t.Error("closed handoff restarted") })
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("timed-out credentials retained")
			}
		})
	}
}

func TestRdpNativeCommandPipeAndReplyContainNoCredentials(t *testing.T) {
	var output bytes.Buffer
	process := &rdpProcess{stdin: fixtureRdpWriteCloser{Writer: &output}, sessionID: "session", lifecycleID: "lifecycle", startRequestID: "start"}
	if err := process.write(rdpCommand{Op: "start", RequestID: "start", Profile: rdpProfile{Host: "server", Password: "primary-secret", GatewayPassword: "gateway-secret"}}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("secret")) || bytes.Contains(output.Bytes(), []byte(`"password"`)) || bytes.Contains(output.Bytes(), []byte(`"gatewayPassword"`)) {
		t.Fatal("C# pipe received password")
	}
	process.nativeHandoff = newRdpNativeHandoff([]byte("owned-secret"), nil, true, false)
	process.nativeHandoff.start(time.Second, func() { t.Error("late timeout") })
	defer process.nativeHandoff.close()
	if runningNativeControl(process, rdpEvent{Type: "nativeControl", RequestID: "wrong", NativeControl: []byte("reference")}, func([]byte, []byte, []byte, bool, bool) error { t.Fatal("wrong request reached setter"); return nil }) {
		t.Fatal("wrong native control owner")
	}
	output.Reset()
	if !runningNativeControl(process, rdpEvent{Type: "nativeControl", RequestID: "start", NativeControl: []byte("reference")}, func([]byte, []byte, []byte, bool, bool) error { return nil }) {
		t.Fatal("native control rejected")
	}
	var command map[string]any
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &command) != nil || command["op"] != "connect" || command["requestId"] != "start" || bytes.Contains(output.Bytes(), []byte("owned-secret")) {
		t.Fatal("native connection acknowledgement")
	}
	if runningNativeControl(process, rdpEvent{Type: "nativeControl", RequestID: "start", NativeControl: []byte("reference")}, func([]byte, []byte, []byte, bool, bool) error { return nil }) {
		t.Fatal("native control replay")
	}
}

type fixtureRdpWriteCloser struct{ Writer *bytes.Buffer }

func (w fixtureRdpWriteCloser) Write(b []byte) (int, error) { return w.Writer.Write(b) }
func (w fixtureRdpWriteCloser) Close() error                { return nil }

func TestRdpNativeHandoffCloseCancelsInflightSetter(t *testing.T) {
	secret := []byte("cancelled-password")
	h := newRdpNativeHandoff(secret, nil, true, false)
	h.start(time.Second, func() { t.Error("late timeout") })
	h.start(time.Millisecond, func() { t.Error("handoff timer replaced") })
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.consume(nil, func([]byte, []byte, []byte, bool, bool) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	closed := make(chan struct{})
	go func() { h.close(); close(closed) }()
	deadline := time.Now().Add(time.Second)
	for h.state.Load() != 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.state.Load() != 3 {
		t.Fatal("close did not cancel setter")
	}
	close(release)
	if err := <-result; err != errRdpNativeHandoff {
		t.Fatal("cancelled setter succeeded", err)
	}
	<-closed
	if h.applied() || !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("cancelled credential handoff retained state")
	}
}

func TestRdpNativeEventReaderRejectsEarlyAndReplayedCapabilities(t *testing.T) {
	for _, mode := range []string{"early-ready", "capability-leak", "wrong-request", "empty-reference", "setter-error", "write-error", "replay"} {
		t.Run(mode, func(t *testing.T) {
			secret := []byte("owned-event-secret")
			handoff := newRdpNativeHandoff(secret, nil, true, false)
			handoff.start(time.Second, func() { t.Error("late event timeout") })
			defer handoff.close()
			writer := &rdpRecordingWriteCloser{}
			process := &rdpProcess{sessionID: "session", startRequestID: "start", stdin: writer, nativeHandoff: handoff, nativeEventsDone: make(chan struct{})}
			calls := 0
			controller := &rdpController{processes: map[string]*rdpProcess{"session": process}, nativeCredentialApply: func([]byte, []byte, []byte, bool, bool) error {
				calls++
				if mode == "setter-error" {
					return errors.New("native setter error")
				}
				return nil
			}}
			event := rdpEvent{Type: "nativeControl", RequestID: "start", NativeControl: []byte("local-reference")}
			switch mode {
			case "early-ready":
				event = rdpEvent{Type: "ready", RequestID: "start"}
			case "capability-leak":
				event.Type = "ready"
			case "wrong-request":
				event.RequestID = "other"
			case "empty-reference":
				event.NativeControl = nil
			case "write-error":
				process.stdin = fixtureRdpFailingWriteCloser{}
			}
			raw, _ := json.Marshal(event)
			input := string(raw) + "\n"
			if mode == "replay" {
				input += input
			}
			controller.readNativeEvents(process, io.NopCloser(strings.NewReader(input)))
			if handoff.applied() || len(handoff.password) != 0 || !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("rejected native event retained authority or credentials")
			}
			expected := 0
			if mode == "setter-error" || mode == "write-error" || mode == "replay" {
				expected = 1
			}
			if calls != expected {
				t.Fatal("unexpected native setter count", calls)
			}
			select {
			case <-process.nativeEventsDone:
			default:
				t.Fatal("native event reader did not complete")
			}
		})
	}
}

type fixtureRdpFailingWriteCloser struct{}

func (fixtureRdpFailingWriteCloser) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (fixtureRdpFailingWriteCloser) Close() error              { return nil }

func TestLegacyRdpHandoffCopiesOnlySelectedCredentials(t *testing.T) {
	for _, mode := range []string{"none", "primary", "gateway", "both", "shared", "disabled"} {
		p := rdpProfile{GatewayUsageMethod: 1}
		if mode == "primary" || mode == "both" || mode == "shared" || mode == "disabled" {
			p.Password = "primary"
		}
		if mode == "gateway" || mode == "both" || mode == "shared" || mode == "disabled" {
			p.GatewayPassword = "gateway"
		}
		if mode == "shared" {
			p.GatewayUseSameCreds = true
		}
		if mode == "disabled" {
			p.GatewayUsageMethod = 0
		}
		h := legacyRdpNativeHandoff(&p)
		if mode == "none" {
			if h != nil {
				t.Fatal("empty handoff")
			}
			continue
		}
		wantGateway := mode == "gateway" || mode == "both" || mode == "shared"
		if h == nil || h.gatewayProvided != wantGateway || (len(h.gateway) > 0) != wantGateway || h.primaryProvided != (mode != "gateway") {
			t.Fatal("unselected secret copied", mode)
		}
		h.close()
	}
}

func TestRdpStoredSharedPasswordUsesTwoExplicitNativeCredentials(t *testing.T) {
	for _, mode := range []string{"stored", "empty", "prompt", "disabled", "independent"} {
		p := rdpProfile{Username: "remote-user", Domain: "DOMAIN", GatewayUsageMethod: 1, GatewayUseSameCreds: true}
		password := []byte("primary-secret")
		present := true
		if mode == "empty" {
			password = []byte{}
		}
		if mode == "prompt" {
			password = nil
			present = false
		}
		if mode == "disabled" {
			p.GatewayUsageMethod = 0
		}
		if mode == "independent" {
			p.GatewayUseSameCreds = false
		}
		gateway := []byte("unused-gateway-secret")
		h := newRdpProtocolHandoff(&p, password, gateway, present, mode == "independent")
		explicit := mode == "stored" || mode == "empty"
		if explicit {
			if p.GatewayUseSameCreds || p.GatewayUsername != "DOMAIN\\remote-user" || !h.gatewayProvided || !bytes.Equal(h.password, h.gateway) {
				t.Fatal("stored sharing did not create explicit native credentials", mode)
			}
			if len(password) > 0 {
				h.gateway[0] ^= 1
				if h.gateway[0] == password[0] {
					t.Fatal("credential buffers share mutable ownership")
				}
			}
		} else if mode == "prompt" {
			if !p.GatewayUseSameCreds || h.gatewayProvided || len(h.gateway) != 0 {
				t.Fatal("native prompt sharing lost")
			}
		}
		if mode != "independent" && !bytes.Equal(gateway, make([]byte, len(gateway))) {
			t.Fatal("unselected gateway input retained")
		}
		h.close()
	}
	p := rdpProfile{Username: "DOMAIN\\qualified", Domain: "IGNORED", GatewayUsageMethod: 1, GatewayUseSameCreds: true}
	h := newRdpProtocolHandoff(&p, []byte("secret"), nil, true, false)
	defer h.close()
	if p.GatewayUsername != "DOMAIN\\qualified" {
		t.Fatal("gateway domain duplicated")
	}
}
