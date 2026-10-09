package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHShellExitLifecycle(t *testing.T) {
	for _, test := range []struct {
		name       string
		request    string
		payload    []byte
		drop       bool
		earlyClose bool
		reconnect  bool
	}{
		{name: "exit zero", request: "exit-status", payload: ssh.Marshal(struct{ Status uint32 }{0})},
		{name: "exit nonzero", request: "exit-status", payload: ssh.Marshal(struct{ Status uint32 }{7})},
		{name: "close before output starts", request: "exit-status", payload: ssh.Marshal(struct{ Status uint32 }{0}), earlyClose: true},
		{name: "shell signal", request: "exit-signal", payload: ssh.Marshal(struct {
			Signal string
			Core   bool
			Error  string
			Lang   string
		}{Signal: "TERM"})},
		{name: "missing exit status", reconnect: true},
		{name: "transport lost", drop: true, reconnect: true},
	} {
		for _, streaming := range []bool{false, true} {
			t.Run(fmt.Sprint(test.name, "/stream=", streaming), func(t *testing.T) {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				config := &ssh.ServerConfig{NoClientAuth: true}
				config.AddHostKey(signer)
				remoteDone := make(chan error, 1)
				exitReported := make(chan struct{})
				go func() {
					remoteDone <- func() error {
						raw, err := listener.Accept()
						if err != nil {
							return err
						}
						defer raw.Close()
						connection, channels, requests, err := ssh.NewServerConn(raw, config)
						if err != nil {
							return err
						}
						defer connection.Close()
						go ssh.DiscardRequests(requests)
						channelRequest := <-channels
						if channelRequest == nil {
							return errors.New("missing session channel")
						}
						channel, shellRequests, err := channelRequest.Accept()
						if err != nil {
							return err
						}
						defer channel.Close()
						for request := range shellRequests {
							if err := request.Reply(true, nil); err != nil {
								return err
							}
							if request.Type != "shell" {
								continue
							}
							input := make([]byte, len("exit\r"))
							if _, err := io.ReadFull(channel, input); err != nil {
								return err
							}
							if string(input) != "exit\r" {
								return errors.New("unexpected shell input")
							}
							if test.drop {
								return nil
							}
							if _, err := channel.Write([]byte("logout\r\n")); err != nil {
								return err
							}
							if test.request != "" {
								if _, err := channel.SendRequest(test.request, false, test.payload); err != nil {
									return err
								}
							}
							if test.earlyClose {
								// Session's request handler replies only after processing
								// the preceding exit-status. Delay native.start so another
								// shutdown path wins before the shell waiter runs.
								if _, err := channel.SendRequest("exit-observed", true, nil); err != nil {
									return err
								}
								close(exitReported)
							}
							if err := channel.Close(); err != nil {
								return err
							}
							// Keep the transport alive until the client closes it, as
							// OpenSSH does after a normal shell completion.
							_ = connection.Wait()
							return nil
						}
						return errors.New("shell did not start")
					}()
				}()

				native, _, err := dialNativeSSH(context.Background(), sshTarget{
					host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, username: "operator", password: "test-password",
				}, 80, 24)
				if err != nil {
					t.Fatal(err)
				}
				var output synchronizedBuffer
				delay := time.Hour
				state := &sshReconnectState{command: sshWireCommand{
					SessionID: "exit", Password: "test-password", PasswordOverride: "test-override",
					KeyPassphraseOverride: "test-passphrase",
				}}
				server := &sshServer{
					output:                 &sshEventWriter{encoder: json.NewEncoder(&output)},
					sessions:               map[string]*sshNativeSession{"exit": native},
					pending:                make(map[string]context.CancelFunc),
					lifecycles:             map[string]*sshReconnectState{"exit": state},
					reconnectDelayOverride: &delay,
				}
				defer server.shutdown()
				native.id, native.server = "exit", server
				if streaming {
					native.terminalStream = newSSHTerminalStream(func(event sshWireEvent) {
						event.SessionID = native.id
						server.output.write(event)
						server.handle(sshWireCommand{Type: "terminal-ack", SessionID: native.id, Sequence: event.Sequence})
					})
				}
				if !test.earlyClose {
					native.start()
				}
				if err := native.write([]byte("exit\r")); err != nil {
					t.Fatal(err)
				}
				if test.earlyClose {
					select {
					case <-exitReported:
					case <-time.After(time.Second):
						t.Fatal("remote exit was not reported")
					}
					native.close(true)
					native.start()
				}
				waitForSSHTestCondition(t, "shell lifecycle event", func() bool {
					return strings.Contains(output.String(), `"type":"closed"`) || strings.Contains(output.String(), `"type":"reconnecting"`)
				})
				server.mu.Lock()
				active := server.sessions[native.id] != nil
				retained := server.lifecycles[native.id] != nil
				pending := server.pending[native.id] != nil
				server.mu.Unlock()
				if active || retained != test.reconnect || pending != test.reconnect {
					t.Fatalf("active=%v retained=%v pending=%v; reconnect=%v", active, retained, pending, test.reconnect)
				}
				command := state.commandSnapshot()
				wantSecrets := sshWireCommand{}
				if test.reconnect {
					wantSecrets.Password = "test-password"
					wantSecrets.PasswordOverride = "test-override"
					wantSecrets.KeyPassphraseOverride = "test-passphrase"
				}
				if command.Password != wantSecrets.Password || command.PasswordOverride != wantSecrets.PasswordOverride ||
					command.KeyPassphraseOverride != wantSecrets.KeyPassphraseOverride {
					t.Fatal("shell exit did not retire reconnect secrets correctly")
				}
				var lifecycle []string
				for _, event := range decodeSSHEvents(t, output.Bytes()) {
					if event.Type == "closed" || event.Type == "reconnecting" || event.Type == "reconnect-failed" {
						lifecycle = append(lifecycle, event.Type)
					}
				}
				want := "closed"
				if test.reconnect {
					want = "reconnecting"
				}
				if len(lifecycle) != 1 || lifecycle[0] != want {
					t.Fatalf("lifecycle=%v, want [%s]", lifecycle, want)
				}
				if !test.drop && !test.earlyClose && !strings.Contains(string(native.mcpReplay.snapshotTail(4096)), "logout") {
					t.Fatal("shell exit discarded final terminal output")
				}
				select {
				case err := <-remoteDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("remote SSH connection was not closed")
				}
			})
		}
	}
}

func TestSSHShellExitOnlyDisablesReconnectForItsActiveSession(t *testing.T) {
	for _, test := range []struct {
		name        string
		active      bool
		noLifecycle bool
		err         error
		disabled    bool
	}{
		{name: "normal", active: true, disabled: true},
		{name: "nonzero", active: true, err: &ssh.ExitError{}, disabled: true},
		{name: "transport error", active: true, err: io.ErrUnexpectedEOF},
		{name: "missing status", active: true, err: &ssh.ExitMissingError{}},
		{name: "replacement session"},
		{name: "retired lifecycle", active: true, noLifecycle: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			native := &sshNativeSession{id: "exit"}
			current := native
			if !test.active {
				current = &sshNativeSession{id: native.id}
			}
			state := &sshReconnectState{command: sshWireCommand{Password: "test-password"}}
			server := &sshServer{
				sessions:   map[string]*sshNativeSession{native.id: current},
				lifecycles: map[string]*sshReconnectState{native.id: state},
			}
			if test.noLifecycle {
				delete(server.lifecycles, native.id)
			}
			server.shellExited(native, test.err)
			if state.reconnectDisabled != test.disabled || (state.commandSnapshot().Password == "") != test.disabled {
				t.Fatal("shell exit modified the wrong reconnect lifecycle")
			}
		})
	}
}

func TestSSHConcurrentCloseWaitsForShellExitResult(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		reconnect bool
	}{
		{name: "exit"},
		{name: "nonzero exit", err: &ssh.ExitError{}},
		{name: "transport loss", err: &ssh.ExitMissingError{}, reconnect: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output synchronizedBuffer
			delay := time.Hour
			state := &sshReconnectState{command: sshWireCommand{SessionID: "exit", Password: "test-password"}}
			native := &sshNativeSession{id: "exit", done: make(chan struct{}), shellWaitDone: make(chan struct{})}
			server := &sshServer{
				output:                 &sshEventWriter{encoder: json.NewEncoder(&output)},
				sessions:               map[string]*sshNativeSession{native.id: native},
				pending:                make(map[string]context.CancelFunc),
				lifecycles:             map[string]*sshReconnectState{native.id: state},
				reconnectDelayOverride: &delay,
			}
			native.server = server
			var releaseResult sync.Once
			defer func() {
				releaseResult.Do(func() { close(native.shellWaitDone) })
				server.shutdown()
			}()
			var workers sync.WaitGroup
			workers.Add(3)
			for range 2 {
				go func() {
					defer workers.Done()
					native.close(true)
				}()
			}
			go func() {
				defer workers.Done()
				native.finishShellExit()
			}()
			select {
			case <-native.done:
			case <-time.After(time.Second):
				t.Fatal("native shutdown did not start")
			}
			if output.Len() != 0 {
				t.Fatal("shutdown decided reconnect before the shell result")
			}
			native.shellWaitErr = test.err
			releaseResult.Do(func() { close(native.shellWaitDone) })
			finished := make(chan struct{})
			go func() { workers.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("concurrent shutdown deadlocked")
			}
			events := decodeSSHEvents(t, output.Bytes())
			want := "closed"
			if test.reconnect {
				want = "reconnecting"
			}
			if len(events) != 1 || events[0].Type != want {
				t.Fatalf("concurrent shutdown events=%v, want one %s", events, want)
			}
		})
	}
}

func TestSSHExplicitCloseDoesNotWaitForShellExitResult(t *testing.T) {
	var output synchronizedBuffer
	state := &sshReconnectState{command: sshWireCommand{SessionID: "exit", Password: "test-password"}}
	native := &sshNativeSession{id: "exit", done: make(chan struct{}), shellWaitDone: make(chan struct{})}
	server := &sshServer{
		output:     &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:   map[string]*sshNativeSession{native.id: native},
		lifecycles: map[string]*sshReconnectState{native.id: state},
	}
	native.server = server
	defer close(native.shellWaitDone)
	finished := make(chan struct{})
	go func() { server.close(native.id); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("explicit close waited for the remote shell")
	}
	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 1 || events[0].Type != "closed" || state.commandSnapshot().Password != "" {
		t.Fatal("explicit close did not release the session and reconnect credentials")
	}
}
