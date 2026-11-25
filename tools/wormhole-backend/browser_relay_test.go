package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestBrowserRelaySwapsUpstreamsAndClosesOldStreams(t *testing.T) {
	input, commands := io.Pipe()
	replies, output := io.Pipe()
	done := make(chan int, 1)
	go func() {
		defer output.Close()
		done <- runBackendCLI([]string{"--operation", "browser-relay"}, input, output, io.Discard)
	}()
	t.Cleanup(func() {
		_ = replies.Close()
		_ = commands.Close()
	})
	encoder, decoder := json.NewEncoder(commands), json.NewDecoder(replies)
	request := func(action, id string, port int) backendResponse {
		t.Helper()
		command := backendCommand{ID: "request", Action: action, SessionID: id, Port: port}
		if err := encoder.Encode(command); err != nil {
			t.Fatal(err)
		}
		var response backendResponse
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.ID != command.ID {
			t.Fatalf("response ID = %q", response.ID)
		}
		return response
	}
	open := request("browser-relay.open", "browser-one", 0)
	if !open.OK || open.ForwardPort < 1 {
		t.Fatalf("open = %+v", open)
	}
	if duplicate := request("browser-relay.open", "browser-one", 0); duplicate.OK {
		t.Fatal("accepted duplicate endpoint")
	}
	if loop := request("browser-relay.route", "browser-one", open.ForwardPort); loop.OK {
		t.Fatal("accepted another relay endpoint as an upstream")
	}
	if invalid := request("browser-relay.route", "browser-one", 65536); invalid.OK {
		t.Fatal("accepted invalid TCP port")
	}
	if unknown := request("tunnel.acquire", "browser-one", 0); unknown.OK {
		t.Fatal("relay service accepted a workspace command")
	}

	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: open.ForwardPort}
	dial := func() *net.TCPConn {
		t.Helper()
		connection, err := net.DialTimeout("tcp4", local.String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() { _ = connection.Close() })
		return connection.(*net.TCPConn)
	}
	startUpstream := func() *net.TCPListener {
		t.Helper()
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: local.IP})
		if err != nil {
			t.Fatal(err)
		}
		_ = listener.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() { _ = listener.Close() })
		return listener
	}
	readClosed := func(connection net.Conn) {
		t.Helper()
		n, err := connection.Read(make([]byte, 1))
		if timeout, ok := err.(net.Error); n != 0 || err == nil || (ok && timeout.Timeout()) {
			t.Fatalf("expected a closed stream, read %d bytes with %v", n, err)
		}
	}
	routeTo := func(port int) {
		t.Helper()
		if answer := request("browser-relay.route", "browser-one", port); !answer.OK {
			t.Fatalf("route = %+v", answer)
		}
	}

	readClosed(dial())
	first := startUpstream()
	routeTo(first.Addr().(*net.TCPAddr).Port)
	browser := dial()
	oldUpstream, err := first.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer oldUpstream.Close()
	_ = oldUpstream.SetDeadline(time.Now().Add(2 * time.Second))
	routeTo(0)
	readClosed(browser)
	readClosed(oldUpstream)
	readClosed(dial())

	second := startUpstream()
	routeTo(second.Addr().(*net.TCPAddr).Port)
	browser = dial()
	upstream, err := second.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := browser.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := browser.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(upstream); err != nil || !bytes.Equal(got, []byte("request")) {
		t.Fatalf("upstream read = %q, %v", got, err)
	}
	if _, err := upstream.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(browser); err != nil || !bytes.Equal(got, []byte("reply")) {
		t.Fatalf("browser read = %q, %v", got, err)
	}
	if answer := request("browser-relay.close", "browser-one", 0); !answer.OK {
		t.Fatalf("close = %+v", answer)
	}
	if connection, err := net.DialTimeout("tcp4", local.String(), 2*time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("retired endpoint is still listening")
	}
	_ = commands.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("relay service exited with %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay service did not stop on EOF")
	}
}
