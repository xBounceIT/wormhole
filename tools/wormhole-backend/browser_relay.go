package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
)

// The browser relay has its own process lifetime. Its loopback origin survives both a
// tunnel sidecar exit and a restart of the backend process that brokers VPN leases.
func serveBrowserRelays(input io.Reader, output io.Writer) error {
	relays := make(map[string]*browserRelay)
	defer func() {
		for _, relay := range relays {
			relay.close()
		}
	}()
	writer := newBackendLineWriter(output)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var command backendCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil || !validBrowserRelayID(command.ID) {
			continue
		}
		response := backendResponse{ID: command.ID}
		err := updateBrowserRelay(relays, command, &response)
		response.OK = err == nil
		if err != nil {
			response.Error = err.Error()
		}
		if err := writer.write(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func validBrowserRelayID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func updateBrowserRelay(relays map[string]*browserRelay, command backendCommand, response *backendResponse) error {
	if !validBrowserRelayID(command.SessionID) {
		return errors.New("browser VPN endpoint ID is invalid")
	}
	relay := relays[command.SessionID]
	switch command.Action {
	case "browser-relay.open":
		if relay != nil {
			return errors.New("browser VPN endpoint already exists")
		}
		opened, err := openBrowserRelay()
		if err != nil {
			return err
		}
		relays[command.SessionID] = opened
		response.ForwardPort = opened.port()
	case "browser-relay.route":
		if relay == nil {
			return errors.New("browser VPN endpoint is closed")
		}
		if command.Port < 0 || command.Port > 65535 {
			return errors.New("browser VPN upstream port is invalid")
		}
		for _, other := range relays {
			if command.Port == other.port() {
				return errors.New("browser VPN endpoints cannot forward to each other")
			}
		}
		relay.setUpstream(command.Port)
	case "browser-relay.close":
		if relay != nil {
			delete(relays, command.SessionID)
			relay.close()
		}
	default:
		return errors.New("browser VPN endpoint command is invalid")
	}
	return nil
}

type browserRelay struct {
	listener *net.TCPListener
	mu       sync.Mutex
	upstream int
	streams  map[*browserRelayStream]struct{}
}

type browserRelayStream struct {
	client *net.TCPConn
	remote *net.TCPConn
	cancel context.CancelFunc
}

func openBrowserRelay() (*browserRelay, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, errors.New("could not open the browser VPN endpoint")
	}
	relay := &browserRelay{listener: listener, streams: make(map[*browserRelayStream]struct{})}
	go relay.serve()
	return relay, nil
}

func (relay *browserRelay) port() int {
	return relay.listener.Addr().(*net.TCPAddr).Port
}

func (relay *browserRelay) setUpstream(port int) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.upstream = port
	for stream := range relay.streams {
		stream.cancel()
		_ = stream.client.Close()
		if stream.remote != nil {
			_ = stream.remote.Close()
		}
		delete(relay.streams, stream)
	}
}

func (relay *browserRelay) close() {
	relay.setUpstream(0)
	_ = relay.listener.Close()
}

func (relay *browserRelay) serve() {
	for {
		client, err := relay.listener.AcceptTCP()
		if err != nil {
			return
		}
		relay.mu.Lock()
		port := relay.upstream
		if port != 0 {
			ctx, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
			stream := &browserRelayStream{client: client, cancel: cancel}
			relay.streams[stream] = struct{}{}
			go relay.forward(ctx, stream, port)
		}
		relay.mu.Unlock()
		if port == 0 {
			_ = client.Close()
		}
	}
}

func (relay *browserRelay) forward(ctx context.Context, stream *browserRelayStream, port int) {
	defer func() {
		stream.cancel()
		_ = stream.client.Close()
		relay.mu.Lock()
		delete(relay.streams, stream)
		relay.mu.Unlock()
	}()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return
	}
	remote := connection.(*net.TCPConn)
	defer remote.Close()
	relay.mu.Lock()
	_, active := relay.streams[stream]
	if active {
		stream.remote = remote
	}
	relay.mu.Unlock()
	if !active {
		return
	}

	// Propagate EOF in each direction without losing a reply to a half-closed request.
	copyDirection := func(destination, source *net.TCPConn) {
		if _, err := io.Copy(destination, source); err != nil {
			_ = source.Close()
			_ = destination.Close()
		} else {
			_ = destination.CloseWrite()
		}
	}
	done := make(chan struct{})
	go func() {
		copyDirection(remote, stream.client)
		close(done)
	}()
	copyDirection(stream.client, remote)
	<-done
}
