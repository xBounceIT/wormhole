package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	vnc "github.com/kward/go-vnc"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type authTestStream struct {
	reader  io.Reader
	written bytes.Buffer
	fail    bool
	count   int
}

func (s *authTestStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *authTestStream) Write(p []byte) (int, error) {
	if s.fail {
		return 0, errors.New("private diagnostic")
	}
	if s.count == 0 {
		return 0, nil
	}
	if len(p) > s.count {
		p = p[:s.count]
	}
	return s.written.Write(p)
}

func TestSealedVNCAuthConsumesAndRejectsReuse(t *testing.T) {
	for _, password := range [][]byte{nil, []byte("native-password"), {0, 255, 0, 1, 2, 3, 4, 5, 6}, bytes.Repeat([]byte("x"), vault.MaxVNCPasswordBytes)} {
		stream := &authTestStream{reader: bytes.NewReader(make([]byte, 16)), count: 1}
		input := bytes.Clone(password)
		a := &sealedVNCAuth{stream: stream, password: input, provided: true}
		if a.SecurityType() != 2 {
			t.Fatal("wrong security type")
		}
		if err := a.Handshake(nil); err != nil {
			t.Fatal(err)
		}
		if len(stream.written.Bytes()) != 16 || a.password != nil || !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("auth retained plaintext or wrote an incomplete response")
		}
		if err := a.Handshake(nil); !errors.Is(err, errSealedVNCAuth) {
			t.Fatal("auth reused", err)
		}
		a.dispose()
		a.dispose()
	}
}

func TestSealedVNCAuthErrorsClearPassword(t *testing.T) {
	for _, mode := range []string{"absent", "inconsistent", "oversized", "no-stream", "read", "write", "short", "disposed"} {
		t.Run(mode, func(t *testing.T) {
			stream := &authTestStream{reader: bytes.NewReader(make([]byte, 16)), count: 16}
			input := []byte("password")
			provided := true
			switch mode {
			case "absent":
				input = nil
				provided = false
			case "inconsistent":
				provided = false
			case "oversized":
				input = make([]byte, vault.MaxVNCPasswordBytes+1)
			case "read":
				stream.reader = bytes.NewReader(nil)
			case "write":
				stream.fail = true
			case "short":
				stream.count = 0
			}
			a := &sealedVNCAuth{stream: stream, password: input, provided: provided}
			if mode == "no-stream" {
				a.stream = nil
			}
			if mode == "disposed" {
				a.dispose()
			}
			if err := a.Handshake(nil); err == nil {
				t.Fatal("invalid handshake succeeded")
			}
			if a.password != nil || !bytes.Equal(input, make([]byte, len(input))) {
				t.Fatal("failure retained borrowed password")
			}
		})
	}
}

func TestSealedVNCAuthOneConsumer(t *testing.T) {
	a := &sealedVNCAuth{stream: &authTestStream{reader: bytes.NewReader(make([]byte, 16)), count: 16}, password: []byte("secret"), provided: true}
	var work sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 8; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			if a.Handshake(nil) == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	work.Wait()
	if success != 1 {
		t.Fatal("more than one authentication consumed the secret")
	}
}

// Exercise the pinned client's real security negotiation over a private socket,
// including explicit empty VNCAuth, which its string-based adapter rejects.
func TestSealedVNCAuthRealRFBHandshake(t *testing.T) {
	for _, password := range []string{"", "native-password"} {
		t.Run(map[bool]string{true: "empty", false: "password"}[password == ""], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() {
				if _, err := io.WriteString(server, "RFB 003.008\n"); err != nil {
					done <- err
					return
				}
				var version [12]byte
				if _, err := io.ReadFull(server, version[:]); err != nil {
					done <- err
					return
				}
				if err := authenticateFakeVnc(server, password); err != nil {
					done <- err
					return
				}
				var init [1]byte
				if _, err := io.ReadFull(server, init[:]); err != nil {
					done <- err
					return
				}
				if err := writeFakeServerInit(server, [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}); err != nil {
					done <- err
					return
				}
				for i := 0; i < 2; i++ {
					if _, _, err := readFakeClientMessage(server); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			raw := []byte(password)
			a := &sealedVNCAuth{stream: client, password: raw, provided: true}
			config := vnc.NewClientConfig("")
			config.Auth = []vnc.ClientAuth{a}
			connection, err := vnc.Connect(context.Background(), client, config)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if connection.FramebufferWidth() != 1 || a.password != nil || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("RFB negotiation or wiping failed")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
