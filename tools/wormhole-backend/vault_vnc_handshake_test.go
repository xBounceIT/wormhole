package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	vnc "github.com/kward/go-vnc"
)

type sealedVNCFixtureConn struct {
	net.Conn
	input     *bytes.Reader
	output    bytes.Buffer
	failWrite bool
}

func (c *sealedVNCFixtureConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *sealedVNCFixtureConn) Write(p []byte) (int, error) {
	if c.failWrite {
		return 0, io.ErrClosedPipe
	}
	return c.output.Write(p)
}

func sealedVNCFixture(modern, password bool) []byte {
	var data bytes.Buffer
	if modern {
		data.WriteString("RFB 003.008\n")
		if password {
			data.Write([]byte{1, 2})
		} else {
			data.Write([]byte{1, 1})
		}
	} else {
		data.WriteString("RFB 003.003\n")
		if password {
			data.Write([]byte{0, 0, 0, 2})
		} else {
			data.Write([]byte{0, 0, 0, 1})
		}
	}
	if password {
		data.Write(make([]byte, 16))
	}
	if modern || password {
		data.Write(make([]byte, 4))
	}
	var init [24]byte
	binary.BigEndian.PutUint16(init[:2], 1)
	binary.BigEndian.PutUint16(init[2:4], 1)
	copy(init[4:20], []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0})
	data.Write(init[:])
	return data.Bytes()
}

func TestSealedVNCHandshakeVersionsAndRealParser(t *testing.T) {
	for _, version := range []string{"RFB 003.003\n", "RFB 003.005\n", "RFB 003.007\n", "RFB 003.008\n", "RFB 003.889\n"} {
		for _, password := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", version[:11], password), func(t *testing.T) {
				modern := version == "RFB 003.008\n" || version == "RFB 003.889\n"
				data := sealedVNCFixture(modern, password)
				copy(data, version)
				connection := &sealedVNCFixtureConn{input: bytes.NewReader(data)}
				raw := []byte("native-password")
				auth := &sealedVNCAuth{password: raw, provided: true}
				authenticated, err := authenticateSealedVNC(context.Background(), connection, auth)
				if err != nil {
					t.Fatal(err)
				}
				if auth.password != nil || !bytes.Equal(raw, make([]byte, len(raw))) {
					t.Fatal("secret retained")
				}
				sent := bytes.Clone(connection.output.Bytes())
				expectedVersion := "RFB 003.003\n"
				if modern {
					expectedVersion = "RFB 003.008\n"
				}
				if !bytes.HasPrefix(sent, []byte(expectedVersion)) || sent[len(sent)-1] != 1 {
					t.Fatal("incorrect real version or ClientInit")
				}
				config := sealedVNCClientConfig()
				if config.Password != "" || len(config.Auth) != 1 || config.Auth[0].SecurityType() != 1 {
					t.Fatal("secret-bearing configuration")
				}
				parsed, err := vnc.Connect(context.Background(), authenticated, config)
				if err != nil {
					t.Fatal(err)
				}
				if parsed.FramebufferWidth() != 1 || parsed.FramebufferHeight() != 1 {
					t.Fatal("real ServerInit lost")
				}
				// The only additional remote messages are SetEncodings and SetPixelFormat;
				// neither version nor ClientInit may be sent a second time.
				extra := connection.output.Bytes()[len(sent):]
				if bytes.Contains(extra, []byte("RFB")) || len(extra) != 28 {
					t.Fatalf("synthetic handshake escaped: %x", extra)
				}
			})
		}
	}
}

func TestSealedVNCHandshakeRejectsMalformedAndWipes(t *testing.T) {
	valid := sealedVNCFixture(true, true)
	for end := 0; end < len(valid); end++ {
		t.Run(fmt.Sprintf("truncated-%d", end), func(t *testing.T) {
			raw := []byte("secret")
			c := &sealedVNCFixtureConn{input: bytes.NewReader(valid[:end])}
			_, err := authenticateSealedVNC(context.Background(), c, &sealedVNCAuth{password: raw, provided: true})
			if err == nil || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("truncated handshake accepted or secret retained")
			}
		})
	}
	for _, mode := range []string{"version", "version-digit", "version-old", "no-security", "unsupported", "legacy-security", "failure", "width", "height", "name", "write", "absent", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			data := sealedVNCFixture(true, false)
			ctx := context.Background()
			raw := []byte("secret")
			provided := true
			switch mode {
			case "version":
				data[0] = 'X'
			case "version-digit":
				data[8] = 'X'
			case "version-old":
				copy(data, "RFB 003.002\n")
			case "no-security":
				data[12] = 0
			case "unsupported":
				data[13] = 19
			case "legacy-security":
				data = sealedVNCFixture(false, false)
				data[12] = 1 // reject uint32 truncation
			case "failure":
				data[17] = 1
			case "width":
				data[18], data[19] = 0, 0
			case "height":
				data[20], data[21] = 0, 0
			case "name":
				binary.BigEndian.PutUint32(data[38:42], 4097)
			case "absent":
				data = sealedVNCFixture(true, true)
				raw = nil
				provided = false
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			c := &sealedVNCFixtureConn{input: bytes.NewReader(data), failWrite: mode == "write"}
			_, err := authenticateSealedVNC(ctx, c, &sealedVNCAuth{password: raw, provided: provided})
			if err == nil || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("invalid handshake accepted or secret retained")
			}
		})
	}
}

func TestSealedVNCHandshakeReplayAndWrites(t *testing.T) {
	c := &sealedVNCFixtureConn{input: bytes.NewReader([]byte{9})}
	wrapped := &sealedVNCAuthenticatedConn{Conn: c, replay: bytes.NewReader([]byte{7})}
	if n, err := wrapped.Write([]byte("wrong")); n != 0 || !errors.Is(err, errSealedVNCAuth) {
		t.Fatal("accepted parser drift")
	}
	if _, err := wrapped.Write([]byte("RFB 003.003\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Write([]byte{0}); !errors.Is(err, errSealedVNCAuth) {
		t.Fatal("accepted exclusive ClientInit")
	}
	if _, err := wrapped.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Write([]byte{5}); err != nil || !bytes.Equal(c.output.Bytes(), []byte{5}) {
		t.Fatal("normal write not forwarded")
	}
	var p [1]byte
	if _, err := wrapped.Read(p[:]); err != nil || p[0] != 7 {
		t.Fatal("replay failed")
	}
	if _, err := wrapped.Read(p[:]); err != nil || p[0] != 9 {
		t.Fatal("normal read not forwarded")
	}
	for _, stream := range []*authTestStream{{count: 0}, {count: 1, fail: true}, {count: 1}} {
		err := writeSealedVNCBytes(stream, []byte{1, 2})
		if (err != nil) != (stream.fail || stream.count == 0) {
			t.Fatal("incorrect write result")
		}
	}
}

func TestSealedVNCHandshakeCancellationInterruptsSocket(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	raw := []byte("secret")
	done := make(chan error, 1)
	go func() {
		_, err := authenticateSealedVNC(ctx, client, &sealedVNCAuth{password: raw, provided: true})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil || !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("cancel failed")
		}
	case <-time.After(time.Second):
		t.Fatal("socket cancellation leaked")
	}
}
