package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"

	vnc "github.com/kward/go-vnc"
)

// authenticateSealedVNC performs the real, bounded RFB authentication before
// letting the pinned parser consume ServerInit. In RFB 3.3 that parser ignores
// ClientConfig.Auth; in 3.8 it omits SecurityResult for None. Never pass a secret
// through its immutable ClientConfig.Password or pretend a network auth succeeded.
func authenticateSealedVNC(ctx context.Context, connection net.Conn, auth *sealedVNCAuth) (net.Conn, error) {
	defer auth.dispose()
	var version [12]byte
	if _, err := io.ReadFull(connection, version[:]); err != nil {
		return nil, errSealedVNCAuth
	}
	if !bytes.Equal(version[:8], []byte("RFB 003.")) || version[11] != '\n' {
		return nil, errSealedVNCAuth
	}
	minor := 0
	for _, digit := range version[8:11] {
		if digit < '0' || digit > '9' {
			return nil, errSealedVNCAuth
		}
		minor = minor*10 + int(digit-'0')
	}
	if minor < 3 {
		return nil, errSealedVNCAuth
	}
	modern := minor >= 8
	copy(version[:], "RFB 003.003\n")
	if modern {
		copy(version[:], "RFB 003.008\n")
	}
	if err := writeSealedVNCBytes(connection, version[:]); err != nil {
		return nil, err
	}
	var security byte
	if modern {
		var count [1]byte
		if _, err := io.ReadFull(connection, count[:]); err != nil || count[0] == 0 {
			return nil, errSealedVNCAuth
		}
		var types [255]byte
		if _, err := io.ReadFull(connection, types[:int(count[0])]); err != nil {
			return nil, errSealedVNCAuth
		}
		// Preserve the existing client's server preference order, supporting only
		// None and VNCAuth. Unsupported schemes never fall back to another transport.
		for _, candidate := range types[:int(count[0])] {
			if candidate == 1 || candidate == 2 {
				security = candidate
				break
			}
		}
		if security == 0 {
			return nil, errSealedVNCAuth
		}
		if err := writeSealedVNCBytes(connection, []byte{security}); err != nil {
			return nil, err
		}
	} else {
		var value [4]byte
		if _, err := io.ReadFull(connection, value[:]); err != nil {
			return nil, errSealedVNCAuth
		}
		code := binary.BigEndian.Uint32(value[:])
		if code != 1 && code != 2 {
			return nil, errSealedVNCAuth
		}
		security = byte(code)
	}
	if security == 2 {
		auth.stream = connection
		if err := auth.Handshake(nil); err != nil {
			return nil, err
		}
	} else {
		auth.dispose()
	}
	if modern || security == 2 {
		var result [4]byte
		if _, err := io.ReadFull(connection, result[:]); err != nil || binary.BigEndian.Uint32(result[:]) != 0 {
			return nil, errSealedVNCAuth
		}
		// Failure reasons are untrusted text and can advertise multi-gigabyte lengths.
		// Close on failure without reading, allocating or forwarding the reason.
	}
	if ctx.Err() != nil {
		return nil, errSealedVNCAuth
	}
	if err := writeSealedVNCBytes(connection, []byte{1}); err != nil {
		return nil, err
	}
	var init [24]byte
	if _, err := io.ReadFull(connection, init[:]); err != nil {
		return nil, errSealedVNCAuth
	}
	if validateVncDimensions(int(binary.BigEndian.Uint16(init[0:2])), int(binary.BigEndian.Uint16(init[2:4]))) != nil {
		return nil, errSealedVNCAuth
	}
	nameSize := binary.BigEndian.Uint32(init[20:24])
	if nameSize > 4096 {
		return nil, errSealedVNCAuth
	}
	// Replay only public protocol metadata to the parser. No replayed bytes are
	// sent to the remote endpoint: its version/auth/ClientInit are already complete.
	replay := make([]byte, 16+len(init)+int(nameSize))
	copy(replay, "RFB 003.003\n\x00\x00\x00\x01")
	copy(replay[16:], init[:])
	if _, err := io.ReadFull(connection, replay[16+len(init):]); err != nil {
		return nil, errSealedVNCAuth
	}
	if ctx.Err() != nil {
		return nil, errSealedVNCAuth
	}
	return &sealedVNCAuthenticatedConn{Conn: connection, replay: bytes.NewReader(replay)}, nil
}

func writeSealedVNCBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil || n <= 0 || n > len(value) {
			return errSealedVNCAuth
		}
		value = value[n:]
	}
	return nil
}

// The pinned client writes each version/ClientInit in one call. Reject drift
// rather than letting its synthetic prelude escape onto the authenticated socket.
type sealedVNCAuthenticatedConn struct {
	net.Conn
	replay *bytes.Reader
	writes int
}

func (c *sealedVNCAuthenticatedConn) Read(p []byte) (int, error) {
	if c.replay.Len() > 0 {
		return c.replay.Read(p)
	}
	return c.Conn.Read(p)
}
func (c *sealedVNCAuthenticatedConn) Write(p []byte) (int, error) {
	if c.writes < 2 {
		expected := []byte("RFB 003.003\n")
		if c.writes == 1 {
			expected = []byte{1}
		}
		if !bytes.Equal(p, expected) {
			return 0, errSealedVNCAuth
		}
		c.writes++
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// The configuration contains no plaintext even while native authentication runs.
func sealedVNCClientConfig() *vnc.ClientConfig {
	config := vnc.NewClientConfig("")
	config.Auth = []vnc.ClientAuth{&vnc.ClientAuthNone{}}
	return config
}
