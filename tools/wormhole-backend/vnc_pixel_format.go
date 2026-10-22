package main

import "net"

// vncPixelFormatConn corrects SetPixelFormat messages from the pinned go-vnc
// version (83d72ad87d5f). Its wire encoder writes the three channel maxima in
// little-endian order, but RFB requires network byte order regardless of the
// pixel endianness flag (RFC 6143, section 7.4).
//
// go-vnc sends each complete client message in one Write. SetPixelFormat is the
// only 20-byte message starting with type 0 in our None/VNC-auth session flow.
// Wrap the socket before Connect because it also sends this message internally.
// Remove this adapter when upgrading to an encoder that uses network byte order;
// the handshake regression tests check the actual bytes of both format messages.
type vncPixelFormatConn struct {
	net.Conn
}

func (c *vncPixelFormatConn) Write(data []byte) (int, error) {
	if len(data) != 20 || data[0] != 0 {
		return c.Conn.Write(data)
	}
	var message [20]byte
	copy(message[:], data)
	for offset := 8; offset < 14; offset += 2 {
		message[offset], message[offset+1] = message[offset+1], message[offset]
	}
	return c.Conn.Write(message[:])
}
