package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type vncPixelFormatWriter struct {
	net.Conn
	data []byte
	n    int
	err  error
}

func (w *vncPixelFormatWriter) Write(data []byte) (int, error) {
	w.data = append([]byte(nil), data...)
	return w.n, w.err
}

func TestVncPixelFormatConnWritesNetworkOrderWithoutMutatingInput(t *testing.T) {
	for _, endian := range []byte{0, 1} {
		// Unequal maxima ensure each field is corrected independently.
		input := []byte{0, 0, 0, 0, 16, 16, endian, 1, 31, 0, 63, 0, 31, 0, 11, 5, 0, 0, 0, 0}
		original := bytes.Clone(input)
		want := []byte{0, 0, 0, 0, 16, 16, endian, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0}
		for _, result := range []struct {
			name string
			n    int
			err  error
		}{
			{"success", len(input), nil},
			{"closed", 0, net.ErrClosed},
			{"partial write", 9, io.ErrShortWrite},
		} {
			t.Run(result.name, func(t *testing.T) {
				writer := &vncPixelFormatWriter{n: result.n, err: result.err}
				connection := &vncPixelFormatConn{Conn: writer}
				n, err := connection.Write(input)
				if n != result.n || !errors.Is(err, result.err) {
					t.Fatalf("write result = (%d, %v), want (%d, %v)", n, err, result.n, result.err)
				}
				if !bytes.Equal(writer.data, want) {
					t.Fatalf("wire bytes = %x, want %x", writer.data, want)
				}
				if !bytes.Equal(input, original) {
					t.Fatal("caller-owned pixel format was modified")
				}
			})
		}
	}
}

func TestVncPixelFormatConnPreservesOtherWrites(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		[]byte("RFB 003.008\n"),
		{1},              // Security selection and ClientInit.
		make([]byte, 16), // VNC authentication response.
		make([]byte, 19),
		make([]byte, 21),
		append([]byte{2}, make([]byte, 19)...), // SetEncodings with four encodings.
		{3, 0, 0, 0, 0, 0, 0, 1, 0, 1},         // FramebufferUpdateRequest.
		{4, 1, 0, 0, 0, 0, 0xff, 0x0d},         // KeyEvent.
		{5, 1, 0, 0, 0, 0},                     // PointerEvent.
	} {
		writer := &vncPixelFormatWriter{n: len(input)}
		connection := &vncPixelFormatConn{Conn: writer}
		n, err := connection.Write(input)
		if n != len(input) || err != nil || !bytes.Equal(writer.data, input) {
			t.Fatalf("write changed: input=%x output=%x n=%d err=%v", input, writer.data, n, err)
		}
	}
}
