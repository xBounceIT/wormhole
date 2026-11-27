package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

var errRdpNativeReference = errors.New("native RDP control reference is invalid")

// Keep only local RPC bindings before COM unmarshaling. In particular, never
// activate a custom marshaler, handler or remote object from child stdout.
func localRdpDispatchReference(raw []byte) ([]byte, error) {
	if len(raw) < 68 || len(raw) > 32768 || binary.LittleEndian.Uint32(raw) != 0x574f454d || binary.LittleEndian.Uint32(raw[4:]) != 1 || !bytes.Equal(raw[8:24], []byte{0, 4, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}) {
		return nil, errRdpNativeReference
	}
	count := int(binary.LittleEndian.Uint16(raw[64:]))
	security := int(binary.LittleEndian.Uint16(raw[66:]))
	if binary.LittleEndian.Uint64(raw[32:]) == 0 || binary.LittleEndian.Uint64(raw[40:]) == 0 || bytes.Equal(raw[48:64], make([]byte, 16)) {
		return nil, errRdpNativeReference
	}
	// Windows uses an empty resolver binding array for a same-machine reference.
	// With no remote transport/address, COM resolves the OXID through local RPCSS.
	if count == 0 && security == 0 && len(raw) == 68 {
		return bytes.Clone(raw), nil
	}
	if count < 3 || 68+2*count != len(raw) || security < 2 || security >= count {
		return nil, errRdpNativeReference
	}
	entries := make([]uint16, count)
	for i := range entries {
		entries[i] = binary.LittleEndian.Uint16(raw[68+2*i:])
	}
	var local []uint16
	position := 0
	terminated := false
	for position < security {
		tower := entries[position]
		position++
		if tower == 0 {
			terminated = position == security
			break
		}
		start := position
		for position < security && entries[position] != 0 {
			position++
		}
		if position >= security || position-start > 1024 {
			return nil, errRdpNativeReference
		}
		position++
		if tower == 0x10 {
			local = append(local, tower)
			local = append(local, entries[start:position]...)
		}
	}
	if !terminated || len(local) == 0 || entries[len(entries)-1] != 0 {
		return nil, errRdpNativeReference
	}
	// Validate the security array as bounded terminated bindings, even though COM
	// will apply the caller's explicit local authentication blanket separately.
	position = security
	terminated = false
	for position < count {
		auth := entries[position]
		position++
		if auth == 0 {
			terminated = position == count
			break
		}
		if position >= count {
			return nil, errRdpNativeReference
		}
		position++ // authorization service
		start := position
		for position < count && entries[position] != 0 {
			position++
		}
		if position >= count || position-start > 1024 {
			return nil, errRdpNativeReference
		}
		position++
	}
	if !terminated {
		return nil, errRdpNativeReference
	}
	local = append(local, 0)
	offset := len(local)
	local = append(local, entries[security:]...)
	out := append([]byte{}, raw[:68]...)
	binary.LittleEndian.PutUint16(out[64:], uint16(len(local)))
	binary.LittleEndian.PutUint16(out[66:], uint16(offset))
	for _, entry := range local {
		out = binary.LittleEndian.AppendUint16(out, entry)
	}
	return out, nil
}

// Convert a borrowed credential without creating an immutable Go string. The
// caller owns and wipes this mutable UTF-16 buffer after the native setter.
func rdpCredentialUTF16(raw []byte) ([]uint16, error) {
	if len(raw) > 64*1024 || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, errRdpNativeReference
	}
	out := make([]uint16, 0, len(raw))
	for len(raw) > 0 {
		r, n := utf8.DecodeRune(raw)
		raw = raw[n:]
		if r <= 0xffff {
			out = append(out, uint16(r))
		} else {
			a, b := utf16.EncodeRune(r)
			out = append(out, uint16(a), uint16(b))
		}
	}
	return out, nil
}
