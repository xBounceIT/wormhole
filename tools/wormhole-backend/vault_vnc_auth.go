package main

import (
	"crypto/des"
	"errors"
	"io"
	"math/bits"
	"sync"

	vnc "github.com/kward/go-vnc"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var errSealedVNCAuth = errors.New("VNC authentication failed")
var errSealedVNCPasswordRequired = errors.New("VNC password is required")

// Authentication reads the same socket later owned by the framebuffer parser;
// no second connection or immutable password string is involved. The adapter
// also implements ClientAuth for tests against the pinned library's wire flow.
// The caller owns the decrypted frame and closes the connection on cancellation.
type sealedVNCAuth struct {
	mu       sync.Mutex
	stream   io.ReadWriter
	password []byte
	provided bool
	used     bool
}

func (*sealedVNCAuth) SecurityType() uint8 { return 2 }

// dispose invalidates future use and clears borrowed password bytes. Connection
// cancellation remains the session owner's responsibility, independently of auth.
func (a *sealedVNCAuth) dispose() {
	a.mu.Lock()
	defer a.mu.Unlock()
	vault.Wipe(a.password)
	a.password = nil
	a.used = true
}

func (a *sealedVNCAuth) takeKey(key *[8]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used {
		return errSealedVNCAuth
	}
	a.used = true
	defer func() { vault.Wipe(a.password); a.password = nil }()
	if len(a.password) > vault.MaxVNCPasswordBytes || (!a.provided && len(a.password) != 0) {
		return errSealedVNCAuth
	}
	if !a.provided {
		return errSealedVNCPasswordRequired
	}
	for i := 0; i < len(key) && i < len(a.password); i++ {
		key[i] = bits.Reverse8(a.password[i])
	}
	return nil
}

func (a *sealedVNCAuth) Handshake(_ *vnc.ClientConn) error {
	var key [8]byte
	defer vault.Wipe(key[:])
	if err := a.takeKey(&key); err != nil {
		return err
	}
	if a.stream == nil {
		return errSealedVNCAuth
	}
	var challenge [16]byte
	defer vault.Wipe(challenge[:])
	if _, err := io.ReadFull(a.stream, challenge[:]); err != nil {
		return errSealedVNCAuth
	}
	cipher, err := des.NewCipher(key[:])
	if err != nil {
		return errSealedVNCAuth
	}
	// VNCAuth encrypts two DES blocks with the first eight password bytes, padded
	// with zeroes and with the bits in each key byte reversed (RFB interoperability).
	for offset := 0; offset < len(challenge); offset += cipher.BlockSize() {
		cipher.Encrypt(challenge[offset:offset+cipher.BlockSize()], challenge[offset:offset+cipher.BlockSize()])
	}
	return writeSealedVNCBytes(a.stream, challenge[:])
}
