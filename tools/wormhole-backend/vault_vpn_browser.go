package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This disposable native adapter is separate from vaultwire: only the owning
// Chromium controller may receive its transient browser bytes. It has no DB,
// network listener, renderer IPC, filesystem archive or secret command-line flag.
// Frames are u32 header length, exact JSON header, then its optional binary body.
// Binary bodies avoid base64/string copies of plaintext browser storage.
func readVPNBrowserHeader(input io.Reader) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(input, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > vaultwire.MaxFrameBytes {
		return nil, vaultwire.ErrProtocol
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(input, raw); err != nil {
		vault.Wipe(raw)
		return nil, err
	}
	return raw, nil
}

func writeVPNBrowserFrame(output io.Writer, header any, body []byte) error {
	if len(body) > vault.MaxSecretBytes {
		return vaultwire.ErrProtocol
	}
	raw, err := json.Marshal(header)
	if err != nil || len(raw) == 0 || len(raw) > vaultwire.MaxFrameBytes {
		return vaultwire.ErrProtocol
	}
	defer vault.Wipe(raw)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	for _, part := range [][]byte{size[:], raw, body} {
		if len(part) == 0 {
			continue
		}
		n, err := output.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func vpnBrowserCommand(raw []byte) string {
	var typeName string
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["type"], &typeName) != nil {
		return ""
	}
	return typeName
}

func serveVPNSSOBrowser(input io.ReadCloser, output io.Writer) (result error) {
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		_ = input.Close()
		if closer, ok := output.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer stop()
	key, err := securemem.New(32, false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, key.Close()) }()
	var public []byte
	err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err == nil {
			public = private.PublicKey().Bytes()
		}
		return err
	})
	if err != nil {
		return err
	}
	profile := uuid.NewString()
	if err := writeVPNBrowserFrame(output, map[string]any{"type": "recipient", "profileId": profile, "publicKey": public, "lockedMemory": key.Locked()}, nil); err != nil {
		return err
	}
	closeCommand := func(raw []byte) (bool, error) {
		if vpnBrowserCommand(raw) != "close" {
			return false, nil
		}
		var command string
		if decodeVaultObject(raw, map[string]any{"type": &command}, "type") != nil {
			return true, vaultwire.ErrProtocol
		}
		if err := key.Close(); err != nil {
			return true, err
		}
		return true, writeVPNBrowserFrame(output, map[string]string{"type": "closed"}, nil)
	}
	readCommand := func() ([]byte, bool, error) {
		raw, err := readVPNBrowserHeader(input)
		if err != nil {
			return nil, false, err
		}
		closed, err := closeCommand(raw)
		if closed {
			vault.Wipe(raw)
		}
		return raw, closed, err
	}
	raw, closed, err := readCommand()
	if err != nil || closed {
		return err
	}
	var command string
	var contextRaw, manifestRaw json.RawMessage
	err = decodeVaultObject(raw, map[string]any{"type": &command, "context": &contextRaw, "manifest": &manifestRaw}, "type", "context", "manifest")
	vault.Wipe(raw)
	if err != nil || command != "bind" {
		return vaultwire.ErrProtocol
	}
	c, err := decodeVPNSSOTransferContext(contextRaw)
	if err != nil || c.ProfileID != profile || !bytes.Equal(c.RestorePublicKey, public) {
		return vaultwire.ErrProtocol
	}
	m, err := decodeVPNSSOManifest(manifestRaw)
	count, countErr := vault.VPNSSOTransferChunkCount(c, "restore", m)
	if err != nil || countErr != nil {
		return vaultwire.ErrProtocol
	}
	var bundles []vault.SealedBundle
	defer func() {
		for _, b := range bundles {
			vault.Wipe(b.Ciphertext)
		}
	}()
	for index := 0; index < count; index++ {
		raw, closed, err := readCommand()
		if err != nil || closed {
			return err
		}
		var packetRaw json.RawMessage
		err = decodeVaultObject(raw, map[string]any{"type": &command, "packet": &packetRaw}, "type", "packet")
		vault.Wipe(raw)
		if err != nil || command != "restore" {
			return vaultwire.ErrProtocol
		}
		p, err := decodeVPNSSOPacket(packetRaw)
		if err != nil {
			return err
		}
		bundles = append(bundles, p.Bundle)
		if p.Direction != "restore" || p.Index != index || !reflect.DeepEqual(p.Context, c) || !reflect.DeepEqual(p.Manifest, m) {
			return vaultwire.ErrProtocol
		}
	}
	var archive []byte
	err = key.With(func(private []byte) error {
		var err error
		archive, err = vault.OpenVPNSSOTransferArchive(private, c, "restore", m, bundles)
		return err
	})
	defer vault.Wipe(archive)
	closeErr := key.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	for index := 0; index < count; index++ {
		start := index * vault.MaxSecretBytes
		chunk := archive[start:min(start+vault.MaxSecretBytes, len(archive))]
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeVPNBrowserFrame(output, map[string]any{"type": "archive", "index": index, "bytes": len(chunk)}, chunk); err != nil {
			return err
		}
		vault.Wipe(chunk)
	}
	archive = nil
	if err := writeVPNBrowserFrame(output, map[string]any{"type": "restored", "manifest": m}, nil); err != nil {
		return err
	}
	raw, closed, err = readCommand()
	if err != nil || closed {
		return err
	}
	var total int
	err = decodeVaultObject(raw, map[string]any{"type": &command, "bytes": &total}, "type", "bytes")
	vault.Wipe(raw)
	if err != nil || command != "capture" || total < 1 || total > vault.MaxVPNSSOArchiveBytes {
		return vaultwire.ErrProtocol
	}
	capture := make([]byte, total)
	defer vault.Wipe(capture)
	if err := writeVPNBrowserFrame(output, map[string]string{"type": "capturing"}, nil); err != nil {
		return err
	}
	for index, offset := 0, 0; offset < total; index++ {
		raw, closed, err := readCommand()
		if err != nil || closed {
			return err
		}
		var i, n int
		err = decodeVaultObject(raw, map[string]any{"type": &command, "index": &i, "bytes": &n}, "type", "index", "bytes")
		vault.Wipe(raw)
		if err != nil || command != "chunk" || i != index || n != min(vault.MaxSecretBytes, total-offset) {
			return vaultwire.ErrProtocol
		}
		if _, err := io.ReadFull(input, capture[offset:offset+n]); err != nil {
			return err
		}
		offset += n
	}
	manifest, sealed, err := vault.SealVPNSSOTransferArchive(c, "capture", capture)
	vault.Wipe(capture)
	if err != nil {
		return err
	}
	defer func() {
		for _, b := range sealed {
			vault.Wipe(b.Ciphertext)
		}
	}()
	for index, bundle := range sealed {
		packet := vault.VPNSSOTransferPacket{Context: c, Direction: "capture", Manifest: manifest, Index: index, Bundle: bundle}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeVPNBrowserFrame(output, map[string]any{"type": "packet", "packet": packet}, nil); err != nil {
			return err
		}
		vault.Wipe(bundle.Ciphertext)
	}
	if err := writeVPNBrowserFrame(output, map[string]any{"type": "captured", "manifest": manifest}, nil); err != nil {
		return err
	}
	raw, closed, err = readCommand()
	if err != nil || closed {
		return err
	}
	vault.Wipe(raw)
	return vaultwire.ErrProtocol
}

func runVPNSSOBrowserCLI(input io.Reader, output, errorOutput io.Writer) int {
	if securemem.DisableProcessDumps() != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	if serveVPNSSOBrowser(reader, output) != nil {
		writeErrorTo(errorOutput, "vpn_browser_stopped")
		return 1
	}
	return 0
}
