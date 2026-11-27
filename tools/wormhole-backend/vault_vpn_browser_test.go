package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vpnBrowserFixture struct {
	client  net.Conn
	done    chan error
	profile string
	public  []byte
}

func newVPNBrowserFixture(t *testing.T) *vpnBrowserFixture {
	t.Helper()
	server, client := net.Pipe()
	if err := client.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f := &vpnBrowserFixture{client: client, done: make(chan error, 1)}
	go func() { f.done <- serveVPNSSOBrowser(server, server) }()
	t.Cleanup(func() { client.Close(); server.Close() })
	var recipient struct {
		Type    string `json:"type"`
		Profile string `json:"profileId"`
		Public  []byte `json:"publicKey"`
		Locked  bool   `json:"lockedMemory"`
	}
	f.read(t, &recipient)
	id, parseErr := uuid.Parse(recipient.Profile)
	if recipient.Type != "recipient" || parseErr != nil || id == uuid.Nil || id.String() != recipient.Profile || len(recipient.Public) != 32 {
		t.Fatal("invalid native browser recipient")
	}
	f.profile, f.public = recipient.Profile, recipient.Public
	return f
}

func (f *vpnBrowserFixture) send(t *testing.T, header any, body []byte) {
	t.Helper()
	if err := writeVPNBrowserFrame(f.client, header, body); err != nil {
		t.Fatal(err)
	}
}

func (f *vpnBrowserFixture) read(t *testing.T, target any) {
	t.Helper()
	raw, err := readVPNBrowserHeader(f.client)
	defer vault.Wipe(raw)
	if err != nil || json.Unmarshal(raw, target) != nil {
		t.Fatal("native response", err)
	}
}

func (f *vpnBrowserFixture) finish(t *testing.T) {
	t.Helper()
	f.send(t, map[string]string{"type": "close"}, nil)
	var closed map[string]string
	f.read(t, &closed)
	if closed["type"] != "closed" || len(closed) != 1 {
		t.Fatal("missing native release confirmation")
	}
	if err := <-f.done; err != nil {
		t.Fatal("native release", err)
	}
}

func (f *vpnBrowserFixture) begin(t *testing.T, h *vaultFoundationHandler, request map[string]any, binding vault.TunnelBundleBinding) localvault.VPNSSOTransferOffer {
	t.Helper()
	raw, err := h.Handle(context.Background(), "vpn-sso-begin", vaultInput(t, map[string]any{"request": request, "binding": binding, "challengeId": uuid.NewString(), "profileId": f.profile, "startURL": "https://vpn.test:443/remote/saml/start?realm=staff", "ignoreCertificateErrors": false, "restorePublicKey": f.public}))
	if err != nil {
		t.Fatal(err)
	}
	var offer localvault.VPNSSOTransferOffer
	if json.Unmarshal(raw, &offer) != nil {
		t.Fatal("root offer")
	}
	return offer
}

func (f *vpnBrowserFixture) restore(t *testing.T, h *vaultFoundationHandler, offer localvault.VPNSSOTransferOffer) []byte {
	t.Helper()
	f.send(t, map[string]any{"type": "bind", "context": offer.Context, "manifest": offer.Manifest}, nil)
	count, err := vault.VPNSSOTransferChunkCount(offer.Context, "restore", offer.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		raw, err := h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": offer.Context, "index": i}))
		if err != nil {
			t.Fatal(err)
		}
		f.send(t, map[string]any{"type": "restore", "packet": json.RawMessage(raw)}, nil)
	}
	archive := make([]byte, 0, offer.Manifest.Bytes)
	for i := 0; i < count; i++ {
		var header struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Bytes int    `json:"bytes"`
		}
		f.read(t, &header)
		if header.Type != "archive" || header.Index != i || header.Bytes != min(vault.MaxSecretBytes, offer.Manifest.Bytes-i*vault.MaxSecretBytes) {
			t.Fatal("invalid binary chunk")
		}
		chunk := make([]byte, header.Bytes)
		if _, err := io.ReadFull(f.client, chunk); err != nil {
			t.Fatal(err)
		}
		archive = append(archive, chunk...)
		vault.Wipe(chunk)
	}
	var receipt struct {
		Type     string                       `json:"type"`
		Manifest vault.VPNSSOTransferManifest `json:"manifest"`
	}
	f.read(t, &receipt)
	if receipt.Type != "restored" || !bytes.Equal(receipt.Manifest.Digest, offer.Manifest.Digest) || receipt.Manifest.Bytes != len(archive) {
		t.Fatal("invalid restore completion")
	}
	if _, err := h.Handle(context.Background(), "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": offer.Context, "manifest": offer.Manifest})); err != nil {
		t.Fatal(err)
	}
	return archive
}

func TestVPNBrowserNativeRecipientCustodyRoundtrip(t *testing.T) {
	h, q, b := nativeSSOFixture(t)
	f := newVPNBrowserFixture(t)
	offer := f.begin(t, h, q, b)
	if restored := f.restore(t, h, offer); len(restored) != 0 {
		t.Fatal("fresh restore not empty")
	}
	archive := bytes.Repeat([]byte{0x93}, vault.MaxSecretBytes+31)
	defer vault.Wipe(archive)
	f.send(t, map[string]any{"type": "capture", "bytes": len(archive)}, nil)
	var ready map[string]string
	f.read(t, &ready)
	if ready["type"] != "capturing" {
		t.Fatal("capture not admitted")
	}
	count := (len(archive) + vault.MaxSecretBytes - 1) / vault.MaxSecretBytes
	for i := 0; i < count; i++ {
		chunk := archive[i*vault.MaxSecretBytes : min((i+1)*vault.MaxSecretBytes, len(archive))]
		f.send(t, map[string]any{"type": "chunk", "index": i, "bytes": len(chunk)}, chunk)
	}
	for i := 0; i < count; i++ {
		var frame struct {
			Type   string          `json:"type"`
			Packet json.RawMessage `json:"packet"`
		}
		f.read(t, &frame)
		if frame.Type != "packet" {
			t.Fatal("capture plaintext returned")
		}
		if _, err := h.Handle(context.Background(), "vpn-sso-push", frame.Packet); err != nil {
			t.Fatal(err)
		}
	}
	var captured struct {
		Type     string                       `json:"type"`
		Manifest vault.VPNSSOTransferManifest `json:"manifest"`
	}
	f.read(t, &captured)
	if captured.Type != "captured" || captured.Manifest.Bytes != len(archive) {
		t.Fatal("capture receipt")
	}
	if _, err := h.Handle(context.Background(), "vpn-sso-commit", vaultInput(t, map[string]any{"context": offer.Context})); err != nil {
		t.Fatal(err)
	}
	f.finish(t)
	second := newVPNBrowserFixture(t)
	newOffer := second.begin(t, h, q, b)
	restored := second.restore(t, h, newOffer)
	defer vault.Wipe(restored)
	if !bytes.Equal(restored, archive) || bytes.Equal(second.public, f.public) {
		t.Fatal("native restore")
	}
	second.finish(t)
}

func TestVPNBrowserNativeCloseAndInvalidMessages(t *testing.T) {
	newVPNBrowserFixture(t).finish(t)
	for _, invalid := range []any{
		map[string]any{"type": "close", "extra": true},
		map[string]any{"type": "bind", "context": nil, "manifest": nil},
		map[string]any{"type": "capture", "bytes": 1},
		map[string]any{"type": "bind", "context": map[string]any{}, "manifest": map[string]any{}},
		map[string]any{"type": "other"},
	} {
		f := newVPNBrowserFixture(t)
		f.send(t, invalid, nil)
		if err := <-f.done; err == nil {
			t.Fatal("invalid native command accepted")
		}
	}
	for _, n := range []uint32{0, vaultwire.MaxFrameBytes + 1} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], n)
		if _, err := readVPNBrowserHeader(bytes.NewReader(size[:])); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := readVPNBrowserHeader(bytes.NewReader([]byte{0})); err == nil {
		t.Fatal("truncated prefix")
	}
	if err := writeVPNBrowserFrame(io.Discard, map[string]string{"type": "chunk"}, make([]byte, vault.MaxSecretBytes+1)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if err := writeVPNBrowserFrame(io.Discard, make(chan int), nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if vpnBrowserCommand([]byte(`{"type":3}`)) != "" {
		t.Fatal("coerced type")
	}
}

func TestVPNBrowserRejectsRecipientAndCiphertextSubstitution(t *testing.T) {
	for _, mode := range []string{"profile", "recipient", "manifest", "context", "ciphertext", "order", "early-close"} {
		h, q, b := nativeSSOFixture(t)
		// Seed a real custody archive through its existing root transfer API.
		seed, seedPrivate := beginNativeSSO(t, h, q, b)
		defer vault.Wipe(seedPrivate)
		if _, err := h.Handle(context.Background(), "vpn-sso-restore-ack", vaultInput(t, map[string]any{"context": seed.Context, "manifest": seed.Manifest})); err != nil {
			t.Fatal(err)
		}
		m, chunks, err := vault.SealVPNSSOTransferArchive(seed.Context, "capture", []byte("actual encrypted state"))
		if err != nil {
			t.Fatal(err)
		}
		p := vault.VPNSSOTransferPacket{Context: seed.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]}
		raw, _ := json.Marshal(p)
		if _, err := h.Handle(context.Background(), "vpn-sso-push", raw); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(context.Background(), "vpn-sso-commit", vaultInput(t, map[string]any{"context": seed.Context})); err != nil {
			t.Fatal(err)
		}
		f := newVPNBrowserFixture(t)
		offer := f.begin(t, h, q, b)
		c := offer.Context
		manifest := offer.Manifest
		if mode == "profile" {
			c.ProfileID = uuid.NewString()
		}
		if mode == "recipient" {
			c.RestorePublicKey = bytes.Repeat([]byte{3}, 32)
		}
		if mode == "manifest" {
			manifest.Bytes = -1
		}
		f.send(t, map[string]any{"type": "bind", "context": c, "manifest": manifest}, nil)
		if mode == "profile" || mode == "recipient" || mode == "manifest" {
			if err := <-f.done; err == nil {
				t.Fatal(mode)
			}
			continue
		}
		if mode == "early-close" {
			f.finish(t)
			continue
		}
		raw, err = h.Handle(context.Background(), "vpn-sso-take", vaultInput(t, map[string]any{"context": offer.Context, "index": 0}))
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("packet")
		}
		if mode == "context" {
			p.Context.ChallengeID = uuid.NewString()
		}
		if mode == "ciphertext" {
			p.Bundle.Ciphertext[0] ^= 1
		}
		if mode == "order" {
			p.Index = 1
		}
		f.send(t, map[string]any{"type": "restore", "packet": p}, nil)
		if err := <-f.done; err == nil {
			t.Fatal("substitution accepted", mode)
		}
	}
}

type vpnBrowserShortWriter struct{}

func (vpnBrowserShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestVPNBrowserFramingFailures(t *testing.T) {
	if err := writeVPNBrowserFrame(vpnBrowserShortWriter{}, map[string]string{"type": "close"}, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], 2)
	if _, err := readVPNBrowserHeader(bytes.NewReader(append(size[:], '{'))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

func TestVPNBrowserNativeCaptureBoundsAndCancellation(t *testing.T) {
	for _, mode := range []string{"zero", "oversize", "coercion", "extra", "order", "length", "partial", "close"} {
		h, q, binding := nativeSSOFixture(t)
		f := newVPNBrowserFixture(t)
		offer := f.begin(t, h, q, binding)
		f.restore(t, h, offer)
		header := map[string]any{"type": "capture", "bytes": 2}
		switch mode {
		case "zero":
			header["bytes"] = 0
		case "oversize":
			header["bytes"] = vault.MaxVPNSSOArchiveBytes + 1
		case "coercion":
			header["bytes"] = "2"
		case "extra":
			header["extra"] = true
		}
		f.send(t, header, nil)
		if mode == "zero" || mode == "oversize" || mode == "coercion" || mode == "extra" {
			if err := <-f.done; err == nil {
				t.Fatal("invalid capture size admitted", mode)
			}
			continue
		}
		var ready map[string]string
		f.read(t, &ready)
		if mode == "close" {
			f.finish(t)
			continue
		}
		chunk := map[string]any{"type": "chunk", "index": 0, "bytes": 2}
		if mode == "order" {
			chunk["index"] = 1
		}
		if mode == "length" {
			chunk["bytes"] = 1
		}
		f.send(t, chunk, nil)
		if mode == "partial" {
			if _, err := f.client.Write([]byte{0x94}); err != nil {
				t.Fatal(err)
			}
			f.client.Close()
		}
		if err := <-f.done; err == nil {
			t.Fatal("malformed native capture accepted", mode)
		}
	}
}

func TestVPNBrowserCLIHasNoDatabaseDependencyAndRedactsErrors(t *testing.T) {
	var input, output, diagnostic bytes.Buffer
	if err := writeVPNBrowserFrame(&input, map[string]string{"type": "close"}, nil); err != nil {
		t.Fatal(err)
	}
	if code := runBackendCLI([]string{"--operation", "vault-vpn-browser"}, &input, &output, &diagnostic); code != 0 || diagnostic.Len() != 0 {
		t.Fatal("native CLI did not bypass legacy database startup", code)
	}
	for _, want := range []string{"recipient", "closed"} {
		raw, err := readVPNBrowserHeader(&output)
		if err != nil || vpnBrowserCommand(raw) != want {
			t.Fatal("CLI protocol output", err)
		}
	}
	output.Reset()
	diagnostic.Reset()
	if code := runBackendCLI([]string{"--operation", "vault-vpn-browser"}, bytes.NewReader(nil), &output, &diagnostic); code != 1 || diagnostic.String() != "vpn_browser_stopped\n" {
		t.Fatal("native CLI exposed a raw failure", code)
	}
}
