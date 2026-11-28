package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSSHBitwardenTicketBindingAndExpiry(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(),
		RequestID: uuid.NewString(), Protocol: "ssh", Host: "fixture", Port: 22, Epoch: 5}
	p := ConnectionBitwardenTicketPayload{
		ItemID: uuid.NewString(), Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		SavedSession: []byte("fixture-session"), TargetPublicKey: target.PublicKey().Bytes(), ExpiresAt: now.Add(time.Minute).UnixMilli(),
	}
	ticket, err := SealConnectionBitwardenTicket(key.PublicKey().Bytes(), b, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenConnectionBitwardenTicket(key.Bytes(), ticket, now); err != nil || !bytes.Equal(got.SavedSession, p.SavedSession) {
		t.Fatal("ticket changed", err)
	}
	if _, err := OpenBundle(key.Bytes(), b, ticket.Ticket); err == nil {
		t.Fatal("resolver ticket opened as a regular bundle")
	}
	if _, err := OpenConnectionBitwardenTicket(target.Bytes(), ticket, now); err == nil {
		t.Fatal("target opened the CLI session")
	}
	if _, err := OpenConnectionBitwardenTicket(key.Bytes(), ticket, now.Add(time.Minute)); err == nil {
		t.Fatal("expired ticket opened")
	}
	changed := ticket
	changed.Binding.Host = "redirected"
	if _, err := OpenConnectionBitwardenTicket(key.Bytes(), changed, now); err == nil {
		t.Fatal("ticket opened against a changed target")
	}
	for _, modify := range []func(*BundleBinding, *ConnectionBitwardenTicketPayload){
		func(b *BundleBinding, _ *ConnectionBitwardenTicketPayload) { b.RequestID = "invalid" },
		func(b *BundleBinding, _ *ConnectionBitwardenTicketPayload) { b.Protocol = "rdp" },
		func(b *BundleBinding, _ *ConnectionBitwardenTicketPayload) { b.Epoch = 0 },
		func(b *BundleBinding, _ *ConnectionBitwardenTicketPayload) { b.TunnelConfigID = uuid.NewString() },
		func(_ *BundleBinding, p *ConnectionBitwardenTicketPayload) { p.ItemID = "--help" },
		func(_ *BundleBinding, p *ConnectionBitwardenTicketPayload) {
			p.TargetPublicKey = key.PublicKey().Bytes()
		},
		func(_ *BundleBinding, p *ConnectionBitwardenTicketPayload) { p.Endpoint = "127.0.0.1:3000" },
		func(_ *BundleBinding, p *ConnectionBitwardenTicketPayload) { p.SFTPOnly, p.AutoSudo = true, true },
		func(_ *BundleBinding, p *ConnectionBitwardenTicketPayload) { p.Route = &TunnelBundleBinding{} },
	} {
		badBinding, badPayload := b, p
		modify(&badBinding, &badPayload)
		if _, err := SealConnectionBitwardenTicket(key.PublicKey().Bytes(), badBinding, badPayload, now); err == nil {
			t.Fatal("invalid binding or ticket payload was sealed")
		}
	}
}

func TestVNCBitwardenTicketProtocolIsolation(t *testing.T) {
	worker, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(),
		RequestID: uuid.NewString(), Protocol: "vnc", Host: "vnc.example", Port: 5900, Epoch: 1}
	p := ConnectionBitwardenTicketPayload{
		TargetPublicKey: target.PublicKey().Bytes(), ItemID: uuid.NewString(),
		SavedSession: []byte("fixture"), ExpiresAt: now.Add(time.Minute).UnixMilli(),
	}
	ticket, err := SealConnectionBitwardenTicket(worker.PublicKey().Bytes(), b, p, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := OpenConnectionBitwardenTicket(worker.Bytes(), ticket, now)
	if err != nil || parsed.ItemID != p.ItemID {
		t.Fatal("VNC ticket unavailable", err)
	}
	ticket.Binding.Protocol = "ssh"
	if _, err := OpenConnectionBitwardenTicket(worker.Bytes(), ticket, now); err == nil {
		t.Fatal("VNC ciphertext opened in the SSH domain")
	}
	for _, mutate := range []func(*ConnectionBitwardenTicketPayload){
		func(p *ConnectionBitwardenTicketPayload) { p.Username = "ssh" },
		func(p *ConnectionBitwardenTicketPayload) { p.Fingerprint = "SHA256:unexpected" },
		func(p *ConnectionBitwardenTicketPayload) { p.AutoSudo = true },
		func(p *ConnectionBitwardenTicketPayload) { p.SFTPOnly = true },
	} {
		malformed := p
		mutate(&malformed)
		if _, err := SealConnectionBitwardenTicket(worker.PublicKey().Bytes(), b, malformed, now); err == nil {
			t.Fatal("VNC ticket accepted SSH coordinates")
		}
	}
}
