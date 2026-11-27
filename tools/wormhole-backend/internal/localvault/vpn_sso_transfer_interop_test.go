package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Synthetic native client over stdio exercises the production owner/codec and
// SQLite. This is deliberately not a production RPC or renderer registration.
func TestVPNSSOTransferInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_VPN_TRANSFER_INTEROP")
	if mode == "" {
		t.Skip("independent Node HPKE fixture")
	}
	ctx := context.Background()
	o, _, _, _ := owner(t)
	b := vpnSSOFixture()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	initial := bytes.Repeat([]byte{0x73}, vault.MaxSecretBytes+3)
	saveVPNSSO(t, o, b, id, initial)
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32*1024*1024))
	decoder.DisallowUnknownFields()
	encoder := json.NewEncoder(os.Stdout)
	var hello struct {
		PublicKey []byte `json:"publicKey"`
	}
	if decoder.Decode(&hello) != nil {
		t.Fatal("native hello")
	}
	q, unused := vpnTransferRequest(t)
	vault.Wipe(unused)
	q.RestorePublicKey = hello.PublicKey
	offer, err := o.BeginVPNSSOTransfer(ctx, b, q)
	if err != nil {
		t.Fatal(err)
	}
	if encoder.Encode(offer) != nil {
		t.Fatal("native offer")
	}
	count, err := vault.VPNSSOTransferChunkCount(offer.Context, "restore", offer.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		packet, err := o.TakeVPNSSOTransfer(ctx, offer.Context, i)
		if err != nil {
			t.Fatal(err)
		}
		if encoder.Encode(packet) != nil {
			t.Fatal("native restore")
		}
		wipeBrowserBundles([]vault.SealedBundle{packet.Bundle})
	}
	var ack struct {
		Manifest vault.VPNSSOTransferManifest `json:"manifest"`
		Chunks   int                          `json:"chunks"`
	}
	if decoder.Decode(&ack) != nil || ack.Chunks < 1 || ack.Chunks > 16 {
		t.Fatal("native receipt")
	}
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, ack.Manifest); err != nil {
		t.Fatal(err)
	}
	var pushError error
	for i := 0; i < ack.Chunks; i++ {
		var packet vault.VPNSSOTransferPacket
		if decoder.Decode(&packet) != nil {
			t.Fatal("native capture")
		}
		if pushError == nil {
			pushError = o.PushVPNSSOTransfer(ctx, packet)
		}
		wipeBrowserBundles([]vault.SealedBundle{packet.Bundle})
	}
	if mode == "foreign" {
		if pushError == nil || len(o.vpnSSOTransfers) != 1 {
			t.Fatal("foreign transfer changed original")
		}
		if err := o.CancelVPNSSOTransfer(offer.Context); err != nil {
			t.Fatal(err)
		}
		if encoder.Encode(map[string]bool{"rejected": true, "preserved": true}) != nil {
			t.Fatal("native refusal")
		}
		return
	}
	if pushError != nil {
		t.Fatal(pushError)
	}
	checkpoint, err := o.CommitVPNSSOTransfer(ctx, offer.Context)
	if mode != "ready" {
		if err == nil || len(o.vpnSSOTransfers) != 0 {
			t.Fatal("unproven capture committed")
		}
		if encoder.Encode(map[string]bool{"rejected": true, "preserved": false}) != nil {
			t.Fatal("native refusal")
		}
		return
	}
	if err != nil || checkpoint.Revision != 2 {
		t.Fatal("native commit", err)
	}
	if err := o.OpenVPNSSO(ctx, b, q.RequestID, checkpoint, func(snapshot VPNSSOSnapshot) error {
		if !bytes.Equal(snapshot.Archive, bytes.Repeat([]byte{0xa9}, vault.MaxSecretBytes+7)) {
			t.Fatal("independent native capture changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if encoder.Encode(struct {
		Checkpoint VPNSSOCheckpoint `json:"checkpoint"`
		Verified   bool             `json:"verified"`
	}{checkpoint, true}) != nil {
		t.Fatal("native commit receipt")
	}
}
