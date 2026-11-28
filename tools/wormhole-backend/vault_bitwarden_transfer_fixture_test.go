package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Synthetic stdio fixture. Plaintext never leaves this process; only public
// context, recipient-sealed packets and a fixed acknowledgement reach stdout.
func TestVaultBitwardenTransferInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_BITWARDEN_TRANSFER")
	if mode == "" {
		t.Skip("native browser transfer fixture")
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 8*1024*1024)
	next := func() []byte {
		if !scan.Scan() {
			t.Fatal("missing fixture message")
		}
		return scan.Bytes()
	}
	var returnKey string
	var prepared vault.BrowserTransferContext
	var restore []byte
	var err error
	if mode == "browser" {
		if json.Unmarshal(next(), &prepared) != nil {
			t.Fatal("bad prepared context")
		}
		restore = prepared.RestorePublicKey
	} else {
		if json.Unmarshal(next(), &returnKey) != nil {
			t.Fatal("bad public key")
		}
		restore, err = base64.StdEncoding.Strict().DecodeString(returnKey)
	}
	if err != nil || len(restore) != 32 {
		t.Fatal("bad public key")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := key.Bytes()
	defer vault.Wipe(private)
	c := vault.BrowserTransferContext{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), ProfileID: uuid.NewString(), RequestID: uuid.NewString(), TransferID: uuid.NewString(), Epoch: 2, PolicySequence: "9223372036854775807", Action: "hydrate", SourceRevision: "9223372036854775805", CapturePublicKey: key.PublicKey().Bytes(), RestorePublicKey: restore}
	if mode == "browser" {
		c.WorkspaceID, c.ProfileID, c.RequestID = prepared.WorkspaceID, prepared.ProfileID, prepared.RequestID
		c.Epoch, c.Action, c.SourceRevision = prepared.Epoch, prepared.Action, prepared.SourceRevision
		if c.Validate() != nil {
			t.Fatal("invalid prepared browser context")
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	if encoder.Encode(c) != nil {
		t.Fatal("public context write")
	}
	local, session := []byte(`{"capture":"synthetic-🔑","n":9007199254740993}`), []byte(`{"session":"temporary"}`)
	if mode == "browser" {
		local = []byte(`{"capture":"synthetic-🔑","n":"9007199254740993"}`)
	}
	if mode == "large" {
		local = []byte(`{"v":"` + strings.Repeat("x", vault.MaxBrowserTransferArea-8) + `"}`)
		session = bytes.Clone(local)
	}
	expected, err := vault.EncodeBrowserTransferFrame(local, session)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(expected)
	var assembled []byte
	defer func() { vault.Wipe(assembled) }()
	count, _ := vault.BrowserTransferChunkCount(vault.BrowserTransferManifest{Bytes: len(expected)})
	for i := 0; i < count; i++ {
		var packet vault.BrowserTransferPacket
		if json.Unmarshal(next(), &packet) != nil || packet.Index != i || packet.Direction != "capture" {
			t.Fatal("bad capture packet")
		}
		if packet.Manifest.Bytes != len(expected) || packet.Manifest.Revision != c.SourceRevision || packet.Manifest.Restore {
			t.Fatal("bad capture manifest")
		}
		opened, err := vault.OpenBrowserTransferChunk(private, c, "capture", packet.Manifest, i, packet.Bundle)
		if err != nil {
			t.Fatal("capture authentication failed")
		}
		assembled = append(assembled, opened...)
		vault.Wipe(opened)
	}
	if !bytes.Equal(assembled, expected) {
		t.Fatal("capture frame mismatch")
	}
	local, session = []byte(`{"restore":"synthetic-saved"}`), []byte(`{"session":"ready"}`)
	if mode == "large" {
		local = []byte(`{"v":"` + strings.Repeat("y", vault.MaxBrowserTransferArea-8) + `"}`)
		session = bytes.Clone(local)
	}
	outgoing, err := vault.EncodeBrowserTransferFrame(local, session)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(outgoing)
	manifest := vault.BrowserTransferManifest{Bytes: len(outgoing), Revision: "9223372036854775806", Restore: true}
	if mode == "browser" {
		manifest.Revision = "1"
	}
	count, _ = vault.BrowserTransferChunkCount(manifest)
	for i := 0; i < count; i++ {
		size, _ := vault.BrowserTransferChunkSize(manifest, i)
		start := i * vault.MaxSecretBytes
		sealed, err := vault.SealBrowserTransferChunk(c, "restore", manifest, i, outgoing[start:start+size])
		if err != nil {
			t.Fatal("restore sealing failed")
		}
		if err := encoder.Encode(vault.BrowserTransferPacket{Context: c, Direction: "restore", Manifest: manifest, Index: i, Bundle: sealed}); err != nil {
			t.Fatal("restore write")
		}
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(next(), &ack) != nil || !ack.OK {
		t.Fatal("missing restore acknowledgement")
	}
}

// Runs the production CLI/stdio server against a synthetic encrypted SQLite file.
func TestVaultBitwardenTransferServiceFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_BITWARDEN_SERVICE")
	if path == "" {
		t.Skip("native Bitwarden service fixture")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		doc, key := localSlotFixture(t)
		doc.Initializing = true
		owner, err := initializeVaultFiles(context.Background(), path, doc, key)
		vault.Wipe(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = owner.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	os.Exit(runBackendCLI([]string{"--operation", "vault", "--database", path}, os.Stdin, os.Stdout, os.Stderr))
}
