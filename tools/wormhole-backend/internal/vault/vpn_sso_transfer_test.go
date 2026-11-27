package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func vpnTransferFixture(t *testing.T) (VPNSSOTransferContext, []byte, []byte) {
	t.Helper()
	capture, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, source := sha256.Sum256([]byte("native binding")), sha256.Sum256([]byte("source checkpoint"))
	return VPNSSOTransferContext{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), ProfileID: uuid.NewString(), RequestID: uuid.NewString(), TransferID: uuid.NewString(), SessionID: uuid.NewString(), ChallengeID: uuid.NewString(), Epoch: 3, PolicySequence: "9007199254740993", SourceRevision: "9007199254740993", BindingDigest: binding[:], SourceDigest: source[:], CapturePublicKey: capture.PublicKey().Bytes(), RestorePublicKey: restore.PublicKey().Bytes()}, capture.Bytes(), restore.Bytes()
}

func TestVPNSSOTransferOpaqueArchiveRoundtripAndBounds(t *testing.T) {
	c, capture, restore := vpnTransferFixture(t)
	defer Wipe(capture)
	defer Wipe(restore)
	for _, direction := range []string{"capture", "restore"} {
		private := capture
		if direction == "restore" {
			private = restore
		}
		for _, raw := range [][]byte{[]byte{0, 255, 1}, bytes.Repeat([]byte{0xa3}, MaxSecretBytes+19)} {
			m, bundles, err := SealVPNSSOTransferArchive(c, direction, raw)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := OpenVPNSSOTransferArchive(private, c, direction, m, bundles)
			if err != nil || !bytes.Equal(actual, raw) {
				t.Fatal("archive changed", err)
			}
			Wipe(actual)
			for i, bundle := range bundles {
				if err := ValidateVPNSSOTransferPacket(VPNSSOTransferPacket{c, direction, m, i, bundle}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenVPNSSOTransferArchive(private, c, direction, m, append(bundles, bundles[0])); err != ErrFormat {
				t.Fatal("extra chunk accepted", err)
			}
		}
	}
	m := VPNSSOTransferManifest{Bytes: MaxVPNSSOArchiveBytes, Digest: bytes.Repeat([]byte{1}, 32)}
	count, err := VPNSSOTransferChunkCount(c, "capture", m)
	if err != nil || count != 16 {
		t.Fatal(count, err)
	}
	if size, err := VPNSSOTransferChunkSize(c, "capture", m, 15); err != nil || size != MaxSecretBytes-48 {
		t.Fatal(size, err)
	}
	for _, index := range []int{-1, 16, math.MaxInt} {
		if _, err := VPNSSOTransferChunkSize(c, "capture", m, index); err != ErrFormat {
			t.Fatal(err)
		}
	}
	for _, size := range []int{-1, 0, MaxVPNSSOArchiveBytes + 1} {
		m.Bytes = size
		if _, err := VPNSSOTransferChunkCount(c, "capture", m); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, _, err := SealVPNSSOTransferArchive(c, "capture", make([]byte, MaxVPNSSOArchiveBytes+1)); err != ErrFormat {
		t.Fatal(err)
	}
}

func TestVPNSSOTransferContextAndDirectionCannotBeSubstituted(t *testing.T) {
	c, capture, restore := vpnTransferFixture(t)
	defer Wipe(capture)
	defer Wipe(restore)
	raw := []byte("opaque provider state")
	m, bundles, err := SealVPNSSOTransferArchive(c, "capture", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*VPNSSOTransferContext){
		func(c *VPNSSOTransferContext) { c.WorkspaceID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.FileID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.ProfileID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.RequestID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.TransferID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.SessionID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.ChallengeID = uuid.NewString() },
		func(c *VPNSSOTransferContext) { c.Epoch++ },
		func(c *VPNSSOTransferContext) { c.PolicySequence = "4" },
		func(c *VPNSSOTransferContext) { c.SourceRevision = "4" },
		func(c *VPNSSOTransferContext) { c.SourceDeleted = true },
		func(c *VPNSSOTransferContext) { c.SourceDigest = bytes.Repeat([]byte{2}, 32) },
		func(c *VPNSSOTransferContext) { c.BindingDigest = bytes.Repeat([]byte{2}, 32) },
		func(c *VPNSSOTransferContext) { c.CapturePublicKey = restorePublic(restore) },
		func(c *VPNSSOTransferContext) { c.RestorePublicKey = bytes.Repeat([]byte{2}, 32) },
	} {
		other := c
		change(&other)
		if other.Validate() != nil {
			t.Fatal("test changed to invalid shape")
		}
		if actual, err := OpenVPNSSOTransferArchive(capture, other, "capture", m, bundles); err == nil || actual != nil {
			t.Fatal("changed context opened")
		}
	}
	if _, err := OpenVPNSSOTransferArchive(restore, c, "restore", m, bundles); err == nil {
		t.Fatal("direction changed")
	}
	if _, err := OpenVPNSSOTransferArchive(nil, c, "capture", m, bundles); err != ErrAuthentication {
		t.Fatal("bad key accepted", err)
	}
	if _, err := OpenVPNSSOTransferArchive(restore, c, "capture", m, bundles); err != ErrAuthentication {
		t.Fatal("foreign key accepted", err)
	}
	if _, err := OpenVPNSSOTransferChunk(nil, c, "capture", m, 0, bundles[0]); err != ErrAuthentication {
		t.Fatal(err)
	}
	if _, err := SealVPNSSOTransferChunk(c, "capture", m, 0, []byte("short")); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := SealVPNSSOTransferChunk(c, "capture", m, 1, raw); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := OpenVPNSSOTransferChunk(capture, c, "capture", m, -1, bundles[0]); err != ErrFormat {
		t.Fatal(err)
	}
	wrongManifest := m
	wrongManifest.Digest = bytes.Repeat([]byte{3}, 32)
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", wrongManifest, bundles); err == nil {
		t.Fatal("manifest substituted")
	}
	// A sender can seal data under an incorrect full digest. Chunk authentication
	// succeeds, but archive assembly must still reject it.
	bad, err := SealVPNSSOTransferChunk(c, "capture", wrongManifest, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", wrongManifest, []SealedBundle{bad}); err != ErrAuthentication {
		t.Fatal("full digest not verified", err)
	}
	bad = bundles[0]
	bad.Ciphertext = bytes.Clone(bad.Ciphertext)
	bad.Ciphertext[0] ^= 1
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", m, []SealedBundle{bad}); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	bad.Ciphertext = bad.Ciphertext[:len(bad.Ciphertext)-1]
	if err := ValidateVPNSSOTransferPacket(VPNSSOTransferPacket{c, "capture", m, 0, bad}); err != ErrFormat {
		t.Fatal(err)
	}
}

func restorePublic(private []byte) []byte {
	key, _ := ecdh.X25519().NewPrivateKey(private)
	return key.PublicKey().Bytes()
}

func TestVPNSSOTransferEmptyRestoreAndValidation(t *testing.T) {
	c, capture, restore := vpnTransferFixture(t)
	defer Wipe(capture)
	defer Wipe(restore)
	for _, deleted := range []bool{false, true} {
		c.SourceDeleted = deleted
		if !deleted {
			c.SourceRevision, c.SourceDigest = "0", make([]byte, 32)
		} else {
			c.SourceRevision, c.SourceDigest = "2", bytes.Repeat([]byte{1}, 32)
		}
		m, chunks, err := SealVPNSSOTransferArchive(c, "restore", nil)
		if err != nil || len(chunks) != 0 {
			t.Fatal(err)
		}
		actual, err := OpenVPNSSOTransferArchive(restore, c, "restore", m, chunks)
		if err != nil || len(actual) != 0 {
			t.Fatal(err)
		}
		if _, err := OpenVPNSSOTransferArchive(capture, c, "restore", m, chunks); err != ErrAuthentication {
			t.Fatal("empty restore ignored recipient", err)
		}
		if _, _, err := SealVPNSSOTransferArchive(c, "restore", []byte("unexpected")); err != ErrFormat {
			t.Fatal(err)
		}
		m.Digest = bytes.Repeat([]byte{1}, 32)
		if _, err := VPNSSOTransferChunkCount(c, "restore", m); err != ErrFormat {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*VPNSSOTransferContext){
		func(c *VPNSSOTransferContext) { c.ChallengeID = uuid.Nil.String() },
		func(c *VPNSSOTransferContext) { c.SessionID = "bad" },
		func(c *VPNSSOTransferContext) { c.Epoch = 0 },
		func(c *VPNSSOTransferContext) { c.Epoch = 9007199254740992 },
		func(c *VPNSSOTransferContext) { c.CapturePublicKey = nil },
		func(c *VPNSSOTransferContext) { c.RestorePublicKey = nil },
		func(c *VPNSSOTransferContext) { c.BindingDigest = make([]byte, 32) },
		func(c *VPNSSOTransferContext) { c.SourceDigest = nil },
		func(c *VPNSSOTransferContext) { c.SourceDigest = make([]byte, 32) },
		func(c *VPNSSOTransferContext) { c.PolicySequence = "01" },
		func(c *VPNSSOTransferContext) { c.SourceRevision = strings.Repeat("1", 20) },
	} {
		other := c
		change(&other)
		if other.Validate() != ErrFormat {
			t.Fatal("invalid context accepted")
		}
		if _, _, err := SealVPNSSOTransferArchive(other, "capture", []byte{1}); err != ErrFormat {
			t.Fatal(err)
		}
	}
	c.SourceRevision = "0"
	if c.Validate() != ErrFormat {
		t.Fatal("zero revision with tombstone/digest accepted")
	}
	c, _, _ = vpnTransferFixture(t)
	if _, _, err := SealVPNSSOTransferArchive(c, "unknown", []byte{1}); err != ErrFormat {
		t.Fatal(err)
	}
	c.CapturePublicKey = make([]byte, 32)
	if _, _, err := SealVPNSSOTransferArchive(c, "capture", []byte{1}); err == nil {
		t.Fatal("low order recipient accepted")
	}
}

func TestVPNSSOTransferRejectsBitwardenPurposeAndReorderedChunks(t *testing.T) {
	c, capture, _ := vpnTransferFixture(t)
	defer Wipe(capture)
	raw := bytes.Repeat([]byte{4}, MaxSecretBytes+1)
	m, chunks, err := SealVPNSSOTransferArchive(c, "capture", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", m, []SealedBundle{chunks[1], chunks[0]}); err == nil {
		t.Fatal("reordered chunks accepted")
	}
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", m, []SealedBundle{chunks[0], chunks[0]}); err == nil {
		t.Fatal("duplicated chunk accepted")
	}
	raw = []byte("different authenticated purpose")
	digest := sha256.Sum256(raw)
	m = VPNSSOTransferManifest{len(raw), digest[:]}
	bw := BrowserTransferContext{WorkspaceID: c.WorkspaceID, FileID: c.FileID, ProfileID: c.ProfileID, RequestID: c.RequestID, TransferID: c.TransferID, Epoch: c.Epoch, PolicySequence: c.PolicySequence, Action: "capture", SourceRevision: c.SourceRevision, CapturePublicKey: c.CapturePublicKey, RestorePublicKey: c.RestorePublicKey}
	bundle, err := SealBrowserTransferChunk(bw, "capture", BrowserTransferManifest{Bytes: len(raw), Revision: c.SourceRevision}, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVPNSSOTransferArchive(capture, c, "capture", m, []SealedBundle{bundle}); err == nil {
		t.Fatal("Bitwarden ciphertext crossed purpose boundary")
	}
}
