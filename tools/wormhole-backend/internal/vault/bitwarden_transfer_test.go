package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func browserTransferFixture(t *testing.T) (BrowserTransferContext, []byte, []byte) {
	t.Helper()
	capture, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := BrowserTransferContext{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), 2, "9223372036854775807", "hydrate", "9223372036854775805", capture.PublicKey().Bytes(), restore.PublicKey().Bytes()}
	return c, capture.Bytes(), restore.Bytes()
}
func TestBrowserTransferChunksRoundTripAndFraming(t *testing.T) {
	c, capture, restore := browserTransferFixture(t)
	defer Wipe(capture)
	defer Wipe(restore)
	for _, large := range []bool{false, true} {
		local, session := []byte(`{"account":"synthetic-🔑","n":9007199254740993}`), []byte(`{"key":"session-only"}`)
		if large {
			local = []byte(`{"v":"` + strings.Repeat("x", MaxBrowserTransferArea-8) + `"}`)
			session = bytes.Clone(local)
		}
		raw, err := EncodeBrowserTransferFrame(local, session)
		if err != nil {
			t.Fatal(err)
		}
		m := BrowserTransferManifest{len(raw), c.SourceRevision, false}
		count, err := BrowserTransferChunkCount(m)
		if err != nil || (large && count != 5) {
			t.Fatal(count, err)
		}
		for _, direction := range []string{"capture", "restore"} {
			private := capture
			if direction == "restore" {
				private = restore
				m.Revision = "9223372036854775806"
				m.Restore = true
			}
			out := make([]byte, 0, len(raw))
			for i := 0; i < count; i++ {
				n, _ := BrowserTransferChunkSize(m, i)
				start := i * MaxSecretBytes
				sealed, err := SealBrowserTransferChunk(c, direction, m, i, raw[start:start+n])
				if err != nil {
					t.Fatal(err)
				}
				opened, err := OpenBrowserTransferChunk(private, c, direction, m, i, sealed)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, opened...)
				Wipe(opened)
			}
			decoded, err := DecodeBrowserTransferFrame(out)
			if err != nil || !bytes.Equal(decoded.LocalJSON, local) || !bytes.Equal(decoded.SessionJSON, session) {
				t.Fatal("frame mismatch", err)
			}
			if _, err := json.Marshal(decoded); err == nil {
				t.Fatal("plaintext frame can cross ordinary IPC")
			}
			Wipe(out)
		}
		Wipe(raw)
	}
}
func TestBrowserTransferBindsEveryContextAndManifestField(t *testing.T) {
	c, private, _ := browserTransferFixture(t)
	defer Wipe(private)
	raw, _ := EncodeBrowserTransferFrame([]byte(`{"account":"synthetic"}`), []byte(`{}`))
	defer Wipe(raw)
	m := BrowserTransferManifest{len(raw), c.SourceRevision, false}
	sealed, err := SealBrowserTransferChunk(c, "capture", m, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	changes := []func(*BrowserTransferContext){
		func(c *BrowserTransferContext) { c.WorkspaceID = uuid.NewString() }, func(c *BrowserTransferContext) { c.FileID = uuid.NewString() }, func(c *BrowserTransferContext) { c.ProfileID = uuid.NewString() }, func(c *BrowserTransferContext) { c.RequestID = uuid.NewString() }, func(c *BrowserTransferContext) { c.TransferID = uuid.NewString() }, func(c *BrowserTransferContext) { c.Epoch++ }, func(c *BrowserTransferContext) { c.PolicySequence = "1" }, func(c *BrowserTransferContext) { c.Action = "capture" }, func(c *BrowserTransferContext) { c.SourceRevision = "9223372036854775804" }, func(c *BrowserTransferContext) { c.CapturePublicKey = bytes.Repeat([]byte{9}, 32) }, func(c *BrowserTransferContext) { c.RestorePublicKey = bytes.Repeat([]byte{8}, 32) },
	}
	for i, change := range changes {
		changed := c
		change(&changed)
		if _, err := OpenBrowserTransferChunk(private, changed, "capture", m, 0, sealed); err == nil {
			t.Fatal("context substitution", i)
		}
	}
	for _, changed := range []BrowserTransferManifest{{m.Bytes - 1, m.Revision, false}, {m.Bytes, m.Revision, true}, {m.Bytes, "0", false}} {
		if _, err := OpenBrowserTransferChunk(private, c, "capture", changed, 0, sealed); err == nil {
			t.Fatal("manifest substitution")
		}
	}
	if _, err := OpenBrowserTransferChunk(private, c, "restore", m, 0, sealed); err == nil {
		t.Fatal("direction substitution")
	}
	if _, err := OpenBrowserTransferChunk(private, c, "capture", m, 1, sealed); err == nil {
		t.Fatal("index substitution")
	}
	sealed.Ciphertext[0] ^= 1
	if _, err := OpenBrowserTransferChunk(private, c, "capture", m, 0, sealed); err == nil {
		t.Fatal("ciphertext tamper")
	}
}
func TestBrowserTransferMalformedMetadataAndEnvelopes(t *testing.T) {
	c, private, _ := browserTransferFixture(t)
	defer Wipe(private)
	for _, raw := range []string{"", "01", "-1", "+1", "1.0", "1e1", "9223372036854775808", "18446744073709551616"} {
		if _, err := browserDecimal(raw, true); err == nil {
			t.Fatal("noncanonical decimal")
		}
	}
	if _, err := browserDecimal("0", false); err == nil {
		t.Fatal("zero policy")
	}
	for _, change := range []func(*BrowserTransferContext){func(c *BrowserTransferContext) { c.ProfileID = "bad" }, func(c *BrowserTransferContext) { c.Epoch = 0 }, func(c *BrowserTransferContext) { c.Epoch = math.MaxUint64 }, func(c *BrowserTransferContext) { c.PolicySequence = "0" }, func(c *BrowserTransferContext) { c.SourceRevision = "bad" }, func(c *BrowserTransferContext) { c.Action = "secret" }, func(c *BrowserTransferContext) { c.CapturePublicKey = nil }, func(c *BrowserTransferContext) { c.RestorePublicKey = nil }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid context")
		}
		if _, err := SealBrowserTransferChunk(bad, "capture", BrowserTransferManifest{14, "0", false}, 0, make([]byte, 14)); err == nil {
			t.Fatal("bad binding sealed")
		}
	}
	for _, n := range []int{-1, 0, 13, MaxBrowserTransferFrame + 1} {
		if _, err := BrowserTransferChunkCount(BrowserTransferManifest{Bytes: n}); err == nil {
			t.Fatal("invalid frame bound")
		}
	}
	for _, index := range []int{-1, 5, 100} {
		if _, err := BrowserTransferChunkSize(BrowserTransferManifest{Bytes: 14}, index); err == nil {
			t.Fatal("invalid index")
		}
	}
	raw, _ := EncodeBrowserTransferFrame([]byte(`{}`), []byte(`{}`))
	m := BrowserTransferManifest{len(raw), c.SourceRevision, false}
	if _, err := SealBrowserTransferChunk(c, "capture", m, 1, raw); err == nil {
		t.Fatal("invalid chunk")
	}
	if _, err := SealBrowserTransferChunk(c, "capture", m, 0, nil); err == nil {
		t.Fatal("short chunk")
	}
	if _, err := SealBrowserTransferChunk(c, "capture", BrowserTransferManifest{len(raw), "bad", false}, 0, raw); err == nil {
		t.Fatal("bad revision")
	}
	if _, err := SealBrowserTransferChunk(c, "restore", BrowserTransferManifest{len(raw), "0", false}, 0, raw); err == nil {
		t.Fatal("revision regression")
	}
	if _, err := SealBrowserTransferChunk(c, "other", m, 0, raw); err == nil {
		t.Fatal("unknown direction")
	}
	sealed, err := SealBrowserTransferChunk(c, "capture", m, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SealedBundle){func(b *SealedBundle) { b.FormatVersion = 2 }, func(b *SealedBundle) { b.SuiteID = 1 }, func(b *SealedBundle) { b.Enc = nil }, func(b *SealedBundle) { b.Ciphertext = b.Ciphertext[:len(b.Ciphertext)-1] }} {
		bad := sealed
		change(&bad)
		if _, err := OpenBrowserTransferChunk(private, c, "capture", m, 0, bad); err == nil {
			t.Fatal("invalid envelope")
		}
	}
	if _, err := OpenBrowserTransferChunk(nil, c, "capture", m, 0, sealed); err == nil {
		t.Fatal("missing key")
	}
}
func TestBrowserTransferRejectsMalformedPlaintextFrames(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`[]`), []byte(`null`), []byte(`{} {}`), []byte{0xff, '{', '}'}, bytes.Repeat([]byte{'x'}, MaxBrowserTransferArea+1)} {
		if _, err := EncodeBrowserTransferFrame(raw, []byte(`{}`)); err == nil {
			t.Fatal("invalid local JSON")
		}
		if _, err := EncodeBrowserTransferFrame([]byte(`{}`), raw); err == nil {
			t.Fatal("invalid session JSON")
		}
	}
	good, _ := EncodeBrowserTransferFrame([]byte(`{}`), []byte(`{}`))
	for _, change := range []func([]byte) []byte{func(b []byte) []byte { return nil }, func(b []byte) []byte { return append(b, 0) }, func(b []byte) []byte { b[0] = 2; return b }, func(b []byte) []byte { b[1] = 1; return b }, func(b []byte) []byte { binary.BigEndian.PutUint32(b[2:6], math.MaxUint32); return b }, func(b []byte) []byte { b[10] = '['; return b }, func(b []byte) []byte { b[len(b)-2] = '['; return b }} {
		if _, err := DecodeBrowserTransferFrame(change(bytes.Clone(good))); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestBrowserTransferValidRetaggingCannotBypassAuthentication(t *testing.T) {
	c, private, _ := browserTransferFixture(t)
	defer Wipe(private)
	raw := bytes.Repeat([]byte{'x'}, MaxSecretBytes)
	m := BrowserTransferManifest{Bytes: MaxSecretBytes + 100, Revision: c.SourceRevision}
	sealed, err := SealBrowserTransferChunk(c, "capture", m, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	// Both modified first-chunk contexts retain a full, valid 4 MiB payload size.
	changed := m
	changed.Bytes++
	if _, err := OpenBrowserTransferChunk(private, c, "capture", changed, 0, sealed); err != ErrAuthentication {
		t.Fatal("total length was not authenticated", err)
	}
	// Two full-sized chunks make a valid index substitution rather than a size error.
	m.Bytes = 2 * MaxSecretBytes
	sealed, err = SealBrowserTransferChunk(c, "capture", m, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBrowserTransferChunk(private, c, "capture", m, 1, sealed); err != ErrAuthentication {
		t.Fatal("chunk index was not authenticated", err)
	}
	changed = m
	changed.Revision = "9223372036854775804"
	other := c
	other.SourceRevision = changed.Revision
	if _, err := OpenBrowserTransferChunk(private, other, "capture", changed, 0, sealed); err != ErrAuthentication {
		t.Fatal("source revision was not authenticated", err)
	}
	// Reusing a public recipient for both directions must not make their domains interchangeable.
	c.RestorePublicKey = bytes.Clone(c.CapturePublicKey)
	sealed, err = SealBrowserTransferChunk(c, "capture", m, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBrowserTransferChunk(private, c, "restore", m, 0, sealed); err != ErrAuthentication {
		t.Fatal("direction was not authenticated", err)
	}
	outgoing := m
	outgoing.Revision = "9223372036854775806"
	outgoing.Restore = true
	sealed, err = SealBrowserTransferChunk(c, "restore", outgoing, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*BrowserTransferManifest){func(m *BrowserTransferManifest) { m.Revision = "9223372036854775807" }, func(m *BrowserTransferManifest) { m.Restore = false }} {
		altered := outgoing
		change(&altered)
		if _, err := OpenBrowserTransferChunk(private, c, "restore", altered, 0, sealed); err != ErrAuthentication {
			t.Fatal("restore metadata was not authenticated", err)
		}
	}
}
