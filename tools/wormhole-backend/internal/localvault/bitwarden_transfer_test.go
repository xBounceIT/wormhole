package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func transferRequest(t *testing.T, o *Owner, action, profile, source string) (BitwardenTransferRequest, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := o.WorkspaceID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return BitwardenTransferRequest{workspace, profile, uuid.NewString(), 2, action, source, key.PublicKey().Bytes()}, key.Bytes()
}
func beginTransfer(t *testing.T, o *Owner, action, profile, source string) (vault.BrowserTransferContext, []byte) {
	t.Helper()
	q, key := transferRequest(t, o, action, profile, source)
	c, err := o.BeginBitwardenTransfer(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}
func transferPackets(t *testing.T, c vault.BrowserTransferContext, local, session string) []vault.BrowserTransferPacket {
	t.Helper()
	raw, err := vault.EncodeBrowserTransferFrame([]byte(local), []byte(session))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	return transferRawPackets(t, c, raw)
}
func transferRawPackets(t *testing.T, c vault.BrowserTransferContext, raw []byte) []vault.BrowserTransferPacket {
	t.Helper()
	m := vault.BrowserTransferManifest{Bytes: len(raw), Revision: c.SourceRevision}
	count, err := vault.BrowserTransferChunkCount(m)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]vault.BrowserTransferPacket, count)
	for i := range out {
		size, _ := vault.BrowserTransferChunkSize(m, i)
		sealed, err := vault.SealBrowserTransferChunk(c, "capture", m, i, raw[i*vault.MaxSecretBytes:i*vault.MaxSecretBytes+size])
		if err != nil {
			t.Fatal(err)
		}
		out[i] = vault.BrowserTransferPacket{Context: c, Direction: "capture", Manifest: m, Index: i, Bundle: sealed}
	}
	return out
}
func runTransfer(t *testing.T, o *Owner, action, profile, source, local, session string) (vault.BrowserTransferManifest, string, string) {
	t.Helper()
	c, key := beginTransfer(t, o, action, profile, source)
	defer vault.Wipe(key)
	for _, packet := range transferPackets(t, c, local, session) {
		if err := o.PushBitwardenTransfer(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
	}
	stage := o.bitwardenTransfers[c.TransferID]
	input := stage.input[0].Ciphertext
	nativeKey := stage.key
	m, err := o.CommitBitwardenTransfer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("incoming ciphertext retained after commit")
	}
	if err := nativeKey.With(func([]byte) error { t.Fatal("native recipient remains usable"); return nil }); err != securemem.ErrClosed {
		t.Fatal(err)
	}
	count, _ := vault.BrowserTransferChunkCount(m)
	var raw []byte
	for i := 0; i < count; i++ {
		packet, err := o.TakeBitwardenTransfer(context.Background(), c, i)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := vault.OpenBrowserTransferChunk(key, c, "restore", m, i, packet.Bundle)
		if err != nil {
			t.Fatal("moved packet was corrupted", err)
		}
		raw = append(raw, opened...)
		vault.Wipe(opened)
		wipeBrowserBundles([]vault.SealedBundle{packet.Bundle})
	}
	defer vault.Wipe(raw)
	payload, err := vault.DecodeBrowserTransferFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := o.bitwardenTransfers[c.TransferID]; exists {
		t.Fatal("completed transfer retained")
	}
	if _, err := o.TakeBitwardenTransfer(context.Background(), c, 0); err == nil {
		t.Fatal("output replay")
	}
	if err := o.CancelBitwardenTransfer(c); err != nil {
		t.Fatal("idempotent cancellation", err)
	}
	return m, string(payload.LocalJSON), string(payload.SessionJSON)
}
func TestBitwardenTransfersNativeStateRoundTrip(t *testing.T) {
	o, _, _, _ := owner(t)
	profile := uuid.NewString()
	m, local, session := runTransfer(t, o, "hydrate", profile, "0", `{}`, `{}`)
	if m.Revision != "0" || m.Restore || local != "{}" || session != "{}" {
		t.Fatal(m)
	}
	m, local, session = runTransfer(t, o, "capture", profile, "0", `{"account":"native-transfer-secret"}`, `{"key":"native-session-secret"}`)
	if m.Revision != "1" || m.Restore || local != `{"account":"native-transfer-secret"}` || session != `{"key":"native-session-secret"}` {
		t.Fatal(m)
	}
	m, local, session = runTransfer(t, o, "hydrate", uuid.NewString(), "0", `{}`, `{}`)
	if m.Revision != "1" || !m.Restore || local != `{"account":"native-transfer-secret"}` || session != `{"key":"native-session-secret"}` {
		t.Fatal(m)
	}
}
func TestBitwardenTransfersRejectBadInputsAndPreserveForeignOwnership(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	q, key := transferRequest(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	for _, change := range []func(*BitwardenTransferRequest){func(q *BitwardenTransferRequest) { q.WorkspaceID = uuid.NewString() }, func(q *BitwardenTransferRequest) { q.ProfileID = "bad" }, func(q *BitwardenTransferRequest) { q.RequestID = "bad" }, func(q *BitwardenTransferRequest) { q.Epoch = 0 }, func(q *BitwardenTransferRequest) { q.SourceRevision = "01" }, func(q *BitwardenTransferRequest) { q.Action = "other" }, func(q *BitwardenTransferRequest) { q.RestorePublicKey = nil }, func(q *BitwardenTransferRequest) { q.RestorePublicKey = make([]byte, 32) }} {
		bad := q
		change(&bad)
		if _, err := o.BeginBitwardenTransfer(ctx, bad); err == nil {
			t.Fatal("invalid begin accepted")
		}
	}
	c, err := o.BeginBitwardenTransfer(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.BeginBitwardenTransfer(ctx, q); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	wrong := cloneBrowserTransferContext(c)
	wrong.ProfileID = uuid.NewString()
	if err := o.CancelBitwardenTransfer(wrong); err == nil {
		t.Fatal("foreign cancellation")
	}
	if len(o.bitwardenTransfers) != 1 {
		t.Fatal("foreign cancellation retired owned key")
	}
	packet := transferPackets(t, c, `{}`, `{}`)[0]
	packet.Context = wrong
	if err := o.PushBitwardenTransfer(ctx, packet); err == nil {
		t.Fatal("foreign packet")
	}
	packet.Context = c
	if err := o.PushBitwardenTransfer(ctx, packet); err != nil {
		t.Fatal(err)
	}
	// The manager owns its copies, independently of the caller's packet buffers.
	packet.Bundle.Ciphertext[0] ^= 1
	packet.Bundle.Enc[0] ^= 1
	if _, err := o.CommitBitwardenTransfer(ctx, c); err != nil {
		t.Fatal("packet buffer alias", err)
	}
	if err := o.CancelBitwardenTransfer(c); err != nil {
		t.Fatal(err)
	}
	if err := o.CancelBitwardenTransfer(vault.BrowserTransferContext{}); err == nil {
		t.Fatal("invalid cleanup context")
	}
	if err := o.CloseBitwardenBrowserProfile("bad"); err == nil {
		t.Fatal("invalid profile cleanup")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.BeginBitwardenTransfer(cancelled, q); err != context.Canceled {
		t.Fatal(err)
	}
}
func TestBitwardenTransfersInvalidStagesRetireKeysAndCiphertext(t *testing.T) {
	for _, mode := range []string{"duplicate", "wrong-direction", "wrong-manifest", "tamper", "frame", "incomplete", "take-before-commit", "take-order", "commit-twice", "push-after-commit", "source-conflict", "revision-regression", "cancelled-push", "cancelled-commit"} {
		t.Run(mode, func(t *testing.T) {
			o, _, _, _ := owner(t)
			c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
			defer vault.Wipe(key)
			ctx := context.Background()
			raw, _ := vault.EncodeBrowserTransferFrame([]byte(`{}`), []byte(`{}`))
			if mode == "frame" {
				raw[0] = 2
			}
			packets := transferRawPackets(t, c, raw)
			stage := o.bitwardenTransfers[c.TransferID]
			nativeKey := stage.key
			var err error
			if mode == "take-before-commit" {
				_, err = o.TakeBitwardenTransfer(ctx, c, 0)
			} else if mode == "incomplete" {
				_, err = o.CommitBitwardenTransfer(ctx, c)
			} else if mode == "source-conflict" || mode == "revision-regression" {
				if e := o.CancelBitwardenTransfer(c); e != nil {
					t.Fatal(e)
				}
				action, source := "capture", "0"
				if mode == "revision-regression" {
					action, source = "hydrate", "1"
				}
				c, key = beginTransfer(t, o, action, uuid.NewString(), source)
				defer vault.Wipe(key)
				nativeKey = o.bitwardenTransfers[c.TransferID].key
				for _, p := range transferPackets(t, c, `{}`, `{}`) {
					if e := o.PushBitwardenTransfer(ctx, p); e != nil {
						t.Fatal(e)
					}
				}
				_, err = o.CommitBitwardenTransfer(ctx, c)
			} else {
				packet := packets[0]
				if mode == "wrong-direction" {
					packet.Direction = "restore"
				}
				if mode == "wrong-manifest" {
					packet.Manifest.Restore = true
				}
				if mode == "tamper" {
					packet.Bundle.Ciphertext[0] ^= 1
				}
				if mode == "cancelled-push" {
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					err = o.PushBitwardenTransfer(cancelled, packet)
				} else {
					err = o.PushBitwardenTransfer(ctx, packet)
				}
				if err == nil {
					switch mode {
					case "duplicate":
						err = o.PushBitwardenTransfer(ctx, packet)
					case "take-order", "commit-twice", "push-after-commit":
						if _, e := o.CommitBitwardenTransfer(ctx, c); e != nil {
							t.Fatal(e)
						}
						if mode == "take-order" {
							_, err = o.TakeBitwardenTransfer(ctx, c, 1)
						} else if mode == "commit-twice" {
							_, err = o.CommitBitwardenTransfer(ctx, c)
						} else {
							err = o.PushBitwardenTransfer(ctx, packet)
						}
					default:
						if mode == "cancelled-commit" {
							cancelled, cancel := context.WithCancel(ctx)
							cancel()
							_, err = o.CommitBitwardenTransfer(cancelled, c)
						} else {
							_, err = o.CommitBitwardenTransfer(ctx, c)
						}
					}
				}
			}
			if err == nil {
				t.Fatal("invalid stage succeeded")
			}
			if len(o.bitwardenTransfers) != 0 {
				t.Fatal("failed stage retained")
			}
			if err := nativeKey.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
				t.Fatal("failed stage retained usable recipient", err)
			}
		})
	}
}
func TestBitwardenTransfersCapacityAndProfileClose(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	var contexts []vault.BrowserTransferContext
	for i := 0; i < maxBitwardenTransfers; i++ {
		c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
		vault.Wipe(key)
		contexts = append(contexts, c)
	}
	q, key := transferRequest(t, o, "hydrate", uuid.NewString(), "0")
	vault.Wipe(key)
	if _, err := o.BeginBitwardenTransfer(ctx, q); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	nativeKey := o.bitwardenTransfers[contexts[0].TransferID].key
	if err := o.CloseBitwardenBrowserProfile(contexts[0].ProfileID); err != nil {
		t.Fatal(err)
	}
	if err := nativeKey.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
		t.Fatal(err)
	}
	c, err := o.BeginBitwardenTransfer(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.CancelBitwardenTransfer(c); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if len(o.bitwardenTransfers) != 0 {
		t.Fatal("owner retained stages")
	}
	if _, err := o.BeginBitwardenTransfer(ctx, q); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}
func TestBitwardenTransfersRealExpiryAndPinnedPolicy(t *testing.T) {
	o, _, _, _ := owner(t)
	q, key := transferRequest(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	o.mu.Lock()
	c, err := o.beginBitwardenTransfer(context.Background(), q, 20*time.Millisecond)
	if err != nil {
		o.mu.Unlock()
		t.Fatal(err)
	}
	nativeKey := o.bitwardenTransfers[c.TransferID].key
	o.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		o.mu.Lock()
		n := len(o.bitwardenTransfers)
		o.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timer did not retire key")
		}
		time.Sleep(time.Millisecond)
	}
	if err := nativeKey.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
		t.Fatal(err)
	}
	c, key = beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	policy, err := o.ReadLocalPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(context.Background(), policy.Policy, vault.Default, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.PushBitwardenTransfer(context.Background(), transferPackets(t, c, `{}`, `{}`)[0]); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("changed policy accepted", err)
	}
	if len(o.bitwardenTransfers) != 0 {
		t.Fatal("policy change retained stage")
	}
}

type transferFailedKey struct {
	bitwardenTransferKey
	fail bool
}

func (k *transferFailedKey) Close() error {
	err := k.bitwardenTransferKey.Close()
	if k.fail {
		k.fail = false
		return errors.Join(err, securemem.ErrUnavailable)
	}
	return err
}
func TestBitwardenTransfersUncertainKeyCloseCannotAcknowledgeOrReopen(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	stage := o.bitwardenTransfers[c.TransferID]
	stage.key = &transferFailedKey{stage.key, true}
	if err := o.CancelBitwardenTransfer(c); !errors.Is(err, securemem.ErrUnavailable) {
		t.Fatal(err)
	}
	if !stage.retired || len(o.bitwardenTransfers) != 1 {
		t.Fatal("unconfirmed cleanup lost reservation")
	}
	if err := stage.key.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
		t.Fatal(err)
	}
	if err := o.CancelBitwardenTransfer(c); err != nil {
		t.Fatal(err)
	}
	q, private := transferRequest(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(private)
	if _, err := o.BeginBitwardenTransfer(ctx, q); err != vault.ErrPolicy {
		t.Fatal("failed cleanup silently reopened", err)
	}
}

func TestBitwardenTransfersKeyReleaseFailuresAtCommitProfileAndOwnerClose(t *testing.T) {
	for _, operation := range []string{"commit", "profile", "owner"} {
		t.Run(operation, func(t *testing.T) {
			o, _, _, _ := owner(t)
			c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
			defer vault.Wipe(key)
			stage := o.bitwardenTransfers[c.TransferID]
			stage.key = &transferFailedKey{stage.key, true}
			var err error
			switch operation {
			case "commit":
				if err := o.PushBitwardenTransfer(context.Background(), transferPackets(t, c, `{}`, `{}`)[0]); err != nil {
					t.Fatal(err)
				}
				_, err = o.CommitBitwardenTransfer(context.Background(), c)
				if o.bitwarden != nil {
					t.Fatal("state API ran after unconfirmed key release")
				}
			case "profile":
				err = o.CloseBitwardenBrowserProfile(c.ProfileID)
			case "owner":
				err = o.Close()
			}
			if !errors.Is(err, securemem.ErrUnavailable) || !o.bitwardenTransferFailure {
				t.Fatal("unconfirmed release acknowledged", err)
			}
			if err := o.Close(); err != nil {
				t.Fatal("cleanup retry failed", err)
			}
			if len(o.bitwardenTransfers) != 0 {
				t.Fatal("close retry retained key reservation")
			}
		})
	}
}
func TestBitwardenTransfersRetainedBudgetAndCommitReservation(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	var contexts []vault.BrowserTransferContext
	for i := 0; i < 3; i++ {
		c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
		vault.Wipe(key)
		contexts = append(contexts, c)
		manifest := vault.BrowserTransferManifest{Bytes: vault.MaxBrowserTransferFrame, Revision: "0"}
		count, _ := vault.BrowserTransferChunkCount(manifest)
		for index := 0; index < count; index++ {
			size, _ := vault.BrowserTransferChunkSize(manifest, index)
			p := vault.BrowserTransferPacket{Context: c, Direction: "capture", Manifest: manifest, Index: index, Bundle: vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, size+16)}}
			if err := o.PushBitwardenTransfer(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	c, key := beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	for _, p := range transferPackets(t, c, `{}`, `{}`) {
		if err := o.PushBitwardenTransfer(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.CommitBitwardenTransfer(ctx, c); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("unreserved output could commit", err)
	}
	if o.bitwarden != nil {
		t.Fatal("budget failure touched shared state")
	}
	if o.bitwardenTransferBytes() > maxBitwardenTransferRetained {
		t.Fatal("retained budget exceeded")
	}
	// A fourth maximum-size ingress must fail instead of crossing the budget.
	c, key = beginTransfer(t, o, "hydrate", uuid.NewString(), "0")
	defer vault.Wipe(key)
	m := vault.BrowserTransferManifest{Bytes: vault.MaxBrowserTransferFrame, Revision: "0"}
	count, _ := vault.BrowserTransferChunkCount(m)
	failed := false
	for i := 0; i < count; i++ {
		size, _ := vault.BrowserTransferChunkSize(m, i)
		p := vault.BrowserTransferPacket{Context: c, Direction: "capture", Manifest: m, Index: i, Bundle: vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, size+16)}}
		err := o.PushBitwardenTransfer(ctx, p)
		if err != nil {
			if !errors.Is(err, vault.ErrPolicy) {
				t.Fatal(err)
			}
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("unbounded fourth ingress")
	}
	for _, c := range contexts {
		if err := o.CancelBitwardenTransfer(c); err != nil {
			t.Fatal(err)
		}
	}
	if o.bitwardenTransferBytes() != 0 {
		t.Fatal("retired buffers remain counted")
	}
}
func TestBitwardenTransfersMaximumNativeRoundTrip(t *testing.T) {
	o, _, _, _ := owner(t)
	profile := uuid.NewString()
	runTransfer(t, o, "hydrate", profile, "0", `{}`, `{}`)
	local := `{"v":"` + string(bytes.Repeat([]byte{'x'}, MaxBitwardenBrowserJSON-8)) + `"}`
	m, got, session := runTransfer(t, o, "capture", profile, "0", local, local)
	if m.Bytes != vault.MaxBrowserTransferFrame || m.Revision != strconv.Itoa(1) || got != local || session != local {
		t.Fatal("maximum native transfer mismatch")
	}
}
