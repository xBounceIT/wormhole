package localvault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestReauthenticationBindsCurrentOwnerAndCheckpoint(t *testing.T) {
	o, _, opts, key := owner(t)
	ctx := context.Background()
	factor := bytes.Repeat([]byte{3}, 32)
	verify := func(doc vault.SlotFile, id string, p, r, a []byte) error {
		return o.VerifyReauthentication(ctx, doc, id, p, r, a)
	}
	if err := verify(opts.Slots, opts.Slots.Slots[0].ID, nil, factor, nil); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		id      string
		p, r, a []byte
	}{
		{uuid.NewString(), nil, factor, nil}, {opts.Slots.Slots[0].ID, nil, bytes.Repeat([]byte{4}, 32), nil}, {opts.Slots.Slots[0].ID, []byte("mixed"), factor, nil}, {opts.Slots.Slots[0].ID, nil, nil, nil}, {opts.Slots.Slots[0].ID, nil, factor, factor},
	} {
		if err := verify(opts.Slots, input.id, input.p, input.r, input.a); !errors.Is(err, ErrReauthentication) {
			t.Fatal("factor rejected incorrectly", err)
		}
	}
	for _, mutate := range []func(*vault.SlotFile){func(d *vault.SlotFile) { d.VaultID = uuid.NewString() }, func(d *vault.SlotFile) { d.RootKeyID = uuid.NewString() }, func(d *vault.SlotFile) { d.Initializing = true }, func(d *vault.SlotFile) { d.Sequence++ }} {
		doc := opts.Slots
		mutate(&doc)
		if err := verify(doc, doc.Slots[0].ID, nil, factor, nil); err == nil || errors.Is(err, ErrReauthentication) {
			t.Fatal("untrusted checkpoint treated as factor failure", err)
		}
	}
	next := opts.Slots
	next.Sequence++
	raw, err := vault.EncodeSlotFile(key, next)
	if err != nil {
		t.Fatal(err)
	}
	next, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(next, next.Slots[0].ID, nil, factor, nil); err != nil {
		t.Fatal(err)
	}
	if err := verify(opts.Slots, opts.Slots.Slots[0].ID, nil, factor, nil); err == nil {
		t.Fatal("observed slot checkpoint rolled back")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.VerifyReauthentication(canceled, next, next.Slots[0].ID, nil, factor, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	o.Close()
	if err := verify(next, next.Slots[0].ID, nil, factor, nil); !errors.Is(err, vaultstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestReauthenticationPasswordAndPolicy(t *testing.T) {
	o, _, opts, key := owner(t)
	ctx := context.Background()
	password := []byte("synthetic fresh password")
	slot, err := vault.CreatePasswordSlot(ctx, opts.Slots.VaultID, uuid.NewString(), 1, key, password, nil, vault.KDFLow)
	if err != nil {
		t.Fatal(err)
	}
	doc := opts.Slots
	doc.Slots = append(doc.Slots, slot)
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	p.Policy.KDF = vault.KDFLow
	p.Policy.LowKDFApproved = true
	if _, err := o.PutLocalPolicy(ctx, p.Policy, vault.Default, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyReauthentication(ctx, doc, slot.ID, password, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{nil, []byte("wrong"), bytes.Repeat([]byte{1}, 1025)} {
		if err := o.VerifyReauthentication(ctx, doc, slot.ID, p, nil, nil); !errors.Is(err, ErrReauthentication) {
			t.Fatal(err)
		}
	}
	if err := o.VerifyReauthentication(ctx, doc, slot.ID, password, nil, []byte{1}); !errors.Is(err, ErrReauthentication) {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	p.Policy.MinAPI = 2
	p.Policy.MaxAPI = 2
	if _, err := o.PutLocalPolicy(ctx, p.Policy, vault.Default, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyReauthentication(ctx, doc, slot.ID, password, nil, nil); !errors.Is(err, vault.ErrNewerFormat) {
		t.Fatal("policy ignored", err)
	}
}
