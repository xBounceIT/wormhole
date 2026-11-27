package localvault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPersonalVPNSSOSourceAuthorizationAndDurableCustody(t *testing.T) {
	opts, key := options(t)
	defer vault.Wipe(key)
	path := filepath.Join(t.TempDir(), "personal.db")
	policy := SecurityProfile{Sequence: 8, Effective: vault.Standard}
	admitted, checks := true, 0
	security := func(context.Context) (SecurityProfile, error) {
		if !admitted {
			return SecurityProfile{}, vault.ErrPolicy
		}
		return policy, nil
	}
	check := func(context.Context) error {
		checks++
		if !admitted {
			return vault.ErrAuthentication
		}
		return nil
	}
	open := func(create bool) *Owner {
		input := bytes.Clone(key)
		o, err := OpenPersonalVPNSSO(context.Background(), path, opts.Identity, opts.Slots, input, create, false, security)
		if err != nil || !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("personal open/wipe", err)
		}
		t.Cleanup(func() {
			if err := o.Close(); err != nil {
				t.Error(err)
			}
		})
		return o
	}
	o := open(true)
	b := vpnSSOFixture() // Source workspace/file are independent of custody identity.
	q, private := vpnTransferRequest(t)
	defer vault.Wipe(private)
	offer, err := o.BeginAuthorizedVPNSSOTransfer(context.Background(), b, q, check)
	if err != nil || offer.Context.WorkspaceID != opts.Identity.WorkspaceID || offer.Context.FileID != opts.Identity.FileID || offer.Context.PolicySequence != "8" {
		t.Fatal("source policy/personal custody", err)
	}
	restoreVPNTransfer(t, o, offer, private, nil)
	archive := []byte("personal-shared-provider-storage")
	pushVPNTransfer(t, o, offer.Context, archive)
	cp, err := o.CommitVPNSSOTransfer(context.Background(), offer.Context)
	if err != nil || checks < 4 {
		t.Fatal("source admission not checked for actions", err, checks)
	}
	if err := o.PersistVPNSSOCheckpoints(context.Background(), opts.Slots, func(next vault.SlotFile, borrowed []byte) error {
		raw, err := vault.EncodeSlotFile(borrowed, next)
		if err != nil {
			return err
		}
		opts.Slots, err = vault.DecodeSlotFile(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if opts.Slots.ProfileSequence != 8 || len(opts.Slots.VPNSSO) != 1 {
		t.Fatal("source/personal rollback floors not persisted")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o = open(false)
	q, private = vpnTransferRequest(t)
	defer vault.Wipe(private)
	offer, err = o.BeginAuthorizedVPNSSOTransfer(context.Background(), b, q, check)
	if err != nil || offer.Floor.Checkpoint != cp {
		t.Fatal("personal reopen", err)
	}
	restoreVPNTransfer(t, o, offer, private, archive)
	admitted = false
	if _, err := o.TakeVPNSSOTransfer(context.Background(), offer.Context, 0); err == nil {
		t.Fatal("revoked source released data")
	}
	// Revocation cannot prevent exact local cleanup.
	if err := o.CancelVPNSSOTransfer(offer.Context); err != nil {
		t.Fatal(err)
	}
	admitted = true
	policy.Sequence = 7
	if _, err := o.BeginAuthorizedVPNSSOTransfer(context.Background(), b, q, check); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("policy rollback", err)
	}
	policy.Sequence, policy.Effective = 9, vault.Hardened
	if _, err := o.BeginAuthorizedVPNSSOTransfer(context.Background(), b, q, check); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("unsupported source policy", err)
	}
	if _, err := o.BeginAuthorizedVPNSSOTransfer(context.Background(), b, q, nil); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("missing source authority", err)
	}
}

func TestPersonalVPNSSORejectsInvalidOpeningAndConsumesRoot(t *testing.T) {
	opts, key := options(t)
	defer vault.Wipe(key)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, name := range []string{"nil-context", "cancelled", "relative", "nil-security", "identity", "tampered", "encrypted", "initializing", "missing-db"} {
		t.Run(name, func(t *testing.T) {
			contextValue, path, slots, identity := context.Background(), filepath.Join(t.TempDir(), "personal.db"), opts.Slots, opts.Identity
			security := func(context.Context) (SecurityProfile, error) {
				return SecurityProfile{Sequence: 1, Effective: vault.Default}, nil
			}
			switch name {
			case "nil-context":
				contextValue = nil
			case "cancelled":
				contextValue = ctx
			case "relative":
				path = "relative.db"
			case "nil-security":
				security = nil
			case "identity":
				identity.Root.Version++
			case "tampered":
				slots.Sequence++
			case "encrypted", "initializing":
				if name == "encrypted" {
					slots.Encrypted = true
				} else {
					slots.Initializing = true
				}
				raw, err := vault.EncodeSlotFile(key, slots)
				if err != nil {
					t.Fatal(err)
				}
				slots, err = vault.DecodeSlotFile(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			input := bytes.Clone(key)
			if o, err := OpenPersonalVPNSSO(contextValue, path, identity, slots, input, false, false, security); err == nil {
				o.Close()
				t.Fatal("invalid opening accepted")
			}
			if !bytes.Equal(input, make([]byte, len(input))) {
				t.Fatal("failed opening retained root")
			}
		})
	}
}
