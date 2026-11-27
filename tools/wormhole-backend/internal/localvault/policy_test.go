package localvault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type policyTestStore struct {
	vaultstore.ProfileStore
	readError  error
	writeError error
	transform  func([]byte) []byte
}

func (s policyTestStore) ReadProfile(ctx context.Context) ([]byte, error) {
	if s.readError != nil {
		return nil, s.readError
	}
	raw, err := s.ProfileStore.ReadProfile(ctx)
	if err == nil && s.transform != nil {
		raw = s.transform(raw)
	}
	return raw, err
}
func (s policyTestStore) WriteProfile(ctx context.Context, raw, expected []byte) error {
	if s.writeError != nil {
		return s.writeError
	}
	return s.ProfileStore.WriteProfile(ctx, raw, expected)
}

func TestLocalPolicyTighteningOnlyAdvancesAfterSignedWrite(t *testing.T) {
	ctx := context.Background()
	o, _, opts, key := owner(t)
	if err := o.TightenToStandard(ctx, 1); err != vault.ErrPolicy {
		t.Fatal("missing password slot", err)
	}
	doc := opts.Slots
	password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("profile fixture"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	doc.Slots = append(doc.Slots, password)
	doc.Sequence++
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyReauthentication(ctx, doc, password.ID, []byte("profile fixture"), nil, nil); err != nil {
		t.Fatal(err)
	}
	store := o.store.(vaultstore.ProfileStore)
	o.store = policyTestStore{ProfileStore: store, writeError: vaultstore.ErrStorage}
	if err := o.TightenToStandard(ctx, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = store
	p, err := o.ReadSecurityProfile(ctx)
	if err != nil || p.Effective != vault.Default || !p.CanTightenToStandard || p.Sequence != 1 {
		t.Fatal("failed write changed the personal floor", p, err)
	}
	if err := o.TightenToStandard(ctx, 2); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if err := o.TightenToStandard(ctx, 1); err != nil {
		t.Fatal(err)
	}
	p, err = o.ReadSecurityProfile(ctx)
	if err != nil || p.Effective != vault.Standard || p.CanTightenToStandard || p.Sequence != 2 {
		t.Fatal("committed floor", p, err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.TightenToStandard(ctx, 2); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestLocalPolicyOwnerInitializesAuthenticatesAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	initial, err := o.ReadLocalPolicy(ctx)
	if err != nil || initial.Policy.Profile != vault.Default || initial.UserProfile != vault.Default || initial.Policy.Sequence != 1 {
		t.Fatal("initial policy", err)
	}
	s := o.store.(vaultstore.ProfileStore)
	old, err := s.ReadProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := initial.Policy
	policy.Sequence++
	policy.Profile = vault.Standard
	policy.KDF = vault.KDFV2
	updated, err := o.PutLocalPolicy(ctx, policy, vault.Hardened, 1)
	if err != nil || updated.Policy.Sequence != 2 || vault.EffectiveProfile(vault.Default, updated.Policy.Profile, updated.UserProfile) != vault.Hardened {
		t.Fatal("policy edit", err)
	}
	if err := vault.VerifyLocalPolicy(key, updated, opts.Identity.WorkspaceID, opts.Identity.FileID, opts.Identity.Root.ID, opts.Identity.Root.Version, 2); err != nil {
		t.Fatal("returned stale authentication", err)
	}
	if _, err := o.PutLocalPolicy(ctx, policy, vault.Default, 1); err != vaultstore.ErrConflict {
		t.Fatal("stale edit", err)
	}
	latest, err := s.ReadProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteProfile(ctx, old, latest); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadLocalPolicy(ctx); err != vault.ErrRollback {
		t.Fatal("same-process replay", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	opts.Slots.ProfileSequence = 2
	encoded, err := vault.EncodeSlotFile(key, opts.Slots)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots, err = vault.DecodeSlotFile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(ctx, path, opts, bytes.Clone(key)); !errors.Is(err, vault.ErrRollback) || reopened != nil {
		t.Fatal("checkpoint replay", err)
	}
	if _, err := o.ReadLocalPolicy(ctx); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	policy.Sequence = 3
	if _, err := o.PutLocalPolicy(ctx, policy, vault.Default, 2); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestLocalPolicyOwnerRejectsFaultsAndInvalidEdits(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	initial, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := o.store.(vaultstore.ProfileStore)
	for _, mode := range []string{"missing", "storage", "format", "authentication", "unsupported", "write"} {
		wrapped := policyTestStore{ProfileStore: s}
		switch mode {
		case "missing":
			wrapped.readError = vaultstore.ErrMissing
		case "storage":
			wrapped.readError = vaultstore.ErrStorage
		case "format":
			wrapped.transform = func([]byte) []byte { return []byte(`{}`) }
		case "authentication":
			wrapped.transform = func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"userProfile":"default"`), []byte(`"userProfile":"standard"`), 1)
			}
		case "write":
			wrapped.writeError = vaultstore.ErrConflict
		}
		o.store = wrapped
		if mode == "unsupported" {
			o.store = transformingStore{Store: s}
		}
		policy := initial.Policy
		policy.Sequence++
		if _, err := o.PutLocalPolicy(ctx, policy, vault.Default, 1); err == nil {
			t.Fatal("fault accepted", mode)
		}
		o.store = s
		got, err := o.ReadLocalPolicy(ctx)
		if err != nil || got.Policy.Sequence != 1 {
			t.Fatal("fault changed policy", err)
		}
	}
	for _, test := range []struct {
		expected, sequence uint64
		workspace          string
		floor              vault.Profile
	}{
		{0, 1, initial.Policy.WorkspaceID, vault.Default}, {math.MaxInt64, math.MaxInt64 + 1, initial.Policy.WorkspaceID, vault.Default},
		{1, 3, initial.Policy.WorkspaceID, vault.Default}, {1, 2, uuid.NewString(), vault.Default}, {1, 2, initial.Policy.WorkspaceID, "future"},
	} {
		policy := initial.Policy
		policy.Sequence = test.sequence
		policy.WorkspaceID = test.workspace
		if _, err := o.PutLocalPolicy(ctx, policy, test.floor, test.expected); err == nil {
			t.Fatal("invalid edit accepted")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadLocalPolicy(canceled); err != context.Canceled {
		t.Fatal(err)
	}
	policy := initial.Policy
	policy.Sequence++
	if _, err := o.PutLocalPolicy(canceled, policy, vault.Default, 1); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestLocalPolicyMissingOrTamperedOnDiskNeverReseedsExistingVault(t *testing.T) {
	for _, value := range []any{nil, []byte(`{"profile":"default"}`)} {
		o, path, opts, key := owner(t)
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("UPDATE WorkspaceMeta SET SignedProfile=?", value); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		opts.Create = false
		if opened, err := Open(context.Background(), path, opts, bytes.Clone(key)); err == nil || opened != nil {
			t.Fatal("missing policy repaired")
		}
		db, err = sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := db.QueryRow("SELECT SignedProfile FROM WorkspaceMeta").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if value == nil && raw != nil {
			t.Fatal("policy reseeded")
		}
		if value != nil && !bytes.Equal(raw, value.([]byte)) {
			t.Fatal("policy repaired")
		}
	}
}

func TestLocalPolicySeedUsesAuthenticatedSlotParametersAndSurvivesResume(t *testing.T) {
	ctx := context.Background()
	opts, key := options(t)
	defer vault.Wipe(key)
	password, err := vault.CreatePasswordSlot(ctx, opts.Identity.WorkspaceID, uuid.NewString(), 1, key, []byte("synthetic-password"), nil, vault.KDFLow)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots.Slots = append(opts.Slots.Slots, password)
	opts.Slots.ProfileSequence = 7
	opts.Slots.Initializing = true
	raw, err := vault.EncodeSlotFile(key, opts.Slots)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.db")
	o, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	p, err := o.ReadLocalPolicy(ctx)
	if err != nil || p.Policy.Sequence != 7 || p.Policy.KDF != vault.KDFLow || !p.Policy.LowKDFApproved || p.Policy.Profile != vault.Default {
		t.Fatal("slot-bound seed", err)
	}
	stored, err := o.store.(vaultstore.ProfileStore).ReadProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	resumed, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	after, err := resumed.store.(vaultstore.ProfileStore).ReadProfile(ctx)
	if err != nil || !bytes.Equal(stored, after) {
		t.Fatal("resume replaced existing seed", err)
	}
	// Even a policy-only change invalidates the pristine initialization marker.
	p.Policy.Sequence++
	if _, err := resumed.PutLocalPolicy(ctx, p.Policy, vault.Default, 7); err != nil {
		t.Fatal(err)
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
	if replayed, err := Open(ctx, path, opts, bytes.Clone(key)); !errors.Is(err, vaultstore.ErrConflict) || replayed != nil {
		t.Fatal("initialization replay after policy-only write", err)
	}
}
