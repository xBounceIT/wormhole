package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func unprotectedUpgradeSource(t *testing.T) rotationOwnerFixture {
	t.Helper()
	f := rotationOwner(t)
	ctx := context.Background()
	policy, err := f.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	// Model an authenticated floor now requiring protection. Ordinary Open must
	// reject the old OS-only source even though its root still authenticates it.
	if _, err := f.owner.PutLocalPolicy(ctx, policy.Policy, vault.Standard, policy.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	doc := f.options.Slots
	slot, err := vault.CreateUnprotectedSlot(doc.VaultID, uuid.NewString(), doc.RootKeyVersion, f.oldKey, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	doc.FormatVersion, doc.Slots = vault.SlotFileFormatVersion, []vault.Slot{slot}
	raw, err := vault.EncodeSlotFile(f.oldKey, doc)
	if err != nil {
		t.Fatal(err)
	}
	f.options.Slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.options.Create, f.options.RequireLocked = false, true
	return f
}

type blockedUpgradeContext struct {
	context.Context
	once             sync.Once
	entered, release chan struct{}
}

type upgradeOpeningContext struct {
	context.Context
	admission *unprotectedUpgradeAdmission
	input     []byte
	observed  bool
}

func (c *upgradeOpeningContext) Err() error {
	if c.admission.root != nil && c.admission.store == nil {
		c.observed = true
		if !bytes.Equal(c.input, make([]byte, len(c.input))) {
			return errors.New("root input retained during SQLite opening")
		}
	}
	return c.Context.Err()
}

func TestUnprotectedUpgradeRootInputIsErasedBeforeDatabaseIO(t *testing.T) {
	o, path, options, key := owner(t)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	options.Create = false
	admission := unprotectedUpgradeAdmission{target: options.Slots}
	input := bytes.Clone(key)
	ctx := &upgradeOpeningContext{Context: context.Background(), admission: &admission, input: input}
	opened, err := openNativeOwner(ctx, path, options, input, &admission)
	if opened != nil {
		defer opened.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if !ctx.observed {
		t.Fatal("test did not observe IO after native key capture")
	}
}

func (c *blockedUpgradeContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return context.Canceled
}

func TestUnprotectedUpgradeCloseJoinsInFlightConsumption(t *testing.T) {
	f := unprotectedUpgradeSource(t)
	scope := NewUnprotectedRootUpgrade()
	ctx := &blockedUpgradeContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	old, next := bytes.Clone(f.oldKey), bytes.Clone(f.key)
	staged := make(chan error, 1)
	go func() {
		_, err := scope.Stage(ctx, f.path, filepath.Join(filepath.Dir(f.path), "cancelled.db"), f.options, f.slots, old, next)
		staged <- err
	}()
	<-ctx.entered
	closed := make(chan error, 1)
	go func() {
		err := scope.Close()
		if err == nil && (!bytes.Equal(old, make([]byte, 32)) || !bytes.Equal(next, make([]byte, 32))) {
			err = errors.New("scope close acknowledged before input consumption")
		}
		closed <- err
	}()
	select {
	case <-closed:
		t.Fatal("close escaped an in-flight stage")
	default:
	}
	close(ctx.release)
	if err := <-staged; err != context.Canceled {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestUnprotectedUpgradeStagesWithoutOrdinarySourceAdmission(t *testing.T) {
	f := unprotectedUpgradeSource(t)
	ctx := context.Background()
	if opened, err := Open(ctx, f.path, f.options, bytes.Clone(f.oldKey)); opened != nil || !errors.Is(err, vault.ErrPolicy) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("ordinary Open bypassed the source floor", err)
	}
	scope := NewUnprotectedRootUpgrade()
	defer scope.Close()
	if _, err := json.Marshal(scope); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("upgrade scope serialized", err)
	}
	old, next := bytes.Clone(f.oldKey), bytes.Clone(f.key)
	destination := filepath.Join(filepath.Dir(f.path), "upgraded.db")
	stage, err := scope.Stage(ctx, f.path, destination, f.options, f.slots, old, next)
	if err != nil {
		t.Fatal("forward stage", err)
	}
	if !bytes.Equal(old, make([]byte, 32)) || !bytes.Equal(next, make([]byte, 32)) {
		t.Fatal("source/new key not consumed")
	}
	doc, err := stage.Document()
	if err != nil || doc.ProfileSequence < 2 || doc.RootKeyVersion != 2 {
		t.Fatal("target floors", err)
	}
	if scope.admission.owner.mu.TryLock() {
		scope.admission.owner.mu.Unlock()
		t.Fatal("source owner not frozen")
	}
	if _, err := scope.Stage(ctx, f.path, destination, f.options, f.slots, bytes.Clone(f.oldKey), bytes.Clone(f.key)); err != vault.ErrPolicy {
		t.Fatal("scope reused", err)
	}
	if _, _, err := stage.SealSourceRecovery(f.key); err != nil {
		t.Fatal("new-root recovery", err)
	}
	if err := stage.CloseDatabases(); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if scope.admission.owner != nil || scope.admission.root != nil || scope.stage != nil {
		t.Fatal("scope retained resources after acknowledged close")
	}
	options := f.options
	options.Slots, options.Identity.Root.Version = doc, doc.RootKeyVersion
	owner, err := Open(ctx, destination, options, bytes.Clone(f.key))
	if err != nil {
		t.Fatal("protected target denied", err)
	}
	defer owner.Close()
	if err := owner.WithSecret(ctx, f.standalone, 1, func(value []byte) error {
		if string(value) != "root-rotation-native-standalone" {
			return vault.ErrAuthentication
		}
		return nil
	}); err != nil {
		t.Fatal("forward upgrade lost secret", err)
	}
	if profile, err := owner.ReadSecurityProfile(ctx); err != nil || profile.Effective != vault.Standard {
		t.Fatal("source floor lowered", err)
	}
	if err := owner.VerifyRootRotation(ctx); err != nil {
		t.Fatal("graph audit", err)
	}
}

func TestUnprotectedUpgradeRejectionsKeepCleanupAndWipeKeys(t *testing.T) {
	f := unprotectedUpgradeSource(t)
	for _, mode := range []string{"closed", "cancelled", "create", "import", "unlocked-memory", "protected-source", "no-source-slot", "same-key", "short-key", "wrong-source-key", "wrong-identity", "no-password", "wrong-version", "OS-target", "weak-target", "occupied-target", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			scope := NewUnprotectedRootUpgrade()
			defer scope.Close()
			options := f.options
			slots := append([]vault.Slot(nil), f.slots...)
			old, next := bytes.Clone(f.oldKey), bytes.Clone(f.key)
			source, destination := f.path, filepath.Join(filepath.Dir(f.path), "denied-"+mode+".db")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "closed":
				scope.Close()
			case "cancelled":
				cancel()
			case "create":
				options.Create = true
			case "import":
				options.AllowImport = true
			case "unlocked-memory":
				options.RequireLocked = false
			case "protected-source":
				options.Slots.Slots = []vault.Slot{f.slots[1]}
			case "no-source-slot":
				options.Slots.Slots = nil
			case "same-key":
				copy(next, old)
			case "short-key":
				old = old[:31]
			case "wrong-source-key":
				old[0] ^= 1
			case "wrong-identity":
				options.Identity.FileID = uuid.NewString()
			case "no-password":
				slots = slots[1:]
			case "wrong-version":
				slots[0].WrappedKey.KeyVersion++
			case "OS-target":
				slots[0].Kind = vault.SlotUnprotected
			case "weak-target":
				slots[0].Preset = vault.KDFLow
			case "occupied-target":
				if err := os.WriteFile(destination, []byte("unrelated target"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-source":
				source = filepath.Join(filepath.Dir(f.path), "missing-source.db")
			}
			if stage, err := scope.Stage(ctx, source, destination, options, slots, old, next); stage != nil || err == nil {
				t.Fatal("invalid upgrade admitted", err)
			}
			if !bytes.Equal(old, make([]byte, len(old))) || !bytes.Equal(next, make([]byte, len(next))) {
				t.Fatal("denied keys retained")
			}
			if mode == "occupied-target" {
				raw, err := os.ReadFile(destination)
				if err != nil || string(raw) != "unrelated target" {
					t.Fatal("unrelated file changed", err)
				}
			}
			if err := scope.Close(); err != nil {
				t.Fatal("failed opening cleanup", err)
			}
			if scope.admission.root != nil || scope.admission.store != nil || scope.admission.owner != nil {
				t.Fatal("failed resources retained after acknowledged close")
			}
		})
	}
}

func TestUnprotectedUpgradeSnapshotsOverlappingKeysBeforeConsumingThem(t *testing.T) {
	f := unprotectedUpgradeSource(t)
	shared := make([]byte, 48)
	copy(shared, f.oldKey)
	copy(shared[32:], bytes.Repeat([]byte{0x27}, 16))
	expected := bytes.Clone(shared[16:])
	defer vault.Wipe(expected)
	p, err := vault.CreatePasswordSlot(context.Background(), f.options.Identity.WorkspaceID, uuid.NewString(), 2, expected, []byte("overlapping native upgrade fixture"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := vault.CreateRecoverySlot(f.options.Identity.WorkspaceID, uuid.NewString(), 2, expected, bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	scope := NewUnprotectedRootUpgrade()
	defer scope.Close()
	destination := filepath.Join(filepath.Dir(f.path), "overlap.db")
	stage, err := scope.Stage(context.Background(), f.path, destination, f.options, []vault.Slot{p, r}, shared[:32], shared[16:])
	if err != nil {
		t.Fatal("overlap consumed before snapshot", err)
	}
	if !bytes.Equal(shared, make([]byte, len(shared))) {
		t.Fatal("overlapping inputs retained")
	}
	doc, err := stage.Document()
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.Slots, options.Identity.Root.Version = doc, doc.RootKeyVersion
	opened, err := Open(context.Background(), destination, options, bytes.Clone(expected))
	if err != nil {
		t.Fatal("overlapping target key changed", err)
	}
	defer opened.Close()
	if err := opened.VerifyRootRotation(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type upgradeCloseFailure struct {
	vaultstore.Store
	fail bool
}

func (s *upgradeCloseFailure) Close() error {
	if s.fail {
		return vaultstore.ErrStorage
	}
	return s.Store.Close()
}

func TestUnprotectedUpgradeRetainsFailedAndPartialCleanup(t *testing.T) {
	f := unprotectedUpgradeSource(t)
	scope := NewUnprotectedRootUpgrade()
	destination := filepath.Join(filepath.Dir(f.path), "close.db")
	stage, err := scope.Stage(context.Background(), f.path, destination, f.options, f.slots, bytes.Clone(f.oldKey), bytes.Clone(f.key))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	store := &upgradeCloseFailure{Store: scope.admission.owner.store, fail: true}
	scope.admission.owner.store = store
	if err := scope.Close(); !errors.Is(err, vaultstore.ErrStorage) || scope.admission.owner == nil {
		t.Fatal("unconfirmed source cleanup discarded", err)
	}
	store.fail = false
	if err := scope.Close(); err != nil || scope.admission.owner != nil {
		t.Fatal("cleanup retry", err)
	}
	partial := NewUnprotectedRootUpgrade()
	root, err := securemem.New(32, true)
	if err != nil {
		t.Fatal(err)
	}
	partial.admission.root = root
	partial.admission.store = &upgradeCloseFailure{Store: store.Store, fail: true}
	if err := partial.Close(); err == nil || partial.admission.root == nil {
		t.Fatal("partial cleanup obligation lost", err)
	}
	partial.admission.store.(*upgradeCloseFailure).fail = false
	if err := partial.Close(); err != nil || partial.admission.root != nil {
		t.Fatal("partial cleanup retry", err)
	}
}
