package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func migrationStageFixture(t *testing.T) (*sql.DB, string, vault.SlotFile, []byte, resolver.MigrationPlan, []string) {
	t.Helper()
	db, path := snapshotDatabase(t)
	doc, key := localSlotFixture(t)
	doc.Nodes = nil
	credential, folder, first, second := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	legacyVaultProfile(t, db, credential, 0)
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Protocol=6,Username=NULL`)
	legacyVaultNodeRow(t, db, folder, nil, 0)
	for _, id := range []string{first, second} {
		legacyVaultNodeRow(t, db, id, folder, 1)
		legacyVaultSQL(t, db, `UPDATE Nodes SET Protocol=6,Host='vnc.example',CredentialMode=2,CredentialId=?,Notes='private stage note' WHERE Id=?`, credential, id)
	}
	plan, err := prepareLegacyResolverMigration(context.Background(), db, doc.VaultID)
	if err != nil || len(plan.Entries) != 2 {
		t.Fatal("fixture needs two changed VNC paths", plan, err)
	}
	return db, path, doc, key, plan, []string{credential, folder, first, second}
}

func openNativeMigrationStage(t *testing.T, path string, key []byte) *localvault.Owner {
	t.Helper()
	doc, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := openVaultFiles(context.Background(), path, doc, key); err != vault.ErrPolicy || owner != nil {
		t.Fatal("ordinary unlock accepted stage", err)
	}
	options := localVaultOptions(doc)
	options.AllowImport = true
	owner, err := localvault.Open(context.Background(), path, options, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestVaultMigrationStageDomainsPinsAndRestart(t *testing.T) {
	db, source, doc, key, plan, ids := migrationStageFixture(t)
	ctx := context.Background()
	for attempt := 0; attempt < 3; attempt++ {
		wantNote := "private stage note"
		if attempt >= 1 {
			wantNote = "changed source note"
			legacyVaultSQL(t, db, `UPDATE Nodes SET Notes=? WHERE Id=?`, wantNote, ids[2])
		}
		if attempt == 2 {
			// Model a crash leaving a torn DB and recovery sidecars. Only the
			// authenticated, UUID-bound unpublished stage may be rebuilt.
			for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
				if err := os.WriteFile(source+".migrating-"+doc.FileID+suffix, []byte("torn staging fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		result, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan)
		if err != nil {
			t.Fatal(err)
		}
		if result.Credentials != 1 || result.Tunnels != 0 || result.Nodes != 3 || result.Pins != 2 || result.Path != source+".migrating-"+doc.FileID {
			t.Fatal("incorrect import result", result)
		}
		marker, err := readVaultSlotFile(result.Path)
		if err != nil || marker.Migration.Phase != vault.MigrationDomainsCopied || marker.Sequence != uint64(2+2*attempt) {
			t.Fatal("journal did not advance", marker, err)
		}
		owner := openNativeMigrationStage(t, result.Path, key)
		for _, id := range ids[2:] {
			n, err := owner.ReadNode(ctx, id, 2)
			if err != nil || n.CreatedAt != "2020-01-02T03:04:05Z" || n.UpdatedAt != "2023-02-03T04:05:06.1234567Z" {
				t.Fatal("pin import changed source timestamps", n, err)
			}
			pin, err := owner.ReadResolverMigration(ctx, id, 2)
			if err != nil || len(pin.Entries) != 1 || pin.Fingerprint != plan.Fingerprint || pin.Entries[0].Choice != "keep" {
				t.Fatal("missing sealed choice", pin, err)
			}
			r, err := owner.ResolveConnectionPath(ctx, id, "", "vnc")
			if err != nil || r.Account.SourceKind != "none" {
				t.Fatal("historical VNC selection lost", r.Account, err)
			}
		}
		if err := owner.WithNodeField(ctx, ids[2], "notes", 2, equalLegacyVaultValue([]byte(wantNote))); err != nil {
			t.Fatal(err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{result.Path, vaultSlotPath(result.Path)} {
			data, err := os.ReadFile(path)
			if err != nil || bytes.Contains(data, []byte(wantNote)) {
				t.Fatal("plaintext note persisted", err)
			}
		}
		if err := requireLegacyWorkspace(source); err != errVaultOwnerRequired {
			t.Fatal("staged source is not quarantined", err)
		}
		if err := requireLegacySlotAbsent(source); err != nil {
			t.Fatal("source retirement started before its journal", err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM Nodes").Scan(&count); err != nil || count != 3 {
		t.Fatal("source mutated", err)
	}
}

func TestVaultMigrationStagePartialCopyIsQuarantinedAndRebuilt(t *testing.T) {
	db, source, doc, key, plan, ids := migrationStageFixture(t)
	legacyVaultSQL(t, db, `UPDATE Nodes SET UpdatedAt='invalid' WHERE Id=?`, ids[2])
	result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err == nil || !reflect.DeepEqual(result, legacyVaultStage{}) {
		t.Fatal("partial copy reported success", result, err)
	}
	stage := source + ".migrating-" + doc.FileID
	marker, err := readVaultSlotFile(stage)
	if err != nil || marker.Migration.Phase != vault.MigrationCopying {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, stage, key)
	if _, err := owner.ReadCredential(context.Background(), ids[0], 1); err != nil {
		t.Fatal("fixture did not fail after writing", err)
	}
	owner.Close()
	legacyVaultSQL(t, db, `UPDATE Nodes SET UpdatedAt='2023-02-03T04:05:06Z' WHERE Id=?`, ids[2])
	result, err = stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err != nil || result.Nodes != 3 {
		t.Fatal("could not rebuild partial copy", err)
	}
	marker, err = readVaultSlotFile(stage)
	if err != nil || marker.Sequence != 3 || marker.Migration.Phase != vault.MigrationDomainsCopied {
		t.Fatal("bad recovery journal", err)
	}
}

func TestVaultMigrationStageRechecksPlanAndBindsChoices(t *testing.T) {
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	ctx := context.Background()
	stage := source + ".migrating-" + doc.FileID
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Username='changed'`)
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan); err != resolver.ErrMigrationStale {
		t.Fatal("stale plan applied", err)
	}
	if _, err := os.Lstat(vaultSlotPath(stage)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale plan created stage")
	}
	legacyVaultSQL(t, db, `UPDATE CredentialProfiles SET Username=NULL`)
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(stage)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := plan.Decide(plan.Fingerprint, []resolver.MigrationDecision{{NodeID: plan.Entries[0].Legacy.NodeID, ProtocolPath: "vnc", Choice: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, key, changed); err != vault.ErrPolicy {
		t.Fatal("different choices resumed stage", err)
	}
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, bytes.Repeat([]byte{7}, 32), plan); err == nil {
		t.Fatal("wrong root resumed stage")
	}
	after, err := os.ReadFile(stage)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused resume changed stage", err)
	}
}

func TestVaultMigrationStageInputAndSourceBoundaries(t *testing.T) {
	_, source, doc, key, plan, _ := migrationStageFixture(t)
	for _, mutate := range []func(*vault.SlotFile){
		func(d *vault.SlotFile) { d.Sequence++ }, func(d *vault.SlotFile) { d.Initializing = true }, func(d *vault.SlotFile) { d.Encrypted = true }, func(d *vault.SlotFile) { d.Migration = &vault.LocalMigration{} }, func(d *vault.SlotFile) { d.Nodes = []vault.NodeHighWater{{}} }, func(d *vault.SlotFile) { d.FileID = "../escape" }, func(d *vault.SlotFile) { d.Slots = nil }, func(d *vault.SlotFile) { d.VaultID = uuid.NewString() },
	} {
		bad := doc
		mutate(&bad)
		if _, err := stageLegacyVaultDomains(context.Background(), source, "", bad, key, plan); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, path := range []string{"", "relative.db", t.TempDir(), filepath.Join(t.TempDir(), "missing.db")} {
		if _, err := stageLegacyVaultDomains(context.Background(), path, "", doc, key, plan); err != errVaultMigrationSource {
			t.Fatal(path, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stageLegacyVaultDomains(ctx, source, "", doc, key, plan); err != context.Canceled {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(source), []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err != errVaultMigrationSource {
		t.Fatal("vault reopened as legacy", err)
	}
	if err := equalLegacyVaultValue([]byte("a"))([]byte("b")); err != vault.ErrAuthentication {
		t.Fatal("readback mismatch accepted")
	}
}

func TestVaultMigrationStageLockCancellation(t *testing.T) {
	for _, lock := range []func(string, vault.SlotFile) string{
		func(s string, _ vault.SlotFile) string { return s + ".vault-migration.lock" },
		func(s string, _ vault.SlotFile) string { return tunnelConfigurationLockPath(s) },
		func(s string, _ vault.SlotFile) string { return credentialPrivateKeyLockPath(s) },
		func(s string, d vault.SlotFile) string { return s + ".migrating-" + d.FileID + ".vault.lock" },
	} {
		_, source, doc, key, plan, _ := migrationStageFixture(t)
		release, err := tryAcquireExclusiveFileLock(lock(source, doc))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		_, err = stageLegacyVaultDomains(ctx, source, "", doc, key, plan)
		cancel()
		release()
		if err == nil {
			t.Fatal("lock ignored")
		}
		if _, err := os.Lstat(vaultSlotPath(source + ".migrating-" + doc.FileID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("blocked importer wrote journal")
		}
		if _, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err != nil {
			t.Fatal("lock leaked after cancellation", err)
		}
	}
}

func TestVaultMigrationStageSourceHandleBinding(t *testing.T) {
	db, source := snapshotDatabase(t)
	other, _ := snapshotDatabase(t)
	canonical, info, err := canonicalLegacyVaultSource(source)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := verifyLegacyMigrationSource(resolverCaptureReader{ctx, db}, canonical, info); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationSource(resolverCaptureReader{ctx, other}, canonical, info); err != errVaultMigrationSource {
		t.Fatal("unrelated pool accepted", err)
	}
	_, wrong, err := canonicalLegacyVaultSource(filepath.Join(t.TempDir(), "missing"))
	if err == nil || wrong != nil {
		t.Fatal("missing source accepted")
	}
	otherInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationSource(resolverCaptureReader{ctx, db}, canonical, otherInfo); err != errVaultMigrationSource {
		t.Fatal("replaced source accepted", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationSource(resolverCaptureReader{ctx, db}, canonical, info); err != errVaultMigrationSource {
		t.Fatal("closed pool accepted", err)
	}
	missing := filepath.Join(t.TempDir(), "no-create #.db")
	opened, err := openLegacyMigrationSource(missing)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.PingContext(ctx); err == nil {
		t.Fatal("mode=rw created database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing database created")
	}
	escaped := filepath.Join(filepath.Dir(source), "source #.db")
	if err := os.Rename(source, escaped); err != nil {
		t.Fatal(err)
	}
	escapedDB, err := openLegacyMigrationSource(escaped)
	if err != nil {
		t.Fatal(err)
	}
	defer escapedDB.Close()
	if err := escapedDB.PingContext(ctx); err != nil {
		t.Fatal("URI interpreted filename as query/fragment", err)
	}
}

func TestVaultMigrationStageJournalRecoveryBoundaries(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		doc, key := localSlotFixture(t)
		doc.Nodes = nil
		path := filepath.Join(t.TempDir(), "stage.db")
		if err := os.WriteFile(path+suffix, []byte("unowned"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareLegacyVaultStage(path, key, doc, strings.Repeat("a", 64)); err != errVaultSlotConflict {
			t.Fatal("adopted unjournaled file", err)
		}
		data, err := os.ReadFile(path + suffix)
		if err != nil || string(data) != "unowned" {
			t.Fatal("destroyed unowned file", err)
		}
	}
	for _, mode := range []string{"bad-json", "regular-vault", "wrong-binding", "wrong-root", "sidecar-directory", "slot-lock"} {
		t.Run(mode, func(t *testing.T) {
			doc, key := localSlotFixture(t)
			doc.Nodes = nil
			path := filepath.Join(t.TempDir(), "stage.db")
			binding := strings.Repeat("a", 64)
			stored := doc
			stored.Migration = &vault.LocalMigration{Binding: binding, Phase: vault.MigrationCopying}
			switch mode {
			case "bad-json":
				if err := os.WriteFile(vaultSlotPath(path), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "regular-vault":
				stored.Migration = nil
			case "wrong-binding":
				stored.Migration.Binding = strings.Repeat("b", 64)
			case "wrong-root":
				stored.RootKeyID = uuid.NewString()
			}
			if mode != "bad-json" {
				if err := writeVaultSlotFile(path, key, stored, 0); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "sidecar-directory" {
				if err := os.Mkdir(path+"-wal", 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "slot-lock" {
				release, err := tryAcquireExclusiveFileLock(vaultSlotPath(path) + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			if _, err := prepareLegacyVaultStage(path, key, doc, binding); err == nil {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
}

func TestVaultMigrationStageMarkerCannotBeClearedOrRebound(t *testing.T) {
	doc, key := localSlotFixture(t)
	doc.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationCopying}
	path := filepath.Join(t.TempDir(), "stage.db")
	if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []*vault.LocalMigration{nil, {Binding: strings.Repeat("b", 64), Phase: vault.MigrationCopying}} {
		next := doc
		next.Sequence = 2
		next.Migration = marker
		if err := writeVaultSlotFile(path, key, next, 1); err != vault.ErrPolicy {
			t.Fatal("slot update published/rebound stage", err)
		}
	}
}
