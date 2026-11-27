package main

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
)

func TestResolverCaptureBaselineCoherentWithConcurrentEdit(t *testing.T) {
	db, path, _, _ := shadowFixture(t)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	reader := resolverCaptureReader{context.Background(), tx}
	old, err := readLegacyResolverSnapshots(reader)
	if err != nil || len(old) != 3 {
		t.Fatal(err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`UPDATE CredentialProfiles SET Username='concurrent-edit';`); err != nil {
		t.Fatal(err)
	}
	differences, err := compareCapturedResolverSnapshots(reader, old)
	if err != nil || len(differences) != 0 {
		t.Fatal("edit between legacy/candidate reads produced false drift", differences, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	baseline, err := captureLegacyResolverBaseline(context.Background(), db)
	if err != nil || len(baseline.Snapshots) != 3 || len(baseline.Differences) != 0 || baseline.Snapshots[0].Username != "concurrent-edit" {
		t.Fatal("next snapshot missed committed edit", baseline, err)
	}
}

func TestResolverCaptureBaselineRejectsUnavailableCandidate(t *testing.T) {
	db, _, _, _ := shadowFixture(t)
	// The legacy paths can select an account with this historical display name;
	// the candidate rejects it. Capture success must not imply equivalence.
	if _, err := db.Exec(`UPDATE Nodes SET Name=?;`, "legacy\nname"); err != nil {
		t.Fatal(err)
	}
	if old, err := captureLegacyResolverSnapshots(context.Background(), db); err != nil || len(old) != 3 {
		t.Fatal("fixture did not exercise candidate-only rejection", err)
	}
	if baseline, err := captureLegacyResolverBaseline(context.Background(), db); err != errResolverSnapshot || !reflect.DeepEqual(baseline, legacyResolverBaseline{}) {
		t.Fatal("unavailable candidate certified", baseline, err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Name='valid',Protocol=6; UPDATE CredentialProfiles SET Protocol=6,SecretProvider=1;`); err != nil {
		t.Fatal(err)
	}
	if old, err := captureLegacyResolverSnapshots(context.Background(), db); err != nil || len(old) != 2 {
		t.Fatal(err)
	}
	if baseline, err := captureLegacyResolverBaseline(context.Background(), db); err != errResolverSnapshot || !reflect.DeepEqual(baseline, legacyResolverBaseline{}) {
		t.Fatal("dynamic provider treated as equivalence", baseline, err)
	}
}

func TestResolverCaptureBaselineEmptyAndUnavailableStorage(t *testing.T) {
	db, _ := snapshotDatabase(t)
	baseline, err := captureLegacyResolverBaseline(context.Background(), db)
	if err != nil || baseline.Snapshots == nil || baseline.Differences == nil || len(baseline.Snapshots) != 0 || len(baseline.Differences) != 0 {
		t.Fatal(baseline, err)
	}
	if _, err := db.Exec(`DROP TABLE Nodes;`); err != nil {
		t.Fatal(err)
	}
	if baseline, err := captureLegacyResolverBaseline(context.Background(), db); err != errResolverSnapshot || !reflect.DeepEqual(baseline, legacyResolverBaseline{}) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureLegacyResolverBaseline(ctx, db); err != errResolverSnapshot {
		t.Fatal(err)
	}
	if _, err := captureLegacyResolverBaseline(context.Background(), nil); err != errResolverSnapshot {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLegacyResolverBaseline(context.Background(), db); err != errResolverSnapshot {
		t.Fatal(err)
	}
}

func TestResolverCaptureBaselineDiscardsEarlierDifferencesOnLateFailure(t *testing.T) {
	db, _, _, _ := shadowFixture(t)
	if _, err := db.Exec(`UPDATE Nodes SET Protocol=6; UPDATE CredentialProfiles SET Protocol=6,Username=NULL;`); err != nil {
		t.Fatal(err)
	}
	// Legacy VNC has no stored-secret row and selects none. The candidate chooses
	// the metadata reference: this must become a preserved migration choice.
	baseline, err := captureLegacyResolverBaseline(context.Background(), db)
	if err != nil || len(baseline.Differences) != 1 {
		t.Fatal("missing-secret choice drift not detected", baseline, err)
	}
	d := baseline.Differences[0]
	if d.ProtocolPath != "vnc" || !d.CredentialChanged || !d.SourceChanged || d.UsernameChanged || d.DomainChanged {
		t.Fatal("unexpected drift", d)
	}
	if _, err := db.Exec(`INSERT INTO Nodes(Id,Name,Kind,Protocol,Host,CreatedAt,UpdatedAt) VALUES('ffffffff-ffff-ffff-ffff-ffffffffffff',?,1,4,'web.example','fixture','fixture');`, "bad\nname"); err != nil {
		t.Fatal(err)
	}
	baseline, err = captureLegacyResolverBaseline(context.Background(), db)
	if err != errResolverSnapshot || !reflect.DeepEqual(baseline, legacyResolverBaseline{}) {
		t.Fatal("partial comparison leaked on later candidate failure", baseline, err)
	}
}
