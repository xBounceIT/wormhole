package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func commitMRemoteFixtureForReview(t *testing.T, path string, request mremoteImportRequest) {
	t.Helper()
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	if _, err := commitMRemoteImport(path, request); err != nil {
		t.Fatal(err)
	}
}

func TestMRemoteExplicitPasswordBoundariesSurviveImport(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Container" Name="SSH" Protocol="SSH2" Username="alice" Password="{secret}">
<Node Type="Connection" Name="empty" Hostname="empty.example" Protocol="SSH2" InheritUsername="true" Password=""/>
<Node Type="Connection" Name="invalid" Hostname="invalid.example" Protocol="SSH2" InheritUsername="true" Password="invalid-ciphertext"/>
<Node Type="Container" Name="reset" Protocol="SSH2" InheritUsername="true" Password=""><Node Type="Connection" Name="nested" Hostname="nested.example" Protocol="SSH2" InheritUsername="true" InheritPassword="true"/></Node>
<Node Type="Connection" Name="inherited" Hostname="inherited.example" Protocol="SSH2" InheritUsername="true" InheritPassword="true"/>
</Node><Node Type="Container" Name="RDP" Protocol="RDP" Username="alice" Domain="ACME" Password="{secret}"><Node Type="Connection" Name="empty-rdp" Protocol="RDP" Hostname="rdp.example" InheritUsername="true" InheritDomain="true" Password=""/></Node>`)
	plan := mremotePlanForTest(t, path, request)
	commitMRemoteFixtureForReview(t, path, request)
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, node := range plan.Nodes {
		if node.Kind != workspaceNodeConnection {
			continue
		}
		if node.Name == "empty-rdp" {
			manager := vncManager{database: db, databasePath: path}
			profile, err := manager.resolveRdpProfile(node.ID, nil, false, "")
			if err != nil {
				t.Fatal(err)
			}
			if profile.Password != "" {
				t.Error("explicit empty RDP password inherited a folder secret")
			}
			continue
		}
		target, err := loadSSHTarget(path, node.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if node.Name == "inherited" {
			want = "shared-secret"
		}
		if target.password != want {
			t.Errorf("%s resolved the wrong password source", node.Name)
		}
	}
}

func TestMRemoteReuseReadsEachCandidateOnlyOnce(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="old" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	commitMRemoteFixtureForReview(t, path, request)
	previous := mremoteUnprotectCredentialSecret
	t.Cleanup(func() { mremoteUnprotectCredentialSecret = previous })
	reads := 0
	mremoteUnprotectCredentialSecret = func(id, encoded, encoding string, userData ...string) ([]byte, error) {
		reads++
		return previous(id, encoded, encoding, userData...)
	}
	request = mremoteCredentialRequest(t, `<Node Type="Connection" Name="a" Protocol="SSH2" Username="alice" Password="{other}"/><Node Type="Connection" Name="b" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 1 || len(plan.ReusedCredentials) != 1 {
		t.Fatal("incorrect matching result")
	}
	if reads != 1 {
		t.Fatalf("one candidate was decrypted %d times", reads)
	}
}

func TestMRemoteInterruptedSecretWriteCanBeRecovered(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	previousPrepare, previousStore, previousDelete := credentialSecretPrepare, credentialSecretStore, credentialSecretDelete
	t.Cleanup(func() {
		credentialSecretPrepare, credentialSecretStore, credentialSecretDelete = previousPrepare, previousStore, previousDelete
	})
	stored := map[string]bool{}
	credentialSecretPrepare = func(id string) (string, string, error) {
		return id + ":aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "test-keyring-v1", nil
	}
	credentialSecretStore = func(id, reference, _ string) (string, string, error) {
		if reference == "" {
			reference = id
		}
		stored[reference] = true
		panic("simulated process interruption after protected store write")
	}
	credentialSecretDelete = func(_, reference, _ string) error { delete(stored, reference); return nil }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("interruption was not reached")
			}
		}()
		_, _ = commitMRemoteImport(path, request)
	}()
	if len(stored) != 1 {
		t.Fatal("fixture did not reach external storage")
	}
	if err := recoverCredentialPrivateKeyOperations(path); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatal("interrupted import left an unrecoverable protected secret")
	}
	assertMRemoteDatabaseEmpty(t, path)
}

func TestMRemoteRdpCanonicalKeyUsesUnicodeCaseFolding(t *testing.T) {
	if !strings.EqualFold("ΟΣ", "ος") {
		t.Fatal("fixture is not case equivalent")
	}
	first, _, _ := mremoteCredentialIdentity(1, "ΟΣ", "ACME")
	second, _, _ := mremoteCredentialIdentity(1, "ος", "acme")
	if first != second {
		t.Fatal("case-equivalent RDP accounts have different canonical keys")
	}
	sshFirst, _, _ := mremoteCredentialIdentity(0, "ΟΣ", "")
	sshSecond, _, _ := mremoteCredentialIdentity(0, "ος", "")
	if sshFirst == sshSecond {
		t.Fatal("SSH account matching became case insensitive")
	}
}

func TestMRemoteReusedOnlyImportPreservesCancellation(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	commitMRemoteFixtureForReview(t, path, request)
	request.PlanNonce = "22222222-2222-4222-8222-222222222222"
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = commitMRemoteImportContextWithProgress(ctx, path, request, func(phase, _ string, _ int) {
		if phase == "protecting" {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation error: %v", err)
	}
}

func TestMRemoteReuseChoosesChronologicallyOldestCredential(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, row := range []struct{ id, created string }{
		{"older", "2026-11-16T09:00:00.1Z"},
		{"newer", "2026-11-16T09:00:00.11Z"},
		{"whole-second", "2026-11-16T09:00:00Z"},
	} {
		_, err := db.Exec(`INSERT INTO CredentialProfiles(Id, Name, Username, Kind, Protocol, SecretProvider, CreatedAt) VALUES(?, ?, 'alice', 0, 0, 0, ?); INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) VALUES(?, 'opaque', 'test', 'now')`, row.id, row.id, row.created, row.id)
		if err != nil {
			t.Fatal(err)
		}
	}
	previous := mremoteUnprotectCredentialSecret
	t.Cleanup(func() { mremoteUnprotectCredentialSecret = previous })
	mremoteUnprotectCredentialSecret = func(_, _, _ string, _ ...string) ([]byte, error) { return []byte("shared-secret"), nil }
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.ReusedCredentials) != 1 || plan.ReusedCredentials[0].ID != "whole-second" {
		t.Fatal("reused a newer credential because timestamp text order differs from time order")
	}
	if _, err := db.Exec(`DELETE FROM CredentialProfiles WHERE Id='whole-second'`); err != nil {
		t.Fatal(err)
	}
	plan = mremotePlanForTest(t, path, request)
	if len(plan.ReusedCredentials) != 1 || plan.ReusedCredentials[0].ID != "older" {
		t.Fatal("fractional timestamp prefixes sort in the wrong chronological order")
	}
}

func TestMRemoteReuseIgnoresAmbiguousLegacyIds(t *testing.T) {
	for _, duplicate := range []string{"secret", "profile"} {
		t.Run(duplicate, func(t *testing.T) {
			path := newMRemoteTestDatabase(t)
			db, err := openDatabase(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := "11111111-aaaa-4111-8111-111111111111"
			_, err = db.Exec(`INSERT INTO CredentialProfiles(Id, Name, Username, Kind, Protocol, SecretProvider, CreatedAt) VALUES(?, 'local', 'alice', 0, 0, 0, 'now'); INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) VALUES(?, 'opaque', 'test', 'now')`, id, id)
			if err != nil {
				t.Fatal(err)
			}
			if duplicate == "secret" {
				_, err = db.Exec(`INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) VALUES(?, 'other-opaque', 'test', 'now')`, strings.ToUpper(id))
			} else {
				_, err = db.Exec(`INSERT INTO CredentialProfiles(Id, Name, Username, Kind, Protocol, SecretProvider, CreatedAt) VALUES(?, 'linked', 'mallory', 0, 0, 1, 'now')`, strings.ToUpper(id))
			}
			if err != nil {
				t.Fatal(err)
			}
			previous := mremoteUnprotectCredentialSecret
			t.Cleanup(func() { mremoteUnprotectCredentialSecret = previous })
			reads := 0
			mremoteUnprotectCredentialSecret = func(_, _, _ string, _ ...string) ([]byte, error) { reads++; return []byte("shared-secret"), nil }
			request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
			plan := mremotePlanForTest(t, path, request)
			if len(plan.Credentials) != 1 || len(plan.ReusedCredentials) != 0 || reads != 0 {
				t.Fatal("ambiguous case variants must not be reused or decrypted")
			}
		})
	}
}

func TestMRemoteCancellationBeforeCommitRollsBackLastWrite(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = commitMRemoteImportContextWithProgress(ctx, path, request, func(phase, _ string, percent int) {
		if phase == "committing" && percent == 95 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("final write ignored cancellation before commit: %v", err)
	}
	assertMRemoteDatabaseEmpty(t, path)
}

func TestMRemoteReuseRejectsAmbiguousIdsAddedDuringCommit(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	commitMRemoteFixtureForReview(t, path, request)
	request.PlanNonce = "22222222-2222-4222-8222-222222222222"
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	added := false
	_, err = commitMRemoteImportContextWithProgress(context.Background(), path, request, func(phase, _ string, _ int) {
		if phase != "protecting" || added {
			return
		}
		added = true
		db, err := openDatabase(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = db.Exec(`INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) SELECT upper(Id), 'other-opaque', Encoding, UpdatedAt FROM CredentialSecrets`)
		if err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "analy") {
		t.Fatalf("ambiguous credential committed: %v", err)
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var nodes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM Nodes`).Scan(&nodes); err != nil || nodes != 1 {
		t.Fatal("stale import partially wrote nodes")
	}
}

func TestMRemoteExplicitEmptyIdentityDoesNotInheritWithoutPassword(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	request := mremoteCredentialRequest(t, `<Node Type="Container" Name="Parent" Username="alice" Domain="ACME">
<Node Type="Connection" Name="ssh-empty" Protocol="SSH2" Hostname="ssh.example" Username="" Password=""/>
<Node Type="Connection" Name="ssh-inherited" Protocol="SSH2" Hostname="ssh.example" InheritUsername="true" Password=""/>
<Node Type="Connection" Name="rdp-empty" Protocol="RDP" Hostname="rdp.example" Username="" Domain="" Password=""/>
</Node>`)
	plan := mremotePlanForTest(t, path, request)
	commitMRemoteFixtureForReview(t, path, request)
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, node := range plan.Nodes {
		if node.Kind != workspaceNodeConnection {
			continue
		}
		if node.Name == "rdp-empty" {
			user, domain, err := resolveNodeRdpIdentity(db, node.ID)
			if err != nil || user != "" || domain != "" {
				t.Error("explicit empty RDP identity inherited a parent account")
			}
		} else {
			target, err := loadSSHTarget(path, node.ID)
			if node.Name == "ssh-empty" {
				if err == nil || !strings.Contains(err.Error(), "no username") {
					t.Error("explicit empty SSH identity must require a username")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if node.Name == "ssh-inherited" {
				want = "alice"
			}
			if target.username != want {
				t.Errorf("%s resolved the wrong identity", node.Name)
			}
		}
	}
}
