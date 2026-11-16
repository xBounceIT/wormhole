package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mremoteCredentialRequest(t *testing.T, nodes string) mremoteImportRequest {
	t.Helper()
	nodes = strings.ReplaceAll(nodes, "{secret}", encryptMRemoteFixture(t, "shared-secret", mremoteTestPassword))
	nodes = strings.ReplaceAll(nodes, "{other}", encryptMRemoteFixture(t, "other-secret", mremoteTestPassword))
	return mremoteImportRequest{
		Path:     writeMRemoteFixture(t, fmt.Sprintf(`<mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="%d" Protected="%s">%s</mrng:Connections>`, mremoteTestIterations, encryptMRemoteFixture(t, mremoteVerifier, mremoteTestPassword), nodes)),
		Password: mremoteTestPassword, PlanNonce: "11111111-1111-4111-8111-111111111111",
	}
}

func mremotePlanForTest(t *testing.T, path string, request mremoteImportRequest) mremotePlan {
	t.Helper()
	plan, err := buildMRemotePlan(context.Background(), path, request)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mremoteNodeCredential(t *testing.T, plan mremotePlan, name string) mremotePlannedCredential {
	t.Helper()
	for _, node := range plan.Nodes {
		if node.Name != name {
			continue
		}
		for _, credential := range plan.Credentials {
			if credential.ID == node.CredentialID.String {
				return credential
			}
		}
	}
	t.Fatalf("no new credential for %s", name)
	return mremotePlannedCredential{}
}

func TestMRemoteCredentialCanonicalSharingAndNames(t *testing.T) {
	request := mremoteCredentialRequest(t, `
<Node Type="Container" Name="Linux">
 <Node Type="Connection" Name="web01" Hostname="web01.example" Protocol="SSH2" Username=" alice " Domain="ignored" Password="{secret}"/>
 <Node Type="Container" Name="Nested"><Node Type="Connection" Name="web02" Protocol="SSH2" Username="alice" Password="{secret}"/></Node>
 <Node Type="Connection" Name="web03" Protocol="SSH2" Username="alice" Password="{secret}"/>
 <Node Type="Connection" Name="upper" Protocol="SSH2" Username="Alice" Password="{secret}"/>
</Node>
<Node Type="Container" Name="Windows">
 <Node Type="Connection" Name="dc01" Protocol="RDP" Username="ACME\alice" Password="{secret}"/>
 <Node Type="Connection" Name="dc02" Protocol="RDP" Username="alice" Domain="ACME" Password="{secret}"/>
 <Node Type="Connection" Name="dc03" Protocol="RDP" Username="ALICE" Domain="acme" Password="{secret}"/>
 <Node Type="Connection" Name="upn" Protocol="RDP" Username="alice@acme.com" Password="{secret}"/>
 <Node Type="Connection" Name="different-password" Protocol="RDP" Username="alice" Domain="ACME" Password="{other}"/>
</Node>
<Node Type="Container" Name="Lab"><Node Type="Connection" Name="vnc1" Protocol="VNC" Username="ignored" Password="{secret}"/><Node Type="Connection" Name="vnc2" Protocol="VNC" Domain="ignored" Password="{secret}"/></Node>
<Node Type="Container" Name="A"><Node Type="Connection" Name="a" Protocol="SSH2" Username="charlie" Password="{secret}"/></Node>
<Node Type="Container" Name="B"><Node Type="Connection" Name="b" Protocol="SSH2" Username="charlie" Password="{secret}"/></Node>`)
	path := newMRemoteTestDatabase(t)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 7 || plan.SharedCredentials != 4 || plan.SharedCredentialConnections != 10 {
		t.Fatalf("unexpected consolidation: credentials=%d shared=%d connections=%d", len(plan.Credentials), plan.SharedCredentials, plan.SharedCredentialConnections)
	}
	for _, test := range []struct{ node, name, username, domain string }{
		{"web01", "mremoteng-alice@Linux", "alice", ""},
		{"upper", "mremoteng-Alice@upper", "Alice", ""},
		{"dc01", "mremoteng-ACME-alice@Windows", "alice", "ACME"},
		{"vnc1", "mremoteng-Lab-vnc", "", ""},
		{"a", "mremoteng-charlie-ssh-shared", "charlie", ""},
	} {
		got := mremoteNodeCredential(t, plan, test.node)
		if got.Name != test.name || got.Username != test.username || got.Domain != test.domain {
			t.Errorf("%s: name=%s username=%s domain=%s", test.node, got.Name, got.Username, got.Domain)
		}
	}
	for _, pair := range [][2]string{{"web01", "web02"}, {"web01", "web03"}, {"dc01", "dc02"}, {"dc01", "dc03"}, {"vnc1", "vnc2"}, {"a", "b"}} {
		if mremoteNodeCredential(t, plan, pair[0]).ID != mremoteNodeCredential(t, plan, pair[1]).ID {
			t.Errorf("did not merge %v", pair)
		}
	}
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := mremotePlanToken(plan, request.PlanNonce)
	if err != nil || token != response.PlanToken {
		t.Fatal("analysis names are not deterministic")
	}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"shared-secret", "other-secret", mremoteTestPassword} {
		if strings.Contains(string(payload), secret) {
			t.Fatal("secret leaked into response")
		}
	}
}

func TestMRemoteCredentialInheritanceAndMixedFolderProtocols(t *testing.T) {
	request := mremoteCredentialRequest(t, `
<Node Type="Container" Name="Bob" Username="bob" Protocol="SSH2" Password="{secret}"><Node Type="Container" Name="Nested" InheritUsername="true" InheritPassword="true" InheritProtocol="true"><Node Type="Connection" Name="bob" Hostname="bob.example" InheritUsername="true" InheritPassword="true" InheritProtocol="true"/></Node></Node>
<Node Type="Container" Name="Erin" Username="erin"><Node Type="Connection" Name="erin" Hostname="erin.example" Protocol="SSH2" InheritUsername="true" Password="{secret}"/></Node>
<Node Type="Container" Name="Carol" Username="carol" Domain="ACME" Protocol="RDP"><Node Type="Connection" Name="carol" Hostname="carol.example" Protocol="RDP" InheritUsername="true" InheritDomain="true" Password="{secret}"/></Node>
<Node Type="Container" Name="Mixed" Username="dave" Domain="ACME" Protocol="RDP" Password="{secret}">
 <Node Type="Connection" Name="child-ssh" Hostname="ssh.example" Protocol="SSH2" InheritUsername="true" InheritPassword="true"/>
 <Node Type="Connection" Name="child-rdp" Hostname="rdp.example" Protocol="RDP" InheritUsername="true" InheritDomain="true" InheritPassword="true"/>
</Node>`)
	path := newMRemoteTestDatabase(t)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 5 {
		t.Fatalf("expected five distinct protocol identities, got %d", len(plan.Credentials))
	}
	for _, test := range []struct {
		name, user, domain string
		protocol           int64
	}{
		{"bob", "bob", "", 0}, {"erin", "erin", "", 0}, {"carol", "carol", "ACME", 1},
		{"child-ssh", "dave", "", 0}, {"child-rdp", "dave", "ACME", 1},
	} {
		got := mremoteNodeCredential(t, plan, test.name)
		if got.Username != test.user || got.Domain != test.domain || got.Protocol != test.protocol {
			t.Errorf("wrong inherited identity for %s", test.name)
		}
	}
	for _, node := range plan.Nodes {
		if node.Name == "Mixed" && node.CredentialID.Valid {
			t.Fatal("mixed folder retained an incompatible credential")
		}
		if node.Name == "Bob" && !node.CredentialID.Valid {
			t.Fatal("compatible folder lost its credential")
		}
		if node.Kind == workspaceNodeConnection && node.Username.Valid {
			t.Fatal("inherited node username must remain unset")
		}
	}
	installMRemoteSecretFixture(t)
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	if _, err := commitMRemoteImport(path, request); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, node := range plan.Nodes {
		if node.Kind != workspaceNodeConnection {
			continue
		}
		if node.Name == "carol" || node.Name == "child-rdp" {
			user, domain, err := resolveNodeRdpIdentity(db, node.ID)
			if err != nil || user != "" || domain != "" {
				t.Fatalf("RDP identity failed for %s: %q %q %v", node.Name, user, domain, err)
			}
			manager := vncManager{database: db, databasePath: path}
			profile, err := manager.resolveRdpProfile(node.ID, nil, false, "")
			if err != nil || profile.Username != mremoteNodeCredential(t, plan, node.Name).Username || profile.Domain != "ACME" || profile.Password != "shared-secret" {
				t.Fatalf("RDP connect profile failed for %s: %v", node.Name, err)
			}
		} else {
			target, err := loadSSHTarget(path, node.ID)
			if err != nil || target.username != mremoteNodeCredential(t, plan, node.Name).Username {
				t.Fatalf("SSH connect identity failed for %s: %v", node.Name, err)
			}
		}
	}
}

// Use the actual platform-protected store so the connect paths exercise the
// imported secrets as well as their profile references.
func installMRemoteSecretFixture(t *testing.T) {
	t.Helper()
	previousStore := credentialSecretStore
	type stored struct{ id, encoded, encoding string }
	var secrets []stored
	credentialSecretStore = func(id, ref, value string) (string, string, error) {
		encoded, encoding, err := storeCredentialSecret(id, ref, value)
		if err == nil {
			secrets = append(secrets, stored{id, encoded, encoding})
		}
		return encoded, encoding, err
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		for _, secret := range secrets {
			_ = deleteStoredCredentialSecret(secret.id, secret.encoded, secret.encoding)
		}
	})
}

func TestMRemoteCredentialReuseAndExplicitOptOut(t *testing.T) {
	for _, reuse := range []bool{true, false} {
		t.Run(fmt.Sprint(reuse), func(t *testing.T) {
			path := newMRemoteTestDatabase(t)
			installMRemoteSecretFixture(t)
			request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="server" Protocol="SSH2" Hostname="server.example" Username="alice" Password="{secret}"/>`)
			for iteration := 0; iteration < 2; iteration++ {
				if iteration == 1 {
					request.PlanNonce = "22222222-2222-4222-8222-222222222222"
					request.ReuseExisting = &reuse
				}
				input, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				if code := runBackendCLI([]string{"-database", path, "-electron-user-data", "native-user-data", "-operation", "mremote-import-analyze"}, bytes.NewReader(input), &stdout, &stderr); code != 0 {
					t.Fatalf("CLI analysis failed: %s", stderr.String())
				}
				var response mremoteImportPlanResponse
				if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				wantNew, wantReused := 1, 0
				if iteration == 1 && reuse {
					wantNew, wantReused = 0, 1
				}
				if response.Credentials != wantNew || response.CredentialsReused != wantReused {
					t.Fatalf("incorrect reuse counts: new=%d reused=%d", response.Credentials, response.CredentialsReused)
				}
				request.PlanToken = response.PlanToken
				manager := vncManager{databasePath: path, electronUserDataPath: "native-user-data"}
				rawResult, err := manager.runBackendOperation(context.Background(), backendCommand{
					Action: "mremote.import.commit", Path: request.Path, Password: request.Password,
					PlanNonce: request.PlanNonce, PlanToken: request.PlanToken, ReuseExisting: request.ReuseExisting,
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				result := rawResult.(mremoteImportResult)
				if result.CredentialsCreated != wantNew || result.CredentialsReused != wantReused {
					t.Fatal("commit differs from analysis")
				}
			}
			db, err := openDatabase(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var profiles, refs int
			if err := db.QueryRow(`SELECT COUNT(*) FROM CredentialProfiles`).Scan(&profiles); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(DISTINCT CredentialId) FROM Nodes`).Scan(&refs); err != nil {
				t.Fatal(err)
			}
			want := 2
			if reuse {
				want = 1
			}
			if profiles != want || refs != want {
				t.Fatalf("profiles=%d references=%d", profiles, refs)
			}
		})
	}
}

func TestMRemoteCredentialReuseCandidatesAndBufferClearing(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, candidate := range []struct {
		id, username, domain, created string
		protocol, kind, provider      int
	}{
		{"key", "alice", "", "0", 0, 1, 0}, {"bitwarden", "alice", "", "0", 0, 0, 1},
		{"wrong-user", "bob", "", "0", 0, 0, 0}, {"wrong-protocol", "alice", "", "0", 1, 0, 0},
		{"unreadable", "alice", "", "0", 0, 0, 0}, {"wrong-secret", "alice", "", "0", 0, 0, 0},
		{"newer", "alice", "", "2", 0, 0, 0}, {"oldest-b", "alice", "", "1", 0, 0, 0}, {"oldest-a", "alice", "", "1", 0, 0, 0},
	} {
		_, err := db.Exec(`INSERT INTO CredentialProfiles(Id, Name, Username, Domain, Protocol, Kind, SecretProvider, CreatedAt) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, candidate.id, "custom-"+candidate.id, candidate.username, candidate.domain, candidate.protocol, candidate.kind, candidate.provider, candidate.created)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) VALUES(?, 'opaque', 'test', 'now')`, candidate.id)
		if err != nil {
			t.Fatal(err)
		}
	}
	previous := mremoteUnprotectCredentialSecret
	t.Cleanup(func() { mremoteUnprotectCredentialSecret = previous })
	var buffers [][]byte
	var reads []string
	mremoteUnprotectCredentialSecret = func(id, _, _ string, userData ...string) ([]byte, error) {
		if len(userData) != 1 || userData[0] != "native-user-data" {
			t.Fatal("lost native user data path")
		}
		reads = append(reads, id)
		value := []byte("shared-secret")
		if id == "wrong-secret" {
			value = []byte("other-secret")
		}
		buffers = append(buffers, value)
		if id == "unreadable" {
			return value, errors.New("unavailable")
		}
		return value, nil
	}
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="server" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	request.ElectronUserDataPath = "native-user-data"
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 0 || len(plan.ReusedCredentials) != 1 || plan.ReusedCredentials[0].ID != "oldest-a" {
		t.Fatal("did not choose oldest matching local password")
	}
	if strings.Join(reads, ",") != "unreadable,wrong-secret,oldest-a" {
		t.Fatalf("unexpected secret reads: %v", reads)
	}
	for _, buffer := range buffers {
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("candidate plaintext buffer was not cleared")
			}
		}
	}
	request.ReuseExisting = new(bool)
	optOut := mremotePlanForTest(t, path, request)
	if len(optOut.Credentials) != 1 {
		t.Fatal("opt out still reused credentials")
	}
	// Even if there are no candidates, the option is bound to the token.
	plan = optOut
	plan.ReuseExisting = true
	a, _ := mremotePlanToken(plan, request.PlanNonce)
	b, _ := mremotePlanToken(optOut, request.PlanNonce)
	if a == b {
		t.Fatal("reuse option is not bound to the plan")
	}
}

func TestMRemoteCredentialNamingBoundaries(t *testing.T) {
	taken := map[string]struct{}{}
	first := allocateMRemoteCredentialName("alice", "server.example", "fallback", 0, taken)
	second := allocateMRemoteCredentialName("alice", "server.example", "fallback", 0, taken)
	if first != "mremoteng-alice@server.example" || second != first+"-2" {
		t.Fatal("single-use names or collision suffixes changed")
	}
	if got := allocateMRemoteCredentialName(strings.Repeat("a", 80), strings.Repeat("b", 80), "", 0, taken); len(got) != len("mremoteng-")+121 {
		t.Fatal("name parts exceed limit")
	}
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="v1" Protocol="VNC" Password="{secret}"/><Node Type="Connection" Name="v2" Protocol="VNC" Password="{secret}"/>`)
	plan := mremotePlanForTest(t, newMRemoteTestDatabase(t), request)
	if plan.Credentials[0].Name != "mremoteng-shared-vnc" {
		t.Fatal("cross-folder VNC name is not shared")
	}
}

func TestMRemoteCredentialReuseRejectsDriftAtomically(t *testing.T) {
	for _, change := range []string{
		`DELETE FROM CredentialProfiles`,
		`UPDATE CredentialProfiles SET Username='someone-else'`,
		`UPDATE CredentialProfiles SET Protocol=1`,
		`UPDATE CredentialProfiles SET Kind=1`,
		`UPDATE CredentialProfiles SET SecretProvider=1`,
		`UPDATE CredentialSecrets SET Secret='changed-opaque-value'`,
	} {
		for _, duringCommit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/during=%v", change, duringCommit), func(t *testing.T) {
				path := newMRemoteTestDatabase(t)
				installMRemoteSecretFixture(t)
				request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
				analyzed, err := analyzeMRemoteImport(path, request)
				if err != nil {
					t.Fatal(err)
				}
				request.PlanToken = analyzed.PlanToken
				if _, err := commitMRemoteImport(path, request); err != nil {
					t.Fatal(err)
				}
				request = mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/><Node Type="Connection" Name="new-vnc" Protocol="VNC" Password="{other}"/>`)
				request.PlanNonce = "22222222-2222-4222-8222-222222222222"
				analyzed, err = analyzeMRemoteImport(path, request)
				if err != nil {
					t.Fatal(err)
				}
				if analyzed.Credentials != 1 || analyzed.CredentialsReused != 1 {
					t.Fatal("expected one new and one reused credential")
				}
				request.PlanToken = analyzed.PlanToken
				mutate := func() {
					db, err := openDatabase(path, false)
					if err != nil {
						t.Fatal(err)
					}
					defer db.Close()
					if _, err := db.Exec(change); err != nil {
						t.Fatal(err)
					}
				}
				installUnjournaledCredentialSecretStoreTest(t)
				previousStore, previousDelete := credentialSecretStore, credentialSecretDelete
				pending := map[string]bool{}
				credentialSecretStore = func(id, _, _ string) (string, string, error) { pending[id] = true; return "opaque-" + id, "test", nil }
				credentialSecretDelete = func(id, _, _ string) error { delete(pending, id); return nil }
				t.Cleanup(func() { credentialSecretStore, credentialSecretDelete = previousStore, previousDelete })
				var progress operationProgress
				if duringCommit {
					changed := false
					progress = func(phase, _ string, _ int) {
						if phase == "protecting" && !changed {
							changed = true
							mutate()
						}
					}
				} else {
					mutate()
				}
				_, err = commitMRemoteImportContextWithProgress(context.Background(), path, request, progress)
				if err == nil || !strings.Contains(err.Error(), "analy") {
					t.Fatalf("expected stale-plan rejection, got %v", err)
				}
				if len(pending) != 0 {
					t.Fatal("rollback left an orphaned new secret")
				}
				db, err := openDatabase(path, true)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var nodes, newSecrets int
				if err := db.QueryRow(`SELECT COUNT(*) FROM Nodes`).Scan(&nodes); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`SELECT COUNT(*) FROM CredentialSecrets WHERE Encoding='test'`).Scan(&newSecrets); err != nil {
					t.Fatal(err)
				}
				if nodes != 1 || newSecrets != 0 {
					t.Fatal("stale import partially wrote to the workspace")
				}
			})
		}
	}
}

func TestMRemoteCredentialUnreadableCandidateCreatesNewAndKeepsName(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Hostname="server.example" Username="alice" Password="{secret}"/>`)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO CredentialProfiles(Id, Name, Username, Kind, Protocol, SecretProvider, CreatedAt) VALUES('unreadable', 'mremoteng-alice@server.example', 'alice', 0, 0, 0, 'now'); INSERT INTO CredentialSecrets(Id, Secret, Encoding, UpdatedAt) VALUES('unreadable', 'opaque', 'unsupported', 'now')`)
	if err != nil {
		t.Fatal(err)
	}
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 1 || len(plan.ReusedCredentials) != 0 || plan.Credentials[0].Name != "mremoteng-alice@server.example-2" {
		t.Fatal("unreadable candidate was not treated as no match")
	}
	var name string
	if err := db.QueryRow(`SELECT Name FROM CredentialProfiles WHERE Id='unreadable'`).Scan(&name); err != nil || name != "mremoteng-alice@server.example" {
		t.Fatal("existing credential was renamed")
	}
}

func TestMRemoteCredentialPasswordErrorsDoNotCreateProfiles(t *testing.T) {
	for _, secret := range []string{"", "not-base64", encryptMRemoteFixture(t, strings.Repeat("p", maxStoredCredentialPassword+1), mremoteTestPassword)} {
		request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="`+secret+`"/>`)
		plan := mremotePlanForTest(t, newMRemoteTestDatabase(t), request)
		if len(plan.Credentials) != 0 {
			t.Fatal("invalid password created a profile")
		}
		if secret != "" && len(plan.Warnings) != 1 {
			t.Fatal("invalid password must produce a bounded warning")
		}
	}
}

func TestMRemoteCredentialQualifiedRdpUsernameConnectsAfterConsolidation(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	installMRemoteSecretFixture(t)
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="qualified" Hostname="dc1.example" Protocol="RDP" Username="ACME\alice" Password="{secret}"/><Node Type="Connection" Name="separate" Hostname="dc2.example" Protocol="RDP" Username="alice" Domain="acme" Password="{secret}"/>`)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 1 {
		t.Fatal("RDP spellings did not consolidate")
	}
	response, err := analyzeMRemoteImport(path, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = response.PlanToken
	if _, err := commitMRemoteImport(path, request); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := vncManager{database: db, databasePath: path}
	for _, node := range plan.Nodes {
		profile, err := manager.resolveRdpProfile(node.ID, nil, false, "")
		if err != nil {
			t.Fatal(err)
		}
		if profile.Username != "alice" || !strings.EqualFold(profile.Domain, "ACME") || profile.Password != "shared-secret" {
			t.Fatalf("RDP identity was not split correctly for %s", node.Name)
		}
	}
}

func TestMRemoteCredentialReuseHandlesMissingTableAndCancellation(t *testing.T) {
	path := newMRemoteTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loadMRemoteReuseCandidates(ctx, db); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if _, err := db.Exec(`DROP TABLE CredentialSecrets`); err != nil {
		t.Fatal(err)
	}
	request := mremoteCredentialRequest(t, `<Node Type="Connection" Name="ssh" Protocol="SSH2" Username="alice" Password="{secret}"/>`)
	plan := mremotePlanForTest(t, path, request)
	if len(plan.Credentials) != 1 || len(plan.ReusedCredentials) != 0 {
		t.Fatal("workspace without a secret table did not create a new credential")
	}
}
