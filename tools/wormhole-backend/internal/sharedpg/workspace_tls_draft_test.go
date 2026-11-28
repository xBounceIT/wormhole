package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceTLSAuthorityCarriesIntoOfflineRecovery(t *testing.T) {
	ctx := context.Background()
	scope := WorkspaceBootstrapScope{uuid.New(), "testscope", sha256.Sum256([]byte("protected deployment path"))}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := serverRequest(t, key, nil)
	now := time.Now().Truncate(time.Second)
	hosts := []string{"db.example.test", "127.0.0.1"}
	password := []byte("synthetic-authority-password")
	ask := bytes.Repeat([]byte{54}, 32)
	draft, err := PrepareWorkspaceTLS(ctx, scope, "DB.example.test", hosts, csr, password, ask, now)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(draft)
	if err != nil || bytes.Contains(stored, password) {
		t.Fatal("invalid staged authority", err)
	}
	var resumed WorkspaceTLSDraft
	if err := json.Unmarshal(stored, &resumed); err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(resumed.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	leaf, _ := pem.Decode([]byte(resumed.ServerPEM))
	server, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil || !key.PublicKey.Equal(server.PublicKey) {
		t.Fatal("server certificate used a different key", err)
	}
	for _, host := range hosts {
		if _, err := server.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, CurrentTime: now}); err != nil {
			t.Fatal("approved name did not verify", err)
		}
	}
	other := scope
	other.PlanDigest[0] ^= 1
	for _, attempt := range []struct {
		scope WorkspaceBootstrapScope
		p, a  []byte
	}{
		{scope, []byte("wrong"), ask},
		{scope, password, nil},
		{scope, password, bytes.Repeat([]byte{53}, 32)},
		{other, password, ask},
	} {
		if org, err := resumed.open(ctx, attempt.scope, attempt.p, attempt.a); org != nil || err == nil {
			t.Fatal("unrelated factors or deployment opened the authority", err)
		}
	}
	tampered := resumed
	tampered.ServerPEM += "\n"
	if org, err := tampered.open(ctx, scope, password, ask); org != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("modified leaf escaped draft authentication", err)
	}

	org, err := resumed.open(ctx, scope, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer org.keys.Wipe()
	if bytes.Contains(stored, org.keys.EncryptionPrivate) || bytes.Contains(stored, org.keys.SigningSeed) {
		t.Fatal("organisation keys appeared unencrypted in the draft")
	}
	endpoint := Endpoint{Host: hosts[0], Port: 5432}
	unrelated, _ := pem.Decode(testCA(t))
	if _, _, err := prepareWorkspaceBootstrap(scope.WorkspaceID, scope.RoleTag, Settings{Database: "vault", Endpoints: []Endpoint{endpoint}, Profile: vault.Standard}, [][]byte{unrelated.Bytes}, "alice", true, now, org); !errors.Is(err, ErrServerCertificate) {
		t.Fatal("bootstrap accepted an unrelated verified root", err)
	}
	bootstrap, factors, err := prepareWorkspaceBootstrap(scope.WorkspaceID, scope.RoleTag, Settings{Database: "vault", Endpoints: []Endpoint{endpoint}, Profile: vault.Standard}, [][]byte{issuer.Raw}, "alice", true, now, org)
	if err != nil {
		t.Fatal(err)
	}
	defer factors.wipe()
	trust, err := bootstrap.invitation.AuthenticatedTLSBundle(bootstrap.organisation.Signing, bootstrap.recovery.Signing)
	if err != nil || !slices.Equal(trust.bundle.Hosts, []string{"127.0.0.1", "db.example.test"}) {
		t.Fatal("signed TLS bundle did not include the exact approved names", err)
	}
	checkpoint, err := newWorkspaceBootstrapCheckpoint(ctx, scope, bootstrap, factors, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Close()
	raw, err := checkpoint.Seal()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWorkspaceBootstrapCheckpoint(ctx, scope, raw, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kit, _, _, err := reopened.PrepareRecovery(recipient.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	code, err := vault.FormatRecoveryKey(factors.recoveryKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	recovered, err := OpenWorkspaceRecoveryKit(scope.WorkspaceID, kit, code)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Wipe()
	var record workspaceRecoveryKit
	if err := json.Unmarshal(kit, &record); err != nil || record.Version != 2 || record.CA == nil || !bytes.Equal(record.CA.Certificate, issuer.Raw) {
		t.Fatal("offline kit did not retain the issued CA", err)
	}
	ca := WrappedWorkspaceCA{CertificateDER: record.CA.Certificate, KeyCopy: record.CA.Key.Copy}
	if _, err := ca.IssueServerCertificate(record.CA.Key.binding(org.binding), recovered.EncryptionPrivate, record.Public.Signing, csr, hosts, now, time.Hour); err != nil {
		t.Fatal("recovered organisation could not use the wrapped server CA", err)
	}
	record.CA.Certificate = unrelated.Bytes
	modified, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := OpenWorkspaceRecoveryKit(scope.WorkspaceID, modified, code); keys != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("offline kit accepted a substituted certificate", err)
	}
}

func TestWorkspaceTLSRejectsUnapprovedRequest(t *testing.T) {
	scope := WorkspaceBootstrapScope{uuid.New(), "testscope", sha256.Sum256([]byte("protected deployment path"))}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := serverRequest(t, key, nil)
	for _, tc := range []struct {
		endpoint string
		hosts    []string
		csr      []byte
	}{
		{"outside.example", []string{"db.example.test", "127.0.0.1"}, csr},
		{"db.example.test", []string{"db.example.test"}, csr},
		{"db.example.test", []string{"db.example.test", "DB.example.test"}, csr},
		{"db.example.test", []string{"db.example.test", "127.0.0.1"}, []byte("invalid request")},
	} {
		if draft, err := PrepareWorkspaceTLS(context.Background(), scope, tc.endpoint, tc.hosts, tc.csr, []byte("synthetic"), nil, time.Now()); draft != nil || !errors.Is(err, ErrServerCertificate) {
			t.Fatal("unapproved request issued a certificate", err)
		}
	}
}

func TestWorkspaceTLSBootstrapRequiresExactIssuedLeaf(t *testing.T) {
	settings, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	path := postgresFixtureDataDirectory(t, ctx, conn)
	csr := postgresFixtureCSR(t, path)
	scope := WorkspaceBootstrapScope{uuid.New(), "testscope", sha256.Sum256([]byte("protected deployment path"))}
	password := []byte("synthetic-authority-password")
	hosts := []string{"db.example.test", settings.Endpoints[0].Host}
	now := time.Now()
	draft, err := PrepareWorkspaceTLS(ctx, scope, settings.Endpoints[0].Host, hosts, csr, password, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	org, err := draft.open(ctx, scope, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer org.keys.Wipe()
	wrapped := WrappedWorkspaceCA{CertificateDER: draft.Certificate, KeyCopy: draft.CA.Copy}
	alternate, err := wrapped.IssueServerCertificate(draft.CA.binding(org.binding), org.keys.EncryptionPrivate, draft.Public.Signing, csr, hosts, now, time.Hour)
	if err != nil || bytes.Equal(alternate, []byte(draft.ServerPEM)) {
		t.Fatal("fixture could not issue a different leaf to the same server key", err)
	}
	if err := os.WriteFile(filepath.Join(path, "server.crt"), alternate, 0600); err != nil {
		t.Fatal("fixture leaf write failed")
	}
	settings.CAPEM = draft.CAPEM()
	reloadPostgresFixtureTLS(t, ctx, conn, settings, secret)
	pinned, err := PinDeploymentServerCertificate(settings, draft.ServerPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckSchemaDeployment(ctx, pinned, secret, scope.RoleTag, scope.WorkspaceID.String()); !errors.Is(err, ErrConnection) {
		t.Fatal("Check deployment accepted a different certificate from the same CA", err)
	}
	// The alternate leaf passes CA and hostname verification. Bootstrap must
	// still refuse it before querying deployment identity or sending credentials.
	if _, _, err := prepareWorkspaceBootstrapFromDeployment(ctx, settings, secret, scope.WorkspaceID, scope.RoleTag, "alice", vault.Default, false, org); !errors.Is(err, ErrConnection) {
		t.Fatal("bootstrap accepted a different leaf from the same CA", err)
	}
}
