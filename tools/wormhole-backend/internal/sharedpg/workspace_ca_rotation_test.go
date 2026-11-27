package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func workspaceRotationFixture(t *testing.T, now time.Time) (*VerifiedTLSBundle, workspaceCAKeyCopy, vault.OrganisationRecoveryBinding, *vault.UserKeys) {
	t.Helper()
	original, pin, signer := tlsTrustFixture(t)
	keys := &vault.UserKeys{EncryptionPrivate: vault.NewRecoveryKey(), SigningSeed: signer.Seed()}
	t.Cleanup(keys.Wipe)
	organisation := vault.OrganisationRecoveryBinding{
		WorkspaceID: original.WorkspaceID, Signing: original.Signer,
		Encryption: vault.KeyRef{ID: uuid.New(), Version: 1},
	}
	key := workspaceCAKeyCopy{Key: vault.KeyRef{ID: uuid.New(), Version: 1}}
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateWorkspaceCA(key.binding(organisation), public.Encryption, keys.SigningSeed, original.Hosts, now, now.Add(workspaceCAValidity))
	if err != nil {
		t.Fatal(err)
	}
	key.Copy = ca.KeyCopy
	original.CAs = [][]byte{ca.CertificateDER}
	original.Revoked = []TLSRevocation{{IssuerSPKI: certificateDigest(ca.CertificateDER), Serial: "1"}}
	original, err = SignTLSTrustBundle(original, signer)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := VerifyTLSTrustBundle(original, pin)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, key, organisation, keys
}

func TestWorkspaceCARotationSignsConstrainedOverlap(t *testing.T) {
	current, old, org, keys := workspaceRotationFixture(t, serverCertNow)
	_, key := serverIssuer(t, nil)
	csr := serverRequest(t, key, nil)
	rotation, err := prepareWorkspaceCARotation(current, old, org, keys, csr, serverCertNow)
	if err != nil {
		t.Fatal(err)
	}
	overlap := rotation.overlap
	state := overlap.bundle.WorkspaceCA
	if overlap.bundle.FormatVersion != 2 || overlap.bundle.Sequence != current.bundle.Sequence+1 ||
		state.Key != rotation.key.Key || state.Key == old.Key || state.PreviousCA != certificateDigest(current.bundle.CAs[0]) ||
		len(overlap.bundle.CAs) != 2 || !bytes.Contains(overlap.PendingServerCertificate(), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("invalid overlap")
	}
	ca := workspaceRecoveryCA{Certificate: overlap.bundle.workspaceIssuer(), Key: rotation.key}
	if !ca.matches(keys.EncryptionPrivate, org, current.pin.Organisation) || current.bundle.FormatVersion != 1 || current.PendingServerCertificate() != nil ||
		overlap.bundle.Revoked[0] != current.bundle.Revoked[0] {
		t.Fatal("rotation changed an existing bundle, dropped a revocation, or stored the wrong CA copy")
	}
	raw := overlap.Encode()
	decoded, err := DecodeTLSTrustBundle(raw)
	if err != nil || !bytes.Equal(decoded.WorkspaceCA.ServerCertificate, state.ServerCertificate) {
		t.Fatal("could not resume with the signed pending certificate", err)
	}
	if _, err := overlap.Advance(current.bundle); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("pre-rotation metadata can be replayed", err)
	}
	for name, mutate := range map[string]func(*TLSTrustBundle){
		"format":        func(b *TLSTrustBundle) { b.FormatVersion = 1 },
		"key":           func(b *TLSTrustBundle) { b.WorkspaceCA.Key = vault.KeyRef{} },
		"root":          func(b *TLSTrustBundle) { b.WorkspaceCA.IssuingCA = "missing" },
		"previous":      func(b *TLSTrustBundle) { b.WorkspaceCA.PreviousCA = b.WorkspaceCA.IssuingCA },
		"stable":        func(b *TLSTrustBundle) { b.WorkspaceCA.PreviousCA = "" },
		"leaf":          func(b *TLSTrustBundle) { b.WorkspaceCA.ServerCertificate = b.workspaceIssuer() },
		"invalid leaf":  func(b *TLSTrustBundle) { b.WorkspaceCA.ServerCertificate = []byte("public malformed") },
		"large leaf":    func(b *TLSTrustBundle) { b.WorkspaceCA.ServerCertificate = make([]byte, 33*1024) },
		"missing hosts": func(b *TLSTrustBundle) { b.Hosts = []string{"127.0.0.1"} },
	} {
		t.Run(name, func(t *testing.T) {
			bundle, _ := DecodeTLSTrustBundle(raw)
			mutate(&bundle)
			if _, err := SignTLSTrustBundle(bundle, ed25519.NewKeyFromSeed(keys.SigningSeed)); err == nil {
				t.Fatal("unsupported rotation metadata signed")
			}
		})
	}
	invalid := current.bundle
	invalid.Sequence = math.MaxInt64 - 1
	saturated, err := current.signCAUpdate(invalid, keys.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []*VerifiedTLSBundle{nil, saturated, overlap} {
		if _, err := prepareWorkspaceCARotation(bundle, old, org, keys, csr, serverCertNow); !errors.Is(err, ErrWorkspaceCARotation) {
			t.Fatal("invalid starting state accepted", err)
		}
	}
	foreign := org
	foreign.WorkspaceID = uuid.New()
	if _, err := prepareWorkspaceCARotation(current, old, foreign, keys, csr, serverCertNow); !errors.Is(err, ErrWorkspaceCARotation) {
		t.Fatal("foreign organisation accepted", err)
	}
	old.Copy.Signature = bytes.Clone(old.Copy.Signature)
	old.Copy.Signature[0] ^= 1
	if _, err := prepareWorkspaceCARotation(current, old, org, keys, csr, serverCertNow); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("retired or corrupted source copy opened", err)
	}
	if _, err := current.signCAUpdate(invalid, nil); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("missing signing seed accepted", err)
	}
}

func TestPostgresWorkspaceCARotationRequiresExactLeaf(t *testing.T) {
	settings, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	admin, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(admin)
	data := postgresFixtureDataDirectory(t, ctx, admin)
	csr := postgresFixtureCSR(t, data)
	now := time.Now().Add(-time.Minute)
	current, old, org, keys := workspaceRotationFixture(t, now)
	before := WrappedWorkspaceCA{CertificateDER: current.bundle.workspaceIssuer(), KeyCopy: old.Copy}
	previousLeaf, err := before.IssueServerCertificate(old.binding(org), keys.EncryptionPrivate, current.pin.Organisation, csr, current.bundle.Hosts, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := prepareWorkspaceCARotation(current, old, org, keys, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	overlap := rotation.overlap
	installed := func(leaf []byte, bundle *VerifiedTLSBundle) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(data, "server.crt"), leaf, 0600); err != nil {
			t.Fatal(err)
		}
		base := settings
		base.CAPEM = nil
		prepared, err := bundle.transportSettings(base)
		if err != nil {
			t.Fatal(err)
		}
		pinned, err := PinDeploymentServerCertificate(prepared, string(leaf))
		if err != nil {
			t.Fatal(err)
		}
		reloadPostgresFixtureTLS(t, ctx, admin, pinned, secret)
	}
	settings.CAPEM = nil
	installed(previousLeaf, current)
	if _, err := overlap.retirePreviousWorkspaceCA(ctx, settings, keys.SigningSeed); !errors.Is(err, ErrWorkspaceCARotation) {
		t.Fatal("old server certificate allowed retirement", err)
	}
	// A different valid leaf signed by the new CA still fails the installation
	// check. Only the staged CSR response can authorize retirement.
	next := WrappedWorkspaceCA{CertificateDER: overlap.bundle.workspaceIssuer(), KeyCopy: rotation.key.Copy}
	otherLeaf, err := next.IssueServerCertificate(rotation.key.binding(org), keys.EncryptionPrivate, current.pin.Organisation, csr, current.bundle.Hosts, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	installed(otherLeaf, overlap)
	if _, err := overlap.retirePreviousWorkspaceCA(ctx, settings, keys.SigningSeed); !errors.Is(err, ErrWorkspaceCARotation) {
		t.Fatal("substituted leaf allowed retirement", err)
	}
	installed(overlap.PendingServerCertificate(), overlap)
	unsupported := settings
	unsupported.TLS = TLSOff
	if _, err := overlap.retirePreviousWorkspaceCA(ctx, unsupported, keys.SigningSeed); !errors.Is(err, ErrConfiguration) {
		t.Fatal("plain transport could authorize CA retirement", err)
	}
	noTLS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer noTLS.Close()
	go func() {
		conn, err := noTLS.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request [8]byte
		if _, err := io.ReadFull(conn, request[:]); err == nil {
			_, _ = conn.Write([]byte("N"))
		}
	}()
	fallback := settings
	fallback.Endpoints = append([]Endpoint{settings.Endpoints[0]}, Endpoint{Host: "127.0.0.1", Port: uint16(noTLS.Addr().(*net.TCPAddr).Port)})
	if _, err := overlap.retirePreviousWorkspaceCA(ctx, fallback, keys.SigningSeed); !errors.Is(err, ErrWorkspaceCARotation) {
		t.Fatal("unverified fallback allowed CA retirement", err)
	}
	retired, err := overlap.retirePreviousWorkspaceCA(ctx, settings, keys.SigningSeed)
	if err != nil || retired.bundle.Sequence != 3 || len(retired.bundle.CAs) != 1 || retired.PendingServerCertificate() != nil {
		t.Fatal("installed rotation was not finalized", err)
	}
	if _, err := retired.Advance(overlap.bundle); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("overlap reintroduced a retired root", err)
	}
	if _, err := prepareWorkspaceCARotation(retired, rotation.key, org, keys, csr, now); err != nil {
		t.Fatal("cannot rotate the new issuing CA again", err)
	}
	installed(previousLeaf, current)
	settings.TLSBundle = retired
	connection, err := Connect(ctx, settings, secret)
	if connection != nil {
		closeDeploymentConnection(connection)
	}
	if !errors.Is(err, ErrConnection) {
		t.Fatal("the retired CA still authenticated PostgreSQL", err)
	}
}
