package localvault

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestWorkspaceImportCapturesPinnedAccountsAndStreamsFields(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	node, credential, plan := nodeMigrationFixture(t, o)
	plan, err := plan.Decide(plan.Fingerprint, []resolver.MigrationDecision{{NodeID: node.ID, ProtocolPath: "sftp", Choice: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, node.ID, plan, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	tunnel := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN"}
	settings := []byte(`{"password":"synthetic-vpn"}`)
	if _, err := o.PutTunnel(ctx, tunnel, settings, 0); err != nil {
		t.Fatal(err)
	}
	removed := draft()
	if _, err := o.PutCredential(ctx, removed, []SecretChange{{Field: "password", Value: []byte("removed")}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutCredential(ctx, removed, []SecretChange{{Field: "password", Remove: true}}, 1); err != nil {
		t.Fatal(err)
	}
	source, err := o.CaptureWorkspaceImport(ctx)
	if err != nil || len(source.Accounts) != 3 || len(source.Catalog.Credentials) != 2 || len(source.Catalog.Tunnels) != 1 {
		t.Fatal("source did not contain the complete import graph", err)
	}
	if _, err := json.Marshal(source); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("native identities were serializable", err)
	}
	for _, account := range source.Accounts {
		actual, err := o.ResolveConnectionPath(ctx, node.ID, "", account.ProtocolPath)
		if err != nil || actual.Account != account {
			t.Fatal("the source disagrees with the running resolver", account.ProtocolPath, err)
		}
	}
	same, err := o.CaptureWorkspaceImport(ctx)
	if err != nil || same.Fingerprint != source.Fingerprint {
		t.Fatal("unchanged source did not keep its fingerprint", err)
	}
	destinationNode, destinationCredential := uuid.NewString(), uuid.NewString()
	nodes, credentials := map[string]string{node.ID: destinationNode}, map[string]string{credential.ID: destinationCredential}
	var candidate []resolver.EffectiveCredentialSnapshot
	for _, account := range source.Accounts {
		account.NodeID, account.ResolverVersion = destinationNode, resolver.Version
		if account.SourceKind == "inline" {
			account.CredentialID = destinationNode
		} else {
			account.CredentialID = destinationCredential
		}
		if account.ProtocolPath == "ssh" {
			account.Username = "different-destination-identity"
		}
		candidate = append(candidate, account)
	}
	destination := uuid.NewString()
	destinationPins, err := source.ResolverMigration(destination, nodes, credentials, candidate)
	if err != nil || destinationPins.WorkspaceID != destination || len(destinationPins.Entries) != 1 {
		t.Fatal("could not compute destination-only resolver pins", err)
	}
	pin := destinationPins.Entries[0]
	if pin.Choice != "keep" || pin.Legacy.ProtocolPath != "ssh" || pin.Legacy.NodeID != destinationNode ||
		pin.Legacy.SourceKind != "saved" || pin.Legacy.CredentialID != destinationCredential || pin.Legacy.Username != "old-identity-never-write-clear" {
		t.Fatal("destination pin did not preserve the effective source identity")
	}
	if _, err := source.ResolverMigration(destination, nodes, nil, candidate); !errors.Is(err, resolver.ErrMigration) {
		t.Fatal("a missing credential mapping was accepted", err)
	}
	if _, err := source.ResolverMigration(destination, nodes, credentials, candidate[1:]); !errors.Is(err, resolver.ErrMigration) {
		t.Fatal("an omitted destination path was accepted", err)
	}
	want := map[vaultstore.SecretRef][]byte{
		{OwnerKind: "node", OwnerID: node.ID, Field: "inlinePassword"}:       []byte("candidate-secret"),
		{OwnerKind: "node", OwnerID: node.ID, Field: "notes"}:                []byte("private-notes"),
		{OwnerKind: "credential", OwnerID: credential.ID, Field: "password"}: []byte("pinned-secret"),
		{OwnerKind: "tunnel", OwnerID: tunnel.ID, Field: "settings"}:         settings,
	}
	var borrowed [][]byte
	err = o.WithWorkspaceImportSecrets(ctx, source.Fingerprint, func(ref vaultstore.SecretRef, value []byte) error {
		if expected, ok := want[ref]; !ok || !bytes.Equal(value, expected) {
			t.Fatal("unexpected transfer field", ref)
		}
		delete(want, ref)
		borrowed = append(borrowed, value)
		if o.mu.TryLock() {
			o.mu.Unlock()
			t.Fatal("the export lost the native owner between preflight and release")
		}
		return nil
	})
	if err != nil || len(want) != 0 {
		t.Fatal("the transfer omitted a live field", err)
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("borrowed plaintext survived the callback")
		}
	}
	if _, err := o.PutCredential(ctx, credential.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte("replacement")}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.WithWorkspaceImportSecrets(ctx, source.Fingerprint, func(vaultstore.SecretRef, []byte) error {
		t.Fatal("a stale preview released a field")
		return nil
	}); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("a changed secret did not invalidate the old preview", err)
	}
}

func TestWorkspaceImportRejectsInvalidSourcesAndStopsOnConsumerFailure(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	expectedPaths := make(map[string]int)
	for protocol, count := range map[int]int{0: 3, 1: 3, 3: 1, 4: 1, 5: 1, 6: 2, 7: 3} {
		draft := nodeDraft()
		draft.Protocol = &protocol
		if _, err := o.PutNode(ctx, draft, nil, 0); err != nil {
			t.Fatal(err)
		}
		expectedPaths[draft.ID] = count
	}
	folder := nodeDraft()
	folder.Kind = 0
	if _, err := o.PutNode(ctx, folder, []SecretChange{{Field: "notes", Value: []byte("private folder notes")}}, 0); err != nil {
		t.Fatal(err)
	}
	source, err := o.CaptureWorkspaceImport(ctx)
	if err != nil || len(source.Accounts) != 14 || len(source.Catalog.Nodes) != 8 {
		t.Fatal("protocol path inventory was incomplete", err)
	}
	for _, account := range source.Accounts {
		expectedPaths[account.NodeID]--
	}
	for _, remaining := range expectedPaths {
		if remaining != 0 {
			t.Fatal("one protocol had an incorrect number of account paths")
		}
	}
	sentinel := errors.New("destination stopped staging")
	var borrowed []byte
	err = o.WithWorkspaceImportSecrets(ctx, source.Fingerprint, func(_ vaultstore.SecretRef, value []byte) error {
		borrowed = value
		return sentinel
	})
	if err != sentinel || len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("destination failure retained plaintext or was lost", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.CaptureWorkspaceImport(cancelled); err != context.Canceled {
		t.Fatal("cancelled import continued", err)
	}
	if _, err := o.CaptureWorkspaceImport(nil); err != vault.ErrFormat {
		t.Fatal("nil context was accepted", err)
	}
	if err := o.WithWorkspaceImportSecrets(ctx, source.Fingerprint, nil); err != vault.ErrFormat {
		t.Fatal("nil field consumer was accepted", err)
	}
	if _, err := (WorkspaceImport{}).ResolverMigration(uuid.NewString(), nil, nil, nil); err != resolver.ErrMigration {
		t.Fatal("an uninitialised source could prepare resolver pins", err)
	}
	broken := nodeDraft()
	broken.Host = nil
	if _, err := o.PutNode(ctx, broken, nil, 0); err != nil {
		t.Fatal(err)
	}
	if partial, err := o.CaptureWorkspaceImport(ctx); err != resolver.ErrTarget || len(partial.Catalog.Nodes) != 0 {
		t.Fatal("unresolved source returned a partial preview", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.CaptureWorkspaceImport(ctx); err != vaultstore.ErrClosed {
		t.Fatal("the closed owner returned an import plan", err)
	}
}

type importSecretReader struct {
	catalogStore
	read func(context.Context, vaultstore.SecretRef) (vaultstore.Secret, error)
}

func (s importSecretReader) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	return s.read(ctx, ref)
}

func TestWorkspaceImportRejectsReplacedCiphertextAndRevision(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	credential := draft()
	if _, err := o.PutCredential(ctx, credential, []SecretChange{{Field: "password", Value: []byte("synthetic-import-field")}}, 0); err != nil {
		t.Fatal(err)
	}
	source, err := o.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := o.store.(catalogStore)
	defer func() { o.store = base }()
	for _, mode := range []string{"different revision", "ciphertext changed"} {
		t.Run(mode, func(t *testing.T) {
			o.store = importSecretReader{base, func(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
				stored, err := base.ReadSecret(ctx, ref)
				if err != nil {
					return vaultstore.Secret{}, err
				}
				if mode == "different revision" {
					stored.RowVersion++
				} else {
					stored.Envelope.Ciphertext[0] ^= 1
				}
				return stored, nil
			}}
			if err := o.WithWorkspaceImportSecrets(ctx, source.Fingerprint, func(vaultstore.SecretRef, []byte) error {
				t.Fatal("unverified field reached import staging")
				return nil
			}); !errors.Is(err, vault.ErrAuthentication) {
				t.Fatal("the altered record was not rejected", err)
			}
		})
	}
}

func TestWorkspaceImportRejectsAnAuthenticButMixedCatalog(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	profile := draft()
	old, err := o.PutCredential(ctx, profile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	node := nodeDraft()
	node.CredentialID = &profile.ID
	if _, err := o.PutNode(ctx, node, nil, 0); err != nil {
		t.Fatal(err)
	}
	profile.Username = "updated-account"
	if _, err := o.PutCredential(ctx, profile, nil, old.RowVersion); err != nil {
		t.Fatal(err)
	}
	base := o.store.(catalogStore)
	o.store = catalogTestStore{catalogStore: base, credentials: func(context.Context, string, int) ([]vaultstore.Credential, error) {
		return []vaultstore.Credential{old}, nil
	}}
	defer func() { o.store = base }()
	if partial, err := o.CaptureWorkspaceImport(ctx); err != vault.ErrAuthentication || len(partial.Accounts) != 0 {
		t.Fatal("an account could be resolved against a different signed revision than the upload", err)
	}
}

func TestWorkspaceImportKeepsSeparateRDPGatewayAccount(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	primary, gateway := draft(), draft()
	primary.Protocol, primary.Username = "rdp", "desktop-user"
	gateway.Protocol, gateway.Username = "rdp", "gateway-user"
	for _, metadata := range []vaultstore.CredentialMetadata{primary, gateway} {
		if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("synthetic")}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	node := nodeDraft()
	node.Protocol = nodePtr(1)
	node.CredentialID = &primary.ID
	node.RDPGatewayUsageMethod = nodePtr(1)
	node.RDPGatewayHostname = nodePtr("gateway.example")
	node.RDPGatewayCredentialID = &gateway.ID
	if _, err := o.PutNode(ctx, node, nil, 0); err != nil {
		t.Fatal(err)
	}
	source, err := o.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accounts := make(map[string]resolver.EffectiveCredentialSnapshot, len(source.Accounts))
	for _, account := range source.Accounts {
		accounts[account.ProtocolPath] = account
	}
	if accounts["rdp"].CredentialID != primary.ID || accounts["rdp"].Username != primary.Username ||
		accounts["rdp-gateway"].CredentialID != gateway.ID || accounts["rdp-gateway"].Username != gateway.Username {
		t.Fatal("the source merged the desktop and gateway identities")
	}
}

func TestWorkspaceImportPreviewRejectsSQLiteForeignKeyViolation(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := db.ExecContext(ctx, `PRAGMA foreign_keys=OFF;
UPDATE Keys SET CertSignerKeyId=?, CertSignerKeyVersion=1 WHERE KeyId=?;`, uuid.NewString(), opts.Identity.Root.ID)
	if err := errors.Join(writeErr, db.Close()); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if result, err := reopened.CaptureWorkspaceImport(ctx); err != vaultstore.ErrFormat || len(result.Catalog.Nodes) != 0 {
		t.Fatal("preview accepted a vault with a broken SQLite reference", err)
	}
}
