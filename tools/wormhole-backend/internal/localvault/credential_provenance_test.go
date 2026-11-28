package localvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestCredentialImportPreservesProvenanceAndAuthentication(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	opts.Create = false
	metadata := draft()
	created := "2024-03-01T12:34:56.1234567+01:00"
	c, err := o.ImportCredential(ctx, metadata, created, []SecretChange{{Field: "password", Value: []byte("provenance-fixture")}})
	if err != nil || c.CreatedAt != created {
		t.Fatal("import lost provenance", err)
	}
	if _, err := o.ImportCredential(ctx, metadata, "replacement", nil); err != vaultstore.ErrConflict {
		t.Fatal("import replaced existing credential", err)
	}
	metadata.Name = "renamed"
	c, err = o.PutCredential(ctx, metadata, nil, 1)
	if err != nil || c.CreatedAt != created {
		t.Fatal("edit changed provenance", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	c, err = o.ReadCredential(ctx, metadata.ID, 2)
	if err != nil || c.CreatedAt != created {
		t.Fatal("reopen lost provenance", err)
	}
	if err := o.DeleteCredential(ctx, metadata.ID, 2); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow("SELECT CreatedAt FROM CredentialProfiles WHERE Id=?", metadata.ID).Scan(&stored); err != nil || stored != created {
		t.Fatal("tombstone lost provenance", err)
	}
	if _, err := db.Exec("UPDATE CredentialProfiles SET CreatedAt='tampered'"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, err := o.ReadCredential(ctx, metadata.ID, 1); err != vault.ErrAuthentication {
		t.Fatal("unauthenticated provenance accepted", err)
	}
}

func TestCredentialCreationTimeAndImportErrors(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	start := time.Now().UTC()
	c, err := o.PutCredential(ctx, draft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedAt)
	if err != nil || created.Before(start) || created.After(time.Now().UTC()) {
		t.Fatal("new creation time missing", err)
	}
	for _, bad := range []string{strings.Repeat("x", 129), "a\x00b", string([]byte{255})} {
		m := draft()
		if _, err := o.ImportCredential(ctx, m, bad, nil); err != vaultstore.ErrFormat {
			t.Fatal("invalid provenance imported", err)
		}
		if _, err := o.ReadCredential(ctx, m.ID, 0); err != vaultstore.ErrMissing {
			t.Fatal("invalid import wrote a record", err)
		}
	}
	c, err = o.ImportCredential(ctx, draft(), "", nil)
	if err != nil || c.CreatedAt != "" {
		t.Fatal("unknown time invented", err)
	}
	c, err = o.PutCredential(ctx, c.CredentialMetadata, nil, 1)
	if err != nil || c.CreatedAt != "" {
		t.Fatal("edit invented unknown time", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ImportCredential(cancelled, draft(), "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled import continued", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportCredential(ctx, draft(), "", nil); err != vaultstore.ErrClosed {
		t.Fatal("closed owner imported", err)
	}
}

func TestCredentialProvenanceUpgradePreservesOldMAC(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	opts.Create = false
	c, err := o.ImportCredential(ctx, draft(), "", []SecretChange{{Field: "password", Value: []byte("old-vault-fixture")}})
	if err != nil {
		t.Fatal(err)
	}
	// Independent pre-v5 shape, without any CreatedAt field. Merely marshaling
	// the new type here would fail to detect accidental MAC-format changes.
	old := struct {
		Identity   vaultstore.Identity `json:"identity"`
		Credential struct {
			vaultstore.CredentialMetadata
			RowVersion uint64                       `json:"rowVersion"`
			Deleted    bool                         `json:"deleted"`
			Fields     []vaultstore.CredentialField `json:"fields"`
			Seal       []byte                       `json:"seal"`
		} `json:"credential"`
	}{Identity: opts.Identity}
	old.Credential.CredentialMetadata = c.CredentialMetadata
	old.Credential.RowVersion = c.RowVersion
	old.Credential.Fields = c.Fields
	body, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	subkey, err := vault.DeriveKey(key, []byte(opts.Identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(subkey)
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-credential\x00"))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), c.Seal) {
		t.Fatal("old MAC bytes changed")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE LocalState; ALTER TABLE CredentialProfiles DROP COLUMN CreatedAt; UPDATE WorkspaceMeta SET SchemaVersion=4;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	got, err := o.ReadCredential(ctx, c.ID, 1)
	if err != nil || got.CreatedAt != "" || !bytes.Equal(got.Seal, c.Seal) {
		t.Fatal("upgrade invalidated old credential", err)
	}
	if err := o.WithCredentialSecret(ctx, c.ID, "password", 1, func(value []byte) error {
		if string(value) != "old-vault-fixture" {
			t.Fatal("upgrade changed secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
