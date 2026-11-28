package localvault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type migrationReplayStore struct {
	integrityStore
	credential vaultstore.Credential
	secret     vaultstore.Secret
}

func TestMigrationIntegrityBindsSameVersionPrivatePayloads(t *testing.T) {
	for _, kind := range []string{"credential", "local-state"} {
		t.Run(kind, func(t *testing.T) {
			o, _, opts, _ := integrityFixture(t)
			defer o.Close()
			ctx := context.Background()
			base := o.store.(integrityStore)
			var ref vaultstore.SecretRef
			var replacement []byte
			if kind == "credential" {
				page, err := base.ListCredentials(ctx, "", 128)
				if err != nil || len(page) != 1 {
					t.Fatal(err)
				}
				ref = vaultstore.SecretRef{OwnerKind: kind, OwnerID: page[0].ID, Field: "password"}
				replacement = []byte("authentic secret from another unpublished copy")
			} else {
				state, err := o.ReadLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, 1)
				if err != nil {
					t.Fatal(err)
				}
				ref = vaultstore.SecretRef{OwnerKind: kind, OwnerID: state.ID, Field: state.Fields[0].Field}
				replacement = bytes.Repeat([]byte{8}, vault.MaxSecretBytes)
			}
			_, originalMAC, err := o.VerifyMigrationIntegrity(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Rebuilds use the same root/file identity and start private records at
			// version 1. Construct a second authentic value with identical public
			// metadata and version, as an older unpublished copy could contain.
			o.mu.Lock()
			alternative, err := o.prepareSecretWithReader(ctx, ref, replacement, 0, func(context.Context, vaultstore.SecretRef) (vaultstore.Secret, error) {
				return vaultstore.Secret{}, vaultstore.ErrMissing
			})
			o.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			o.store = integrityProbe{integrityStore: base, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
				if value.Ref == ref {
					return alternative, nil
				}
				return value, nil
			}}
			defer func() { o.store = base }()
			if _, err := o.VerifyIntegrity(ctx); err != nil {
				t.Fatal("same-version authentic replay fixture invalid", err)
			}
			if _, replayMAC, err := o.VerifyMigrationIntegrity(ctx); err != nil || bytes.Equal(originalMAC, replayMAC) {
				t.Fatal("private payload bytes missing from content proof", err)
			}
		})
	}
}

func (s migrationReplayStore) ListCredentials(ctx context.Context, after string, limit int) ([]vaultstore.Credential, error) {
	page, err := s.integrityStore.ListCredentials(ctx, after, limit)
	for i := range page {
		if page[i].ID == s.credential.ID {
			page[i] = s.credential
		}
	}
	return page, err
}

func (s migrationReplayStore) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	if ref == s.secret.Ref {
		return s.secret, nil
	}
	return s.integrityStore.ReadSecret(ctx, ref)
}

func TestMigrationIntegrityDetectsValidCredentialReplay(t *testing.T) {
	o, _, _, _ := integrityFixture(t)
	defer o.Close()
	ctx := context.Background()
	base := o.store.(integrityStore)
	credentials, err := base.ListCredentials(ctx, "", 128)
	if err != nil || len(credentials) != 1 {
		t.Fatal(err)
	}
	old := credentials[0]
	ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: old.ID, Field: "password"}
	secret, err := base.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	before, oldMAC, err := o.VerifyMigrationIntegrity(ctx)
	if err != nil || len(oldMAC) != 32 {
		t.Fatal(err)
	}
	if _, err := o.PutCredential(ctx, old.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte("password from newer copy")}}, old.RowVersion); err != nil {
		t.Fatal(err)
	}
	_, currentMAC, err := o.VerifyMigrationIntegrity(ctx)
	if err != nil || bytes.Equal(oldMAC, currentMAC) {
		t.Fatal("credential payload was not part of the checkpoint", err)
	}
	o.store = migrationReplayStore{integrityStore: base, credential: old, secret: secret}
	defer func() { o.store = base }()
	// Every replayed record is authentic. Counts and ordinary per-row integrity
	// alone cannot prove that the complete newest copy survived journal writes.
	if got, err := o.VerifyIntegrity(ctx); err != nil || got != before {
		t.Fatal("fixture did not reproduce an authentic older record", err)
	}
	_, replayMAC, err := o.VerifyMigrationIntegrity(ctx)
	if err != nil || !bytes.Equal(oldMAC, replayMAC) || bytes.Equal(currentMAC, replayMAC) {
		t.Fatal("frozen content checkpoint did not distinguish the replay", err)
	}
}

func TestMigrationIntegrityExcludesOnlyTheVerifiedRetirementJournal(t *testing.T) {
	o, _, opts, _ := integrityFixture(t)
	defer o.Close()
	ctx := context.Background()
	_, initial, err := o.VerifyMigrationIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := o.PutLocalState(ctx, vaultstore.LocalStateMigrationRetirement, opts.Identity.WorkspaceID, []byte("first intent"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2; step++ {
		counts, mac, err := o.VerifyMigrationIntegrity(ctx)
		if err != nil || counts.LocalStates != 2 || !bytes.Equal(initial, mac) {
			t.Fatal("journal invalidated immutable content proof", err)
		}
		if step == 0 {
			state, err = o.PutLocalState(ctx, state.Kind, state.ScopeID, []byte("completed durable intent with a different length"), state.RowVersion)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	base := o.store.(integrityStore)
	broken := errors.New("retirement journal ciphertext unavailable")
	o.store = integrityProbe{integrityStore: base, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
		if value.Ref.OwnerKind == "local-state" && value.Ref.OwnerID == state.ID {
			return vaultstore.Secret{}, broken
		}
		return value, nil
	}}
	if _, mac, err := o.VerifyMigrationIntegrity(ctx); err == nil || mac != nil {
		t.Fatal("excluded journal escaped integrity verification", err)
	}
	o.store = base
	if _, err := o.PutLocalState(ctx, "bitwarden-browser", opts.Identity.WorkspaceID, []byte("changed immutable browser state"), 1); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := o.VerifyMigrationIntegrity(ctx); err != nil || bytes.Equal(initial, changed) {
		t.Fatal("ordinary local state was excluded", err)
	}
}
