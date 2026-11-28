package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationPublicationCheckpointRejectsStaleFloorsAndJournals(t *testing.T) {
	for _, mutation := range []string{"missing-journal", "bad-journal", "unfinished-sql", "counts", "node-version", "policy-version", "credential-version", "local-state-version", "missing-content-proof", "wrong-content-proof", "wrong-key", "wrong-source", "wrong-binding"} {
		t.Run(mutation, func(t *testing.T) {
			db, source, initial, key, plan, ids := migrationStageFixture(t)
			db.Close()
			root, _ := browserInventoryFixture(t)
			stage := source + ".migrating-" + initial.FileID
			if mutation == "missing-journal" {
				if _, err := stageLegacyVaultDomains(context.Background(), source, root, initial, key, plan); err != nil {
					t.Fatal(err)
				}
			} else if _, err := continueLegacyVaultMigration(context.Background(), source, root, initial, key, plan); err != nil {
				t.Fatal(err)
			}
			document, err := readVaultSlotFile(stage)
			if err != nil {
				t.Fatal(err)
			}
			binding := document.Migration.Binding
			owner := openNativeMigrationStage(t, stage, key)
			switch mutation {
			case "credential-version":
				credential, err := owner.ReadCredential(context.Background(), ids[0], 1)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.PutCredential(context.Background(), credential.CredentialMetadata, []localvault.SecretChange{{Field: "password", Value: []byte("changed native credential")}}, credential.RowVersion); err != nil {
					t.Fatal(err)
				}
			case "local-state-version":
				inventory, _, _, err := readLegacyRetirementInventory(context.Background(), owner, document, source)
				if err != nil || inventory.Browser == nil || inventory.Browser.RootState == nil {
					t.Fatal(err)
				}
				if _, err := owner.PutLocalState(context.Background(), migrationBrowserFileKind, inventory.Browser.RootState.ScopeID, []byte("changed native browser state"), 1); err != nil {
					t.Fatal(err)
				}
			case "bad-journal", "unfinished-sql":
				state, journal, err := readLegacyRetirementJournal(context.Background(), owner, document, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "bad-journal" {
					if _, err := owner.PutLocalState(context.Background(), migrationRetirementKind, document.VaultID, []byte("bad native journal header"), state.RowVersion); err != nil {
						t.Fatal(err)
					}
				} else {
					journal.SQL.Phase = "committed"
					if _, err := writeLegacyRetirementJournal(context.Background(), owner, document.VaultID, journal, state.RowVersion); err != nil {
						t.Fatal(err)
					}
				}
			case "counts", "node-version":
				node, err := owner.ReadNode(context.Background(), ids[1], 1)
				if err != nil {
					t.Fatal(err)
				}
				expected := node.RowVersion
				if mutation == "counts" {
					node.ID, expected = uuid.NewString(), 0
				}
				node.Name = "authenticated unexpected staging change"
				if _, err := owner.PutNode(context.Background(), node.NodeMetadata, nil, expected); err != nil {
					t.Fatal(err)
				}
			case "policy-version":
				policy, err := owner.ReadLocalPolicy(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				next := policy.Policy
				next.Sequence++
				if _, err := owner.PutLocalPolicy(context.Background(), next, policy.UserProfile, policy.Policy.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			owner.Close()
			switch mutation {
			case "missing-content-proof", "wrong-content-proof":
				if mutation == "missing-content-proof" {
					document.Migration.Snapshot.ContentAuthentication = nil
				} else {
					document.Migration.Snapshot.ContentAuthentication = bytes.Repeat([]byte{9}, 32)
				}
				raw, err := vault.EncodeSlotFile(key, document)
				if err != nil {
					t.Fatal(err)
				}
				document, err = vault.DecodeSlotFile(raw)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				key = bytes.Repeat([]byte{9}, 32)
			case "wrong-source":
				source += ".different"
			case "wrong-binding":
				binding += "x"
			}
			if _, err := readLegacyPublicationCheckpoint(context.Background(), stage, source, root, binding, document, key); err == nil {
				t.Fatal("incomplete/mutated checkpoint accepted")
			}
			if mutation == "node-version" || mutation == "policy-version" || mutation == "credential-version" || mutation == "local-state-version" {
				if _, err := publishLegacyVaultMigration(context.Background(), source, root, initial, key, plan); !errors.Is(err, vault.ErrAuthentication) {
					t.Fatal("publication reset original floor commitment", err)
				}
			}
		})
	}
}
