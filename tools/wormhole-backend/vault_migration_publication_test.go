package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationPublicationResumesEveryCutoverBoundary(t *testing.T) {
	for _, stopped := range []string{"intent", "source-retired", "database-published", "source-removed", "stage-removed", "slots-published", "complete"} {
		t.Run(stopped, func(t *testing.T) {
			db, source, document, key, plan, ids := migrationStageFixture(t)
			db.Close()
			root, _ := browserInventoryFixture(t)
			stage, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("cutover process interruption")
			var steps []string
			publication, err := publishLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
				steps = append(steps, step)
				if release, err := acquireWorkspaceOwnership(source, true); err == nil {
					release()
					t.Fatal("cutover lost workspace exclusion")
				}
				guard, err := readVaultSlotFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if step != "slots-published" {
					if guard.Migration == nil || guard.Migration.Phase != vault.MigrationPublishing {
						t.Fatal("ordinary unlock enabled before completed cutover")
					}
					if owner, err := openVaultFiles(context.Background(), source, guard, key); owner != nil || !errors.Is(err, vault.ErrPolicy) {
						t.Fatal("ordinary access to intermediate database", err)
					}
				}
				if step == stopped {
					return stop
				}
				return nil
			})
			if stopped != "complete" {
				if !errors.Is(err, stop) || publication != nil {
					t.Fatal("wrong cutover interruption", publication, err)
				}
				publication, err = publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			}
			if err != nil || publication == nil || len(steps) == 0 {
				t.Fatal("publication/resume failed", steps, err)
			}
			if release, err := acquireWorkspaceOwnership(source, true); err == nil {
				release()
				t.Fatal("published owner did not retain exclusion")
			}
			if err := publication.owner.WithNodeField(context.Background(), ids[2], "notes", 2, equalLegacyVaultValue([]byte("private stage note"))); err != nil {
				t.Fatal("cutover lost private data", err)
			}
			guard, err := readVaultSlotFile(source)
			if err != nil || guard.Migration != nil || guard.ProfileSequence == 0 || len(guard.Nodes) != 3 {
				t.Fatal("final slot checkpoint incomplete", err)
			}
			for _, id := range ids[2:] {
				found := false
				for _, mark := range guard.Nodes {
					if mark.NodeID == id {
						found = mark.Revision == 2
					}
				}
				if !found {
					t.Fatal("resolver-pinned node floor missing")
				}
			}
			if err := publication.close(); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{stage, vaultSlotPath(stage), source + ".retired-" + document.FileID} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("retired file survived", filepath.Base(path), err)
				}
			}
			raw, err := os.ReadFile(source)
			if err != nil || bytes.Contains(raw, []byte("private stage note")) {
				t.Fatal("published database contains legacy plaintext notes", err)
			}
			// A lost final acknowledgement may repeat after restart.
			publication, err = publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal("completed publication not idempotent", err)
			}
			if err := publication.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
