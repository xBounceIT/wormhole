package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

func TestVaultBitwardenIntentPhaseOwnership(t *testing.T) {
	for _, q := range []struct {
		phase, stage, final string
		referenced, success bool
	}{
		{"prepared", "", "", false, true}, {"prepared", "dir", "", false, false}, {"prepared", "", "dir", false, false},
		{"created", "dir", "", false, true}, {"created", "", "", false, true}, {"created", "dir", "dir", false, false}, {"created", "file", "", false, false}, {"created", "dir", "", true, false},
		{"published", "", "dir", false, true}, {"published", "", "dir", true, true}, {"published", "dir", "dir", false, false}, {"published", "", "file", false, false}, {"published", "", "", false, true},
		{"unknown", "", "", false, false},
	} {
		t.Run(q.phase+q.stage+q.final, func(t *testing.T) {
			base, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			id := uuid.NewString()
			stage := ".stage-" + id
			for name, kind := range map[string]string{stage: q.stage, id: q.final} {
				if kind == "dir" {
					if err = base.Mkdir(name, 0700); err != nil {
						t.Fatal(err)
					}
					if err = base.WriteFile(name+"/asset", []byte("fixture"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "file" {
					if err = base.WriteFile(name, []byte("unowned"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = reconcileVaultBitwardenIntent(context.Background(), base, localvault.BitwardenInstallationIntent{ID: id, Phase: q.phase}, q.referenced)
			if (err == nil) != q.success {
				t.Fatal(err)
			}
			if !q.success {
				for name, kind := range map[string]string{stage: q.stage, id: q.final} {
					if kind != "" {
						if _, err = base.Stat(name); err != nil {
							t.Fatal("uncertain ownership deleted", err)
						}
					}
				}
			} else {
				if _, err = base.Stat(stage); !os.IsNotExist(err) {
					t.Fatal("stage retained", err)
				}
				_, err = base.Stat(id)
				if q.referenced {
					if err != nil {
						t.Fatal("referenced final removed", err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatal("abandoned final retained", err)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if reconcileVaultBitwardenIntent(ctx, nil, localvault.BitwardenInstallationIntent{}, false) == nil {
		t.Fatal("invalid context/root")
	}
}

func TestVaultBitwardenIntentRecoveryThroughAuthorizedCleanupAndInstall(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	base, err := openVaultBitwardenInstallRoot(h.databasePath, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	adapter := &scopedVaultBitwardenInstaller{Owner: h.owner, namespace: vaultBitwardenDatabaseNamespace(h.databasePath)}
	id := uuid.NewString()
	stage := ".stage-" + id
	if err = adapter.beginIntent(ctx, id, 0); err != nil {
		t.Fatal(err)
	}
	if err = base.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err = adapter.advanceIntent(ctx, "created"); err != nil {
		t.Fatal(err)
	}
	if err = base.WriteFile(stage+"/interrupted", []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "bitwarden-cleanup", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "expectedRevision": "0"})); err != nil {
		t.Fatal(err)
	}
	if _, err = base.Stat(stage); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	// Another interrupted creation is reconciled before the next explicit import.
	id = uuid.NewString()
	stage = ".stage-" + id
	if err = adapter.beginIntent(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if err = base.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err = adapter.advanceIntent(ctx, "created"); err != nil {
		t.Fatal(err)
	}
	_, source := installerRoots(t)
	if _, err = h.Handle(ctx, "bitwarden-install-folder", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "1"})); err != nil {
		t.Fatal(err)
	}
	if _, err = base.Stat(stage); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "2"})); err != nil {
		t.Fatal("successful import unavailable", err)
	}
	if err = h.owner.ResolveBitwardenInstallationIntent(ctx, adapter.namespace, func(context.Context, localvault.BitwardenInstallationIntent, bool) error {
		t.Fatal("successful import left intent")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
