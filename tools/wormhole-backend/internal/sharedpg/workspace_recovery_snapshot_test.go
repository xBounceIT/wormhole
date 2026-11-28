package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkWorkspaceRecoverySnapshot(t *testing.T, ctx context.Context, session *Session, master *AccountMaster, material *UnverifiedAccountKeys, state TrustState, tls *VerifiedTLSBundle, restore func([]byte), checks []joinedAdministratorCheck) error {
	t.Helper()
	account, err := state.AccountTrust()
	if err != nil {
		return err
	}
	return master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		user, err := vault.OpenEnrolledUserKeys(secret, material.Binding, material.Envelope, *material.EnrollmentCertificate, *state.Account, account, material.EnrollmentCertificate.Manifest.Revision)
		if err != nil {
			return err
		}
		defer user.Wipe()
		for range 2 {
			stored, err := session.EnsureAccountRecovery(ctx, state, user)
			if err != nil || !stored {
				t.Fatalf("current account recovery copies were not confirmed: %v", err)
			}
		}
		for _, check := range checks {
			check(session, state, tls, user)
		}
		snapshot, err := session.ReadWorkspaceRecoverySnapshot(ctx, state, tls, user.EncryptionPrivate, user.SigningSeed)
		if err != nil {
			return err
		}
		defer snapshot.Close()
		plaintext, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		summary, err := InspectWorkspaceRecoverySnapshot(plaintext)
		defer vault.Wipe(plaintext)
		if err != nil || summary.WorkspaceID != state.WorkspaceID || summary.Accounts < 1 || summary.Schema != deploy.SchemaVersion {
			t.Fatal("exported snapshot could not supply restore identity", err)
		}
		if restore != nil {
			restore(plaintext)
		}
		required := map[string]bool{"workspace_meta": false, "users": false, "keys": false, "key_copies": false,
			"user_enrollments": false, "user_key_states": false, "user_key_wraps": false, "boundaries": false,
			"boundary_grants": false, "boundary_manifests": false, "workspace_bootstrap": false}
		var rows [][][]byte
		var metaIndex int
		for index, row := range snapshot.Records {
			if _, want := required[row.Relation]; want {
				required[row.Relation] = true
			}
			if row.Relation == "workspace_meta" {
				metaIndex = index
			}
			if bytes.Contains(row.Body, []byte("synthetic-administrator-account")) {
				t.Fatal("plaintext account factor reached the snapshot")
			}
			rows = append(rows, [][]byte{[]byte(row.Relation), bytes.Clone(row.Body)})
		}
		for name, seen := range required {
			if !seen {
				t.Fatalf("missing persistent relation %s", name)
			}
		}
		for _, relation := range []string{"account_auth", "sessions", "devices", "invitation_logins", "device_admissions", "use_tickets"} {
			extra := append(append([][][]byte(nil), rows...), [][]byte{[]byte(relation), []byte("{}")})
			if bad, err := parseWorkspaceRecoverySnapshot(extra, state, tls); bad != nil || !errors.Is(err, ErrAdmissionResponse) {
				t.Fatal("snapshot allowed transient authentication data", err)
			}
		}
		updated := append([][][]byte(nil), rows...)
		updated[metaIndex] = [][]byte{[]byte("workspace_meta"), []byte("{}")}
		if bad, err := parseWorkspaceRecoverySnapshot(updated, state, tls); bad != nil || !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("snapshot accepted unpinned workspace identity", err)
		}
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(rows[metaIndex][1], &meta); err != nil {
			t.Fatal(err)
		}
		meta["signed_profile"] = json.RawMessage(`"\\x01"`)
		body, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		updated[metaIndex][1] = body
		if bad, err := parseWorkspaceRecoverySnapshot(updated, state, tls); bad != nil || !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("snapshot accepted a substituted profile", err)
		}
		if bad, err := parseWorkspaceRecoverySnapshot(append(rows, rows[metaIndex]), state, tls); bad != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("snapshot allowed duplicate metadata", err)
		}
		snapshot.Close()
		if len(snapshot.Records) != 0 {
			t.Fatal("closed snapshot retained records")
		}
		return nil
	})
}

func TestRecoverySnapshotRejectsIncompleteIdentity(t *testing.T) {
	session := NewSession()
	defer session.Close(context.Background())
	if result, err := session.ReadWorkspaceRecoverySnapshot(nil, TrustState{}, nil, nil, nil); result != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid export context accepted", err)
	}
	factor := make([]byte, 32)
	if result, err := session.ReadWorkspaceRecoverySnapshot(context.Background(), TrustState{}, nil, factor, factor); result != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("an untrusted workspace declared an export custodian", err)
	}
	if result, err := parseWorkspaceRecoverySnapshot(nil, TrustState{}, nil); result != nil || !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("an empty snapshot was accepted", err)
	}
}
