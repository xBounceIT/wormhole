package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func recoveryInspectionSnapshot(t *testing.T) *sharedpg.WorkspaceRecoverySnapshot {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(priv)
	workspace, signer := uuid.New(), uuid.NewString()
	state := sharedpg.TrustState{WorkspaceID: workspace, SignerKeyID: signer, SignerKeyVersion: 1, PublicKey: pub}
	tls := sharedTLSFixture(t, new(sharedAdmissionOptions), state, priv, 1)
	policy, err := vault.SignPolicy(vault.Policy{FormatVersion: 1, WorkspaceID: workspace.String(), Sequence: 1,
		Profile: vault.Standard, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, signer, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := vault.EncodeSignedPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(map[string]any{
		"singleton": true, "workspace_id": workspace, "role_tag": "archive2", "schema_version": 49,
		"state": "ready", "require_tls": true, "tls_sequence": 1, "min_api": 1, "max_api": 1, "resolver_version": 1,
		"tls_bundle": "\\x" + hex.EncodeToString(tls.Encode()), "signed_profile": "\\x" + hex.EncodeToString(wire),
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := json.Marshal(map[string]any{"key_id": signer, "key_version": 1, "kind": "org-sign", "status": "active",
		"owner_id": nil, "suite": 1, "public_key": "\\x" + hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &sharedpg.WorkspaceRecoverySnapshot{FormatVersion: 1, WorkspaceID: workspace, Records: []sharedpg.WorkspaceRecoveryRecord{
		{Relation: "workspace_meta", Body: meta}, {Relation: "keys", Body: key},
	}}
	for _, name := range []string{"users", "user_enrollments", "user_key_states", "user_key_wraps", "key_copies", "boundaries", "boundary_manifests", "workspace_bootstrap", "nodes"} {
		snapshot.Records = append(snapshot.Records, sharedpg.WorkspaceRecoveryRecord{Relation: name, Body: json.RawMessage(`{}`)})
	}
	return snapshot
}

func TestSharedRecoveryInspectionUsesArchiveIdentityWithoutCreatingLocalWorkspace(t *testing.T) {
	snapshot := recoveryInspectionSnapshot(t)
	defer snapshot.Close()
	factor, err := vault.FormatRecoveryKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(factor)
	other, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(other)
	raw, err := encodeSharedRecoveryBackup(snapshot, factor, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	database := filepath.Join(dir, "workspace.db")
	source := filepath.Join(dir, "archive.json")
	destination := filepath.Join(dir, "deploy.sql")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: database}
	request := func(path, script string, password []byte) (sharedRecoveryInspectReply, error) {
		payload, err := json.Marshal(map[string]any{"path": path, "scriptPath": script, "password": password})
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(payload)
		reply, err := h.Handle(context.Background(), "shared-recovery-inspect", payload)
		var result sharedRecoveryInspectReply
		if err == nil && json.Unmarshal(reply, &result) != nil {
			t.Fatal("malformed inspection reply")
		}
		return result, err
	}
	if reply, err := request(source, "", factor); err != nil || reply.Status != "ready" || reply.Summary == nil ||
		reply.Summary.RoleTag != "archive2" || reply.Summary.WorkspaceID != snapshot.WorkspaceID ||
		reply.Summary.Accounts != 1 || reply.Summary.Nodes != 1 || reply.Summary.Profile != vault.Standard {
		t.Fatal("archive identity did not reach restore", err)
	}
	for _, rejection := range []struct {
		path     string
		password []byte
		status   string
	}{
		{source, bytes.Repeat([]byte{'x'}, 76), "invalid-password"},
		{source, other, "invalid-password"},
		{filepath.Join(dir, "missing.json"), factor, "invalid-backup"},
	} {
		if result, err := request(rejection.path, destination, rejection.password); err != nil ||
			result.Status != rejection.status || result.Summary != nil {
			t.Fatal("invalid archive inspection succeeded", err)
		}
		if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed inspection published SQL")
		}
	}
	if _, err := request("archive.json", destination, factor); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("relative picker path accepted", err)
	}
	if _, err := request(source, source, factor); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("source accepted as deployment destination", err)
	}
	numberArray := make([]uint16, len(factor))
	for i, value := range factor {
		numberArray[i] = uint16(value)
	}
	unsafeWire, err := json.Marshal(map[string]any{"path": source, "password": numberArray})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(unsafeWire)
	if _, err := h.Handle(context.Background(), "shared-recovery-inspect", unsafeWire); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("non-byte-field password accepted", err)
	}
	if result, err := request(source, destination, factor); err != nil || result.Status != "saved" {
		t.Fatal("could not save deployment SQL", err)
	}
	want, err := deploy.SchemaScript("archive2", snapshot.WorkspaceID.String())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(destination)
	if err != nil || string(saved) != want || bytes.Contains(saved, factor) {
		t.Fatal("SQL changed archive identity or disclosed the password", err)
	}
	if result, err := request(source, destination, factor); err != nil || result.Status != "save-failed" {
		t.Fatal("existing script was replaced", err)
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created a local database")
	}
	h.migrationQuiesced = true
	if _, err := request(source, "", factor); !errors.Is(err, vault.ErrPolicy) || !h.ExitOnCancel("shared-recovery-inspect") {
		t.Fatal("inspection escaped its launch or cancellation boundary", err)
	}
}

func TestSharedRecoveryInspectionRejectsAmbiguousEnvelope(t *testing.T) {
	snapshot := recoveryInspectionSnapshot(t)
	defer snapshot.Close()
	code, err := vault.FormatRecoveryKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	raw, err := encodeSharedRecoveryBackup(snapshot, code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(raw), []byte(`{}`)...),
		bytes.Replace(raw, []byte(`"schemaVersion": 3`), []byte(`"schemaVersion": 2`), 1),
		bytes.Replace(raw, []byte(`"encryption": "aes-gcm"`), []byte(`"encryption": "none"`), 1),
		bytes.Replace(raw, []byte(`"app": "Wormhole"`), []byte(`"app": "Different"`), 1),
		bytes.Replace(raw, []byte(`"exportedAt": "`), []byte(`"exportedAt": "!invalid`), 1),
		append([]byte(`{"payload": {},`), raw[1:]...),
		append([]byte(`{"app": "Wormhole",`), raw[1:]...),
		bytes.Replace(raw, []byte(`"app":`), []byte(`"APP":`), 1),
		bytes.Replace(raw, []byte(`"encryptedPayload": {`), []byte(`"encryptedPayload": {"iterations": 600000,`), 1),
	} {
		if plaintext, err := openSharedRecoveryBackupEnvelope(bad, code); plaintext != nil || !errors.Is(err, vault.ErrFormat) {
			t.Fatal("ambiguous envelope accepted", err)
		}
	}
}

func TestSharedRecoveryInspectionRejectsUntrustedArchiveIdentity(t *testing.T) {
	snapshot := recoveryInspectionSnapshot(t)
	defer snapshot.Close()
	encode := func(value *sharedpg.WorkspaceRecoverySnapshot) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	change := func(body []byte, key string, value any) []byte {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		fields[key] = raw
		out, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	original := encode(snapshot)
	for _, invalid := range [][]byte{
		nil, []byte(`{"formatVersion":2}`),
		append([]byte(`{"formatVersion":1,`), original[1:]...),
	} {
		if _, err := sharedpg.InspectWorkspaceRecoverySnapshot(invalid); err == nil {
			t.Fatal("unrecognised archive accepted")
		}
	}
	for _, entry := range []struct {
		relation int
		field    string
		value    any
	}{
		{0, "workspace_id", uuid.New()},
		{0, "role_tag", "bad-tag"},
		{0, "tls_sequence", 2},
		{0, "tls_bundle", "invalid"},
		{0, "tls_bundle", "\\xdeadbeef"},
		{0, "signed_profile", "invalid"},
		{0, "signed_profile", "\\xdeadbeef"},
		{0, "max_api", 2},
		{1, "public_key", "\\x" + hex.EncodeToString(bytes.Repeat([]byte{4}, 32))},
		{1, "public_key", "invalid"},
		{1, "status", "retired"},
		{1, "owner_id", uuid.New()},
		{1, "key_version", 0},
		{1, "ſtatus", "active"},
	} {
		draft := *snapshot
		draft.Records = append([]sharedpg.WorkspaceRecoveryRecord(nil), snapshot.Records...)
		record := &draft.Records[entry.relation]
		record.Body = change(record.Body, entry.field, entry.value)
		if _, err := sharedpg.InspectWorkspaceRecoverySnapshot(encode(&draft)); err == nil {
			t.Fatalf("untrusted %s accepted", entry.field)
		}
	}
	for _, relation := range []string{"keys", "account_auth"} {
		draft := *snapshot
		record := snapshot.Records[1]
		record.Relation = relation
		draft.Records = append(draft.Records, record)
		if _, err := sharedpg.InspectWorkspaceRecoverySnapshot(encode(&draft)); err == nil {
			t.Fatalf("unexpected %s row accepted", relation)
		}
	}
}
