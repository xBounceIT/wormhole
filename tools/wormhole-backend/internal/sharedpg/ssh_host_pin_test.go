package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSSHHostPinRequiresAuthenticatedConnectionAndEnrollment(t *testing.T) {
	ctx := context.Background()
	s := &Session{}
	if _, edit, err := s.PrepareSSHHostPin(ctx, TrustState{}, ResolvedConnectionPlan{}); err != ErrConfiguration || edit != nil {
		t.Fatal("unverified plan reached the signing path", err)
	}
	if rev, err := s.CommitSSHHostPin(ctx, TrustState{}, &SSHHostPinEdit{}, "", nil); err != ErrConfiguration || rev != 0 {
		t.Fatal("unenrolled confirmation reached the database", err)
	}
	if observed, matched, err := s.VerifySSHHostPin(ctx, TrustState{}, nil, "", 0); err != ErrConfiguration || matched || observed.Revision != 0 {
		t.Fatal("confirmation without an edit reached the database", err)
	}
	if pinDenial("changed", nil) != ErrAdmissionResponse || pinDenial("unavailable", []byte("unexpected")) != ErrAdmissionResponse {
		t.Fatal("unexpected confirmation response accepted")
	}
}

func TestSSHHostPinMissingFieldManifest(t *testing.T) {
	node := uuid.New()
	trust := TrustState{Enrollment: &EnrollmentPin{}}
	ready := [][]byte{[]byte("ready"), nil}
	var plan ResolvedConnectionPlan
	plan.Plan.Credential.Kind = "saved"
	if _, edit, err := parseSSHHostPinRead(ready, AdmissionRequest{}, trust, plan, node); err != nil || edit == nil || edit.fields != nil {
		t.Fatal("a saved credential without a historical field manifest should remain usable", err)
	}
	plan.Plan.Credential.Kind = "inline"
	if _, edit, err := parseSSHHostPinRead(ready, AdmissionRequest{}, trust, plan, node); err != ErrAdmissionResponse || edit != nil {
		t.Fatal("first observation accepted an inline credential without its signed field manifest", err)
	}
	plan.Plan.Credential.Kind = "saved"
	trust.Catalog = map[string]CatalogFloor{"node-fields/" + node.String(): {Revision: 1}}
	if _, edit, err := parseSSHHostPinRead(ready, AdmissionRequest{}, trust, plan, node); err != ErrAdmissionResponse || edit != nil {
		t.Fatal("a previously observed manifest disappeared", err)
	}
	ready[1] = []byte("null")
	if _, edit, err := parseSSHHostPinRead(ready, AdmissionRequest{}, trust, plan, node); err != ErrAdmissionResponse || edit != nil {
		t.Fatal("invalid field projection accepted", err)
	}
}

func checkImportedSSHHostPin(t *testing.T, ctx context.Context, db *pgconn.PgConn, s *Session, trust TrustState, node uuid.UUID, actor *vault.UserKeys) {
	t.Helper()
	read := func() ResolvedConnectionPlan {
		t.Helper()
		material, err := s.ConnectionPlanPath(ctx, node, DefaultConnectionPath)
		if err != nil {
			t.Fatal("read current SSH plan", err)
		}
		next, p, err := trust.VerifyConnectionPlan(ctx, node, material)
		if err != nil {
			t.Fatal("verify current SSH plan", material.metadata.records.Chain[0].Node.Seal.Revision, err)
		}
		trust = next
		return p
	}
	prepare := func(p ResolvedConnectionPlan) *SSHHostPinEdit {
		t.Helper()
		next, edit, err := s.PrepareSSHHostPin(ctx, trust, p)
		if err != nil {
			t.Fatal("prepare host pin", err)
		}
		if next.Revision != 0 {
			trust = next
		}
		return edit
	}
	mask := func(n string) {
		t.Helper()
		r := db.ExecParams(ctx, `UPDATE wormhole_data.grants SET permissions=$1::integer WHERE node_id=$2::uuid AND user_id=$3::uuid`, [][]byte{[]byte(n), []byte(node.String()), []byte(trust.UserID.String())}, nil, nil, nil).Read()
		if r.Err != nil || r.CommandTag.RowsAffected() != 1 {
			t.Fatal("device grant", r.Err)
		}
	}
	p := read()
	before := p.leaf.Seal.Revision
	edit := prepare(p)
	if edit == nil || edit.fields == nil {
		t.Fatal("expected authenticated field manifest on imported connection")
	}
	pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32))
	mask("3")
	t.Cleanup(func() { mask("31") })
	if revision, err := s.CommitSSHHostPin(ctx, trust, edit, pin, actor); err != nil || revision != 0 {
		t.Fatal("revoked Write accepted", err)
	}
	if denied := prepare(read()); denied != nil {
		t.Fatal("Use alone allowed SSH host pin signing")
	}
	mask("7") // View, Use and Write are sufficient without Reveal or Manage.
	edit = prepare(read())
	if revision, err := s.CommitSSHHostPin(ctx, trust, edit, pin, actor); err != nil || revision != before+1 {
		t.Fatal("host pin not saved", revision, err)
	}
	if revision, err := s.CommitSSHHostPin(ctx, trust, edit, pin, actor); err != nil || revision != 0 {
		t.Fatal("stale confirmation was replayed", err)
	}
	after := read()
	updated := prepare(after)
	if !edit.matchesPlan(after, pin, before+1) || edit.matchesPlan(edit.plan, pin, before+1) || after.Revision == p.Revision || after.Plan.Username != p.Plan.Username || after.Plan.TunnelID != p.Plan.TunnelID {
		t.Fatal("host pin changed other resolution inputs")
	}
	if updated == nil || updated.fields == nil || !edit.matchesFields(updated) {
		t.Fatal("new field signature did not verify")
	}
	noFieldsBefore, noFieldsAfter := *edit, *updated
	noFieldsBefore.fields, noFieldsAfter.fields = nil, nil
	if !noFieldsBefore.matchesFields(&noFieldsAfter) || noFieldsBefore.matchesFields(updated) || edit.matchesFields(nil) {
		t.Fatal("missing readback or changed manifest presence was misclassified")
	}
	for _, tc := range []struct {
		name   string
		change func(*SSHHostPinEdit)
	}{
		{"destination", func(e *SSHHostPinEdit) { e.plan.Plan.Port++ }},
		{"restored workspace", func(e *SSHHostPinEdit) { e.plan.epoch++ }},
		{"old sequence", func(e *SSHHostPinEdit) { e.plan.sequence = edit.plan.sequence }},
		{"missing field manifest", func(e *SSHHostPinEdit) { e.fields = nil }},
		{"different field versions", func(e *SSHHostPinEdit) {
			fields := *e.fields
			record := fields.Record.(sharedcatalog.NodeFieldsRecord)
			next := vaultstore.CredentialField{Field: "inlinePassword", Version: 1}
			if len(record.Fields) > 0 {
				next = record.Fields[0]
				next.Version++
			}
			record.Fields = []vaultstore.CredentialField{next}
			fields.Record = record
			e.fields = &fields
		}},
		{"different manifest signer", func(e *SSHHostPinEdit) {
			fields := *e.fields
			fields.Seal.SignerKeyID = uuid.NewString()
			e.fields = &fields
		}},
	} {
		changed := *updated
		tc.change(&changed)
		if edit.matchesPlan(changed.plan, pin, before+1) && edit.matchesFields(&changed) {
			t.Errorf("acknowledged %s during confirmation", tc.name)
		}
	}
	replacement := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{92}, 32))
	wrong := &vault.UserKeys{EncryptionPrivate: actor.EncryptionPrivate, SigningSeed: bytes.Repeat([]byte{3}, 32)}
	if _, err := s.CommitSSHHostPin(ctx, trust, updated, replacement, wrong); err != vault.ErrAuthentication {
		t.Fatal("unexpected signing key accepted", err)
	}
	rev, err := s.CommitSSHHostPin(ctx, trust, updated, replacement, actor)
	if err != nil || rev != before+2 {
		t.Fatal("changed host key did not verify", rev, err)
	}
	checkpoint, matched, err := s.VerifySSHHostPin(ctx, trust, updated, replacement, rev)
	if err != nil || !matched || checkpoint.Catalog["node/"+node.String()].Revision != rev || checkpoint.Catalog["node-fields/"+node.String()].Revision != rev {
		t.Fatal("missing node or field manifest in the confirmation checkpoint", err)
	}
	trust = checkpoint
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if next, ok, err := s.VerifySSHHostPin(canceled, trust, updated, replacement, rev); err != context.Canceled || ok || next.Revision != 0 {
		t.Fatal("canceled confirmation returned a receipt or trust observation", err)
	}
	// A legitimate edit in between the pin write and its readback need not
	// change the resolved SSH address, user or credential ID.
	credential := updated.plan.pinContext.metadata.records.Credential.Credential
	credential.Record.Metadata.Name = "Renamed while confirming SSH"
	signingKey := ed25519.NewKeyFromSeed(actor.SigningSeed)
	defer vault.Wipe(signingKey)
	signer := trust.Enrollment.Signing
	seal, err := sharedcatalog.SignCredential(trust.WorkspaceID, credential.Boundary, credential.Record, credential.Seal.Revision+1, signer, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	result := db.ExecParams(ctx, `UPDATE wormhole_data.credential_profiles SET name=$1,row_version=row_version+1,
		seal=decode($2,'hex'),seal_signer_key_id=$3::uuid,seal_signer_key_version=$4::integer
		WHERE id=$5::uuid AND row_version=$6::bigint`, [][]byte{[]byte(credential.Record.Metadata.Name), hex.AppendEncode(nil, seal.Signature),
		[]byte(signer.ID.String()), []byte(strconv.FormatUint(uint64(signer.Version), 10)), []byte(credential.Record.Metadata.ID),
		[]byte(strconv.FormatUint(credential.Seal.Revision, 10))}, nil, nil, nil).Read()
	if result.Err != nil || result.CommandTag.RowsAffected() != 1 {
		t.Fatal("could not publish concurrent credential rename", result.Err)
	}
	changed := prepare(read())
	if changed == nil || changed.plan.Plan.Credential != updated.plan.Plan.Credential || changed.plan.Plan.Host != updated.plan.Plan.Host ||
		changed.plan.Plan.HostKeyFingerprint != replacement || changed.plan.pinContext.metadata.records.Credential.Credential.Seal.Revision != seal.Revision ||
		updated.matchesPlan(changed.plan, replacement, rev) {
		t.Fatal("unexpected confirmation result after a signed credential rename")
	}
	checkpoint, matched, err = s.VerifySSHHostPin(ctx, checkpoint, updated, replacement, rev)
	if err != nil || matched || checkpoint.Catalog["credential/"+credential.Record.Metadata.ID].Revision != seal.Revision {
		t.Fatal("concurrent credential observation was not retained on denial", err)
	}
	r := db.ExecParams(ctx, `SELECT count(*) FROM wormhole_data.audit_log WHERE action='ssh_host_pin_change' AND node_id=$1::uuid`, [][]byte{[]byte(node.String())}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "2" {
		t.Fatal("expected one audit per committed pin change", r.Err)
	}
}
