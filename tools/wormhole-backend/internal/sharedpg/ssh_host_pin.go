package sharedpg

import (
	"context"
	"math"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const sshHostPinSignature = "wormhole_api_v1.ssh_host_pin(bytea,uuid,bigint,bigint,bigint,text,uuid,integer,bytea,bytea,bytea,bytea)"
const sshHostPinSQL = `SELECT status,projection::text FROM wormhole_api_v1.ssh_host_pin(
	pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::bigint,$6::text,$7::uuid,$8::integer,
	pg_catalog.decode($9,'hex'),pg_catalog.decode($10,'hex'),pg_catalog.decode($11,'hex'),pg_catalog.decode($12,'hex'))`

// An edit contains authenticated public material only. PostgreSQL repeats the
// permission and snapshot checks when the admitted device commits it.
type SSHHostPinEdit struct {
	plan   ResolvedConnectionPlan
	fields *UnverifiedSelection // Verified by AdvanceSelection before the edit is returned.
	signer vault.KeyRef
}

// An unrelated catalog change can advance the sequence without changing this connection.
func (e *SSHHostPinEdit) matchesPlan(after ResolvedConnectionPlan, received string, revision uint64) bool {
	if e.plan.leaf == nil || after.leaf == nil || e.plan.pinContext == nil || after.pinContext == nil {
		return false
	}
	wantPlan, wantNode := e.plan.Plan, e.plan.leaf.Metadata
	wantPlan.HostKeyFingerprint, wantNode.SshKnownHostFingerprint = received, &received
	seal := after.leaf.Seal
	priorRevision, err := after.pinContext.revision(&e.plan.pinContext.metadata.records.Chain[0])
	return revision == e.plan.leaf.Seal.Revision+1 && seal.Revision == revision &&
		after.epoch == e.plan.epoch && after.sequence > e.plan.sequence && err == nil && priorRevision == e.plan.Revision &&
		seal.SignerKeyID == e.signer.ID.String() && seal.SignerKeyVersion == e.signer.Version &&
		after.leaf.Boundary == e.plan.leaf.Boundary && after.leaf.Permissions == e.plan.leaf.Permissions && after.Path == e.plan.Path &&
		after.Plan == wantPlan && reflect.DeepEqual(after.leaf.Metadata, wantNode) && reflect.DeepEqual(after.Tunnel, e.plan.Tunnel)
}

func (e *SSHHostPinEdit) matchesFields(readback *SSHHostPinEdit) bool {
	if readback == nil || e.signer != readback.signer || (e.fields == nil) != (readback.fields == nil) {
		return false
	}
	f := readback.fields
	return f == nil || (f.Seal.SignerKeyID == e.signer.ID.String() && f.Seal.SignerKeyVersion == e.signer.Version &&
		reflect.DeepEqual(f.Record, e.fields.Record))
}

func (p ResolvedConnectionPlan) pinArgs() [][]byte {
	return [][]byte{[]byte(p.Plan.NodeID), []byte(strconv.FormatUint(p.epoch, 10)), []byte(strconv.FormatUint(p.sequence, 10)), []byte(strconv.FormatUint(p.leaf.Seal.Revision, 10))}
}

func (s *Session) PrepareSSHHostPin(ctx context.Context, trust TrustState, plan ResolvedConnectionPlan) (TrustState, *SSHHostPinEdit, error) {
	node, err := uuid.Parse(plan.Plan.NodeID)
	if ctx == nil || err != nil || node == uuid.Nil || plan.leaf == nil || plan.pinContext == nil || plan.Plan.NodeID != plan.leaf.Metadata.ID ||
		(plan.Plan.Protocol != 0 && plan.Plan.Protocol != 7) || plan.leaf.Metadata.Kind != 1 || plan.epoch == 0 ||
		plan.leaf.Seal.Revision == 0 || plan.leaf.Seal.Revision >= math.MaxInt64 || trust.Account == nil || !trust.Account.Active || trust.Enrollment == nil {
		return TrustState{}, nil, ErrConfiguration
	}
	ok, err := s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure('`+sshHostPinSignature+`') IS NOT NULL)::text`)
	if !ok || err != nil {
		return TrustState{}, nil, err
	}
	return s.readSSHHostPin(ctx, trust, plan, node)
}

func (s *Session) readSSHHostPin(ctx context.Context, trust TrustState, plan ResolvedConnectionPlan, node uuid.UUID) (TrustState, *SSHHostPinEdit, error) {
	var observed TrustState
	var edit *SSHHostPinEdit
	err := s.queryAdministration(ctx, trust, sshHostPinSQL, append(plan.pinArgs(), nil, nil, nil, nil, nil), 2*vault.MaxUserEnrollmentCertificateBytes+65536, 2, func(row [][]byte) error {
		var err error
		observed, edit, err = parseSSHHostPinRead(row, s.admission, trust, plan, node)
		return err
	})
	return observed, edit, err
}

func parseSSHHostPinRead(row [][]byte, admission AdmissionRequest, trust TrustState, plan ResolvedConnectionPlan, node uuid.UUID) (TrustState, *SSHHostPinEdit, error) {
	status, raw := string(row[0]), row[1]
	if status != "ready" {
		return TrustState{}, nil, pinDenial(status, raw)
	}
	edit := &SSHHostPinEdit{plan: plan, signer: trust.Enrollment.Signing}
	observed, fields, err := verifyEditableFields(raw, admission, trust, node, plan.leaf, plan.epoch, plan.sequence, plan.Plan.Credential.Kind == "inline")
	if err != nil {
		return observed, nil, err
	}
	edit.fields = fields
	return observed, edit, nil
}

func verifyEditableFields(raw []byte, admission AdmissionRequest, trust TrustState, node uuid.UUID, leaf *UnverifiedTreeNode, epoch, sequence uint64, required bool) (TrustState, *UnverifiedSelection, error) {
	if raw == nil {
		if required || trust.Catalog["node-fields/"+node.String()].Revision != 0 {
			return TrustState{}, nil, ErrAdmissionResponse
		}
		return TrustState{}, nil, nil
	}
	wire, err := snapshotOptionalRow(raw, 24)
	if err != nil || wire == nil {
		return TrustState{}, nil, ErrAdmissionResponse
	}
	value, author, err := parseSelectionProjection([][][]byte{wire}, admission, sharedcatalog.SelectionScope{Kind: "node-fields", Subject: node}, epoch, sequence)
	if err != nil {
		return TrustState{}, nil, err
	}
	if leaf == nil || value.Boundary != leaf.Boundary || value.Seal.Revision != leaf.Seal.Revision {
		return TrustState{}, nil, ErrAdmissionResponse
	}
	observed, err := trust.AdvanceSelection(*value, *author)
	if err != nil {
		return observed, nil, err
	}
	return observed, value, nil
}

func pinDenial(status string, raw []byte) error {
	if raw == nil && (status == "unavailable" || status == "stale" || status == "busy") {
		return nil
	}
	return ErrAdmissionResponse
}

func (s *Session) CommitSSHHostPin(ctx context.Context, trust TrustState, edit *SSHHostPinEdit, received string, keys *vault.UserKeys) (uint64, error) {
	if ctx == nil || edit == nil || edit.plan.leaf == nil || keys == nil || trust.Account == nil || !trust.Account.Active || trust.Enrollment == nil ||
		!vault.ValidSSHFingerprint(received) || edit.plan.Plan.HostKeyFingerprint == received {
		return 0, ErrConfiguration
	}
	plan := edit.plan
	metadata := plan.leaf.Metadata
	metadata.SshKnownHostFingerprint = &received
	revision := plan.leaf.Seal.Revision + 1
	signer := edit.signer
	seal, fields, err := signEditedNode(trust, keys, signer, plan.leaf.Boundary, metadata, revision, edit.fields)
	if err != nil {
		return 0, err
	}
	args := append(plan.pinArgs(), []byte(received), []byte(signer.ID.String()), []byte(strconv.FormatUint(uint64(signer.Version), 10)), seal, fields)
	var committed uint64
	err = s.queryAdministration(ctx, trust, sshHostPinSQL, args, 256, 2, func(row [][]byte) error {
		if row[1] != nil {
			return ErrAdmissionResponse
		}
		if string(row[0]) != "changed" {
			return pinDenial(string(row[0]), row[1])
		}
		committed = revision
		return nil
	})
	return committed, err
}

// VerifySSHHostPin reconciles the edited leaf and its field manifest on the
// account path originally confirmed. The owner persists both observations in
// one checkpoint, including independently verified changes on a denied receipt.
func (s *Session) VerifySSHHostPin(ctx context.Context, trust TrustState, edit *SSHHostPinEdit, fingerprint string, revision uint64) (TrustState, bool, error) {
	if edit == nil || edit.plan.leaf == nil || trust.Enrollment == nil || !vault.ValidSSHFingerprint(fingerprint) || revision != edit.plan.leaf.Seal.Revision+1 {
		return TrustState{}, false, ErrConfiguration
	}
	node, err := uuid.Parse(edit.plan.Plan.NodeID)
	if err != nil {
		return TrustState{}, false, ErrConfiguration
	}
	input, err := s.connectionPlan(ctx, node, edit.plan.Path)
	if err != nil {
		return TrustState{}, false, err
	}
	observed, plan, err := trust.VerifyConnectionPlan(ctx, node, input)
	if err != nil || !edit.matchesPlan(plan, fingerprint, revision) {
		return observed, false, err
	}
	next, readback, err := s.readSSHHostPin(ctx, observed, plan, node)
	if next.Revision != 0 {
		observed = next
	}
	return observed, err == nil && edit.matchesFields(readback), err
}
