package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkRejectedBoundaryRotation(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState,
	tls *VerifiedTLSBundle, plan *GroupBoundaryRotationPreparation, actor *vault.UserKeys, old vault.KeyRef) {
	t.Helper()
	pin, err := trust.accountTrust()
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{[]byte("{}"), bytes.Repeat([]byte{' '}, 32769)} {
		if _, err := decodeBoundaryRotationSnapshot(plan.request, invalid); err != ErrAdmissionResponse {
			t.Fatal("unbounded or incomplete rotation snapshot was accepted", err)
		}
	}
	wrong := cloneTrustState(trust)
	delete(wrong.Catalog, "boundary/"+plan.request.BoundaryID)
	if _, _, err := session.CommitPreparedGroupBoundaryRotation(ctx, wrong, tls, plan, actor); err != ErrTrustState {
		t.Fatal("rotation borrowed keys without committing the observed boundary", err)
	}
	if _, _, err := session.CommitPreparedGroupBoundaryRotation(ctx, trust, tls, nil, actor); err != ErrConfiguration {
		t.Fatal("rotation reached escrow without a preparation", err)
	}
	outsider := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{11}, 32), SigningSeed: actor.SigningSeed}
	defer vault.Wipe(outsider.EncryptionPrivate)
	if result, err := plan.prepareRoots(ctx, trust, pin, outsider); result != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("a different account opened the rotation custody material", err)
	}
	if e := session.queryServerCA(ctx, trust, boundaryRotationMaterialSQL, plan.request.arguments(nil), maxBoundaryRotationGraph, 1, 15, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 15 {
			return ErrAdmissionResponse
		}
		checkRotationMaterialValidation(t, ctx, trust, pin, plan, rows[0])
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	rotation, err := plan.prepareRoots(ctx, trust, pin, actor)
	if err != nil || rotation == nil || len(rotation.Copies) < 2 {
		t.Fatal("the real plan did not include multiple copies", err)
	}
	manifest, err := vault.EncodeBoundaryManifest(rotation.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	rotation.Copies[len(rotation.Copies)-1].Binding.Holder.ID = uuid.New()
	bad, err := json.Marshal(boundaryRotationPublication{Manifest: string(manifest), Copies: rotation.Copies})
	if err != nil {
		t.Fatal(err)
	}
	err = session.queryServerCA(ctx, trust, "SELECT status"+boundaryRotationCall, plan.request.arguments(bad), 64, 1, 1,
		func([][][]byte) error { t.Error("invalid rotation returned a status"); return nil })
	if err == nil {
		t.Fatal("rotation accepted a replacement copy for the wrong root")
	}
	row, err := readAccountResetRow(ctx, dba, `SELECT (EXISTS(SELECT FROM wormhole_data.keys
         WHERE (key_id,key_version)=($1::uuid,$2::integer) AND status='active')
         AND NOT EXISTS(SELECT FROM wormhole_data.keys WHERE (key_id,key_version)=($1::uuid,($2::integer)+1))
         AND NOT EXISTS(SELECT FROM wormhole_data.audit_log WHERE action='boundary_group_rotation'))::text`, keyCopyFixtureRef(old), 1, 8)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("failed rotation left a partial key, revocation or audit", err)
	}
}

func checkRotationMaterialValidation(t *testing.T, ctx context.Context, trust TrustState, pin vault.UserKeyTrust, plan *GroupBoundaryRotationPreparation, row [][]byte) {
	t.Helper()
	input, err := decodeBoundaryRotationSnapshot(plan.request, row[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*boundaryRotationSnapshot){
		func(s *boundaryRotationSnapshot) { s.NodeID = uuid.NewString() },
		func(s *boundaryRotationSnapshot) { s.Epoch = "-1" },
		func(s *boundaryRotationSnapshot) { s.ChangeSeq = "undefined" },
		func(s *boundaryRotationSnapshot) { s.GraphDigest = strings.Repeat("Z", 64) },
	} {
		bad := input
		bad.Review = ""
		edit(&bad)
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBoundaryRotationSnapshot(plan.request, raw); err != ErrAdmissionResponse {
			t.Fatal("rotation accepted substituted snapshot metadata", err)
		}
	}
	unsigned := plan.request
	unsigned.Review = strings.Repeat("0", 64)
	if _, err := decodeBoundaryRotationSnapshot(unsigned, row[1]); err != vault.ErrAuthentication {
		t.Fatal("wrong confirmation reached the rotation graph", err)
	}
	for _, keyColumn := range []int{0, 5, 11} {
		custody := append([][]byte(nil), row[3:]...)
		custody[keyColumn] = []byte(strings.Repeat("0", len(custody[keyColumn])))
		if next := *plan; next.readCustody(pin, plan.recipient.Encryption, custody) == nil {
			t.Fatal("substituted organisation custody proof was accepted")
		}
	}
	material := *plan
	material.roots = nil
	if _, err := material.verifyGraph(ctx, trust, pin, input.graphScope(), nil); err != ErrAdmissionResponse {
		t.Fatal("missing graph reached rotation", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := material.verifyGraph(canceled, trust, pin, input.graphScope(), row[2]); err != context.Canceled {
		t.Fatal("canceled rotation continued preparing recipients", err)
	}
	if _, err := material.verifyGraph(ctx, trust, pin, input.graphScope(), append(bytes.Clone(row[2]), ' ')); err != vault.ErrAuthentication {
		t.Fatal("changed graph passed the reviewed digest", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*boundaryRotationRootWire)
	}{
		{"unknown purpose", func(root *boundaryRotationRootWire) { root.Purpose = "unsupported" }},
		{"wrong purpose", func(root *boundaryRotationRootWire) { root.Purpose = vault.BoundaryView }},
		{"missing escrow", func(root *boundaryRotationRootWire) { root.Escrow = json.RawMessage("null") }},
		{"bad source copy", func(root *boundaryRotationRootWire) { root.DEKs[0] = json.RawMessage("null") }},
		{"retained revoked group", func(root *boundaryRotationRootWire) {
			root.Recipients[len(root.Recipients)-1] = boundaryRotationHolder{Kind: "group", Subject: uuid.MustParse(plan.request.GroupID)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var graph []boundaryRotationRootWire
			if err := json.Unmarshal(row[2], &graph); err != nil {
				t.Fatal(err)
			}
			tc.edit(&graph[0])
			raw, err := json.Marshal(graph)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			bound := input
			bound.GraphDigest = hex.EncodeToString(digest[:])
			if _, err := material.verifyGraph(ctx, trust, pin, bound.graphScope(), raw); err != ErrAdmissionResponse || len(material.roots) != 0 {
				t.Fatal("invalid graph reached preparation", err)
			}
		})
	}
}
