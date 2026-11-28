package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestTLSTrustMetadataParsing(t *testing.T) {
	b, pin, _ := tlsTrustFixture(t)
	raw, err := EncodeTLSTrustBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	r := admissionRequest()
	r.WorkspaceID = b.WorkspaceID
	rows := [][][]byte{{[]byte(b.WorkspaceID.String()), []byte("1"), hex.AppendEncode(nil, raw)}}
	got, err := parseTLSTrustMetadata(rows, r)
	if err != nil {
		t.Fatal(err)
	}
	wipeQueryRows(rows)
	if _, err := VerifyTLSTrustBundle(*got, pin); err != nil {
		t.Fatal("row buffers aliased", err)
	}
	for _, bad := range [][][][]byte{nil, {{}}, {{[]byte(b.WorkspaceID.String()), []byte("1"), []byte("zz")}}, {{[]byte(b.WorkspaceID.String()), []byte("1"), []byte("00")}}, {{[]byte(b.WorkspaceID.String()), []byte("1"), bytes.Repeat([]byte{'0'}, 2*MaxTLSTrustBundleBytes+1)}}, {{[]byte(uuid.NewString()), []byte("1"), hex.AppendEncode(nil, raw)}}, {{[]byte(b.WorkspaceID.String()), []byte("01"), hex.AppendEncode(nil, raw)}}, {{[]byte(b.WorkspaceID.String()), []byte("2"), hex.AppendEncode(nil, raw)}}} {
		if result, err := parseTLSTrustMetadata(bad, r); result != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid metadata accepted", err)
		}
	}
	r.WorkspaceID = uuid.New()
	if _, err := parseTLSTrustMetadata([][][]byte{{[]byte(b.WorkspaceID.String()), []byte("1"), hex.AppendEncode(nil, raw)}}, r); err != ErrAdmissionResponse {
		t.Fatal("foreign workspace", err)
	}
	// Parsing deliberately does not authenticate the server's signature.
	b.Signature[0] ^= 1
	raw, _ = EncodeTLSTrustBundle(b)
	r.WorkspaceID = b.WorkspaceID
	got, err = parseTLSTrustMetadata([][][]byte{{[]byte(b.WorkspaceID.String()), []byte("1"), hex.AppendEncode(nil, raw)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTLSTrustBundle(*got, pin); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("forged server document trusted", err)
	}
}

func TestTLSTrustMetadataSessionGuards(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.TLSTrustBundle(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.TLSTrustBundle(context.Background()); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.TLSTrustBundle(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.TLSTrustBundle(context.Background()); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.TLSTrustBundle(context.Background()); err != ErrQuery {
		t.Fatal(err)
	}
}

// Runs inside the real PostgreSQL password/account fixture after audited proofs.
func testPostgresTLSTrustRead(t *testing.T, ctx context.Context, admin *pgconn.PgConn, session *Session) {
	t.Helper()
	if value, err := session.TLSTrustBundle(ctx); value != nil || err != ErrTLSMetadata {
		t.Fatal("missing provisioning", err)
	}
	b, pin, org := tlsTrustFixture(t)
	b.WorkspaceID = session.admission.WorkspaceID
	pin.WorkspaceID = b.WorkspaceID
	b, err := SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeTLSTrustBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	result := admin.ExecParams(ctx, "UPDATE wormhole_data.workspace_meta SET tls_sequence=$1::bigint,tls_bundle=decode($2,'hex')", [][]byte{[]byte(strconv.FormatUint(b.Sequence, 10)), hex.AppendEncode(nil, raw)}, nil, nil, nil).Read()
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	value, err := session.TLSTrustBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTLSTrustBundle(*value, pin); err != nil {
		t.Fatal("bundle retrieval", err)
	}
	for _, sql := range []string{"UPDATE wormhole_data.workspace_meta SET tls_sequence=0", "UPDATE wormhole_data.workspace_meta SET tls_bundle=NULL", "UPDATE wormhole_data.workspace_meta SET tls_bundle=''::bytea", "UPDATE wormhole_data.workspace_meta SET tls_bundle=decode(repeat('00',1048577),'hex')"} {
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "23514" {
			t.Fatal("invalid metadata stored", r.Err)
		}
	}
	if _, err := session.Query(ctx, "SELECT tls_bundle FROM wormhole_data.workspace_meta", nil); err == nil {
		t.Fatal("direct metadata table access")
	}
	if r := admin.ExecParams(ctx, "SELECT (NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.tls_trust_bundle(bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text", nil, nil, nil, nil).Read(); r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("PUBLIC API grant", r.Err)
	}
	// Even a privileged writer cannot make an opaque malformed blob trusted.
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.workspace_meta SET tls_bundle='x'::bytea", nil, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
	if value, err := session.TLSTrustBundle(ctx); value != nil || err != ErrAdmissionResponse {
		t.Fatal("malformed server bundle", err)
	}
	if _, err := session.Query(ctx, "SELECT 1", nil); err != ErrSessionClosed {
		t.Fatal("malformed response retained connection", err)
	}
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.workspace_meta SET tls_bundle=decode($1,'hex')", [][]byte{hex.AppendEncode(nil, raw)}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
}
