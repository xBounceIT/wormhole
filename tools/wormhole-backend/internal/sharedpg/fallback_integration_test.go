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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresFallbackMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("fallback migration state", sql, r.Err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var p *pgconn.PgError
		if !errors.As(err, &p) || p.Code != code {
			t.Fatal("fallback migration rejection", err)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.TunnelFallbackMigration("testscope", testHintID)
	wrong, _ := deploy.TunnelFallbackMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.fallback_release_graph(uuid,uuid,uuid,uuid,bigint,bigint) RETURNS jsonb LANGUAGE sql AS 'SELECT NULL::jsonb'")
	reject(migration, "42723")
	check("SELECT (schema_version=42 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='wormhole_data.use_tickets'::regclass AND attname='release_kind') AND to_regprocedure('wormhole_data.fallback_permissions(bytea,uuid,uuid,uuid,bigint,bigint)') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.fallback_release_graph(uuid,uuid,uuid,uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	check("SELECT (schema_version=43)::text FROM wormhole_data.workspace_meta")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, fn := range []string{"fallback_permissions(bytea,uuid,uuid,uuid,bigint,bigint)", "begin_use_intent(bytea,uuid,text,uuid,uuid)", "claim_use_intent(bytea,uuid,uuid,uuid,uuid)", "fallback_release_graph(uuid,uuid,uuid,uuid,bigint,bigint)", "claim_use(bytea,uuid,uuid)"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
		}
		for _, table := range []string{"use_tickets", "use_counter_slots", "tunnel_profiles", "key_copies", "secret_values"} {
			check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data." + table + "','SELECT,INSERT,UPDATE,DELETE'))::text")
		}
		for _, fn := range []string{"begin_fallback_use(bytea,uuid,uuid,uuid,text)", "fetch_fallback_secret(bytea,uuid,uuid,uuid,uuid)"} {
			expected := "false"
			// Admin inherits the user role, but still needs an enrolled device
			// and capability. Its own ACL must not receive an explicit grant.
			if role == "user" || role == "admin" {
				expected = "true"
			}
			check("SELECT (has_function_privilege('wh_testscope_" + role + "','wormhole_api_v1." + fn + "','EXECUTE')=" + expected + ")::text")
			if role != "user" {
				check("SELECT (NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1." + fn + "'::regprocedure AND a.grantee='wh_testscope_" + role + "'::regrole))::text")
			}
		}
	}
	for _, fn := range []string{"begin_fallback_use(bytea,uuid,uuid,uuid,text)", "fetch_fallback_secret(bytea,uuid,uuid,uuid,uuid)"} {
		check("SELECT (prosecdef AND 'search_path=pg_catalog, pg_temp'=ANY(proconfig) AND NOT EXISTS(SELECT 1 FROM aclexplode(proacl) a WHERE a.grantee=0))::text FROM pg_proc WHERE oid='wormhole_api_v1." + fn + "'::regprocedure")
	}
}

func installPostgresFallbackTarget(t *testing.T, ctx context.Context, admin *pgconn.PgConn, d fallbackTestData) {
	t.Helper()
	exec := func(sql string, p ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, p, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	n := func(v uint64) []byte { return []byte(strconv.FormatUint(v, 10)) }
	g := d.parsed
	m := g.manifest
	body, _ := vault.EncodeBoundaryManifest(m)
	exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(m.BoundaryID.String()))
	exec("INSERT INTO wormhole_data.boundary_manifests(boundary_id,version,body,signer_key_id,signer_key_version,signature) VALUES($1::uuid,$2::bigint,decode($3,'hex'),$4::uuid,$5::int,decode($6,'hex'))", []byte(m.BoundaryID.String()), n(m.Revision), hex.AppendEncode(nil, body), []byte(m.Signer.ID.String()), n(uint64(m.Signer.Version)), hex.AppendEncode(nil, m.Signature))
	r := g.target.Selection
	exec("INSERT INTO wormhole_data.tunnel_profiles(id,name,kind,configuration_version,boundary_id,row_version,seal_suite,seal_signer_key_id,seal_signer_key_version,seal) VALUES($1::uuid,'Secondary SSL',2,1,$2::uuid,1,2,$3::uuid,$4::int,decode($5,'hex'))", []byte(d.intent.FallbackTunnel.String()), []byte(r.Boundary.String()), []byte(r.Seal.SignerKeyID), n(uint64(r.Seal.SignerKeyVersion)), hex.AppendEncode(nil, r.Seal.Signature))
	for _, entry := range []struct {
		ref  vault.KeyRef
		kind string
	}{{m.Secret.Key, "boundary-secret"}, {g.values[0].Binding.DEK, "dek"}} {
		exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,$2::int,$3,'pending',2)", []byte(entry.ref.ID.String()), n(uint64(entry.ref.Version)), []byte(entry.kind))
	}
	for _, copy := range []UnverifiedKeyCopy{g.root, g.copy} {
		b := copy.Binding
		exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,$2::int,$3::uuid,$4::int,2,decode($5,'hex'),decode($6,'hex'),$7::uuid,$8::int,decode($9,'hex'))", []byte(b.Key.ID.String()), n(uint64(b.Key.Version)), []byte(b.Holder.ID.String()), n(uint64(b.Holder.Version)), hex.AppendEncode(nil, copy.Copy.Envelope.Enc), hex.AppendEncode(nil, copy.Copy.Envelope.Ciphertext), []byte(b.Issuer.ID.String()), n(uint64(b.Issuer.Version)), hex.AppendEncode(nil, copy.Copy.Signature))
	}
	v := g.values[0]
	envelope, _ := vault.EncodeSharedEnvelope(v.Envelope)
	exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) VALUES('tunnel',$1::uuid,'settings',$2::uuid,$3::int,decode($4,'hex'),1)", []byte(d.intent.FallbackTunnel.String()), []byte(v.Binding.DEK.ID.String()), n(uint64(v.Binding.DEK.Version)), hex.AppendEncode(nil, envelope))
}

func testPostgresFallbackRelease(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, d fallbackTestData) {
	t.Helper()
	exec := func(sql string, p ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, p, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sql string, p ...[]byte) {
		t.Helper()
		r := exec(sql, p...)
		if len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("fallback state")
		}
	}
	command := func(sql string) {
		t.Helper()
		rows, err := native.Query(ctx, sql, nil)
		wipeQueryRows(rows)
		if err != nil {
			t.Fatal(err)
		}
	}
	var capability []byte
	if err := native.capability.With(func(raw []byte) error { capability = hex.AppendEncode(nil, raw); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	node, primary, target := d.f.node(), d.intent.PrimaryTunnel, d.intent.FallbackTunnel
	begin := func() *FallbackUseIntent {
		t.Helper()
		i, err := native.BeginFallbackUse(ctx, node, primary, target, "ui")
		if err != nil {
			t.Fatal("fallback issue", err)
		}
		return i
	}
	query := func(i FallbackUseIntent, want error) {
		t.Helper()
		rows, err := native.Query(ctx, fetchFallbackSecretSQL, [][]byte{capability, []byte(i.Node.String()), []byte(i.Ticket.String()), []byte(i.PrimaryTunnel.String()), []byte(i.FallbackTunnel.String())})
		defer wipeQueryRows(rows)
		if err != want || err != nil && len(rows) != 0 {
			t.Fatal("fallback release", want, err)
		}
		if err == nil {
			if _, err = parseFallbackSecret(rows, native.admission, i); err != nil {
				t.Fatal("real fallback graph", err)
			}
		}
	}
	assertUnspent := func(i FallbackUseIntent) {
		t.Helper()
		r := exec("SELECT counter_slot::text,counter_value::text FROM wormhole_data.use_tickets WHERE ticket_id=$1::uuid", []byte(i.Ticket.String()))
		if len(r.Rows) != 1 {
			t.Fatal("ticket spent during preparation")
		}
		slot, err := strconv.Atoi(string(r.Rows[0][0]))
		if err != nil || slot < 1 || slot > 1024 {
			t.Fatal("bad slot")
		}
		counter := exec("SELECT last_value::text FROM wormhole_data.use_counter_" + strconv.Itoa(slot))
		if !bytes.Equal(counter.Rows[0][0], r.Rows[0][1]) {
			t.Fatal("counter spent during preparation")
		}
	}
	i := begin()
	check("SELECT (action='begin_fallback_use' AND primary_tunnel_id=$2::uuid AND fallback_tunnel_id=$3::uuid AND pg_xact_status(transaction_id)='committed')::text FROM wormhole_data.audit_log WHERE ticket_id=$1::uuid", []byte(i.Ticket.String()), []byte(primary.String()), []byte(target.String()))
	got, err := native.FetchFallbackSecret(ctx, *i)
	if err != nil || got == nil || got.source.enrollment == nil != (d.finalKeys == nil) || got.target.Selection.Boundary != d.parsed.manifest.BoundaryID {
		t.Fatal("typed fallback", err)
	}
	committed, prepared, err := d.f.s.VerifyFallbackRelease(ctx, node, got)
	if err != nil || prepared == nil || d.f.s.ValidateAdvance(committed) != nil {
		t.Fatal("actual fallback proof verification", err)
	}
	var borrowedPrimary, borrowedTarget []byte
	err = prepared.WithConfiguration(ctx, committed, d.private, fallbackSelector(t, func(raw []byte) { borrowedPrimary = raw }), func(s FallbackSources, raw []byte) error {
		if !bytes.Equal(borrowedPrimary, make([]byte, len(borrowedPrimary))) || s.Plan.TunnelID != primary.String() || s.Fallback.Metadata.ID != target.String() || string(raw) != `{"Host":"ssl.test","Password":"secondary-secret"}` {
			t.Fatal("actual SQL source/reference/target handoff")
		}
		borrowedTarget = raw
		return nil
	})
	if err != nil {
		t.Fatal("actual SQL target opening", err)
	}
	assertReleaseWiped(t, [][]byte{borrowedPrimary, borrowedTarget})
	if _, err := prepared.ValidateReference(ctx, committed, d.private, fallbackSelector(t, nil)); err != ErrUseTicket {
		t.Fatal("actual SQL prepared graph replay", err)
	}
	query(*i, ErrUseTicket)
	// Ordinary endpoints cannot consume fallback tickets, and vice versa.
	i = begin()
	rows, err := native.Query(ctx, fetchSecretSQL, [][]byte{capability, []byte(node.String()), []byte(i.Ticket.String())})
	wipeQueryRows(rows)
	if err != ErrUseTicket {
		t.Fatal("fallback ticket consumed as ordinary", err)
	}
	assertUnspent(*i)
	query(*i, nil)
	i = begin()
	ordinary, err := native.BeginUse(ctx, node, "ui")
	if err != nil {
		t.Fatal(err)
	}
	query(*i, ErrUseTicket)
	query(FallbackUseIntent{UseIntent: *ordinary, PrimaryTunnel: primary, FallbackTunnel: target}, ErrUseTicket)
	check("SELECT (release_kind='connection' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL)::text FROM wormhole_data.use_tickets WHERE ticket_id=$1::uuid", []byte(ordinary.Ticket.String()))
	if _, err = native.FetchSecret(ctx, *ordinary); err != nil {
		t.Fatal("ordinary purpose was not reset", err)
	}
	ordinary, err = native.BeginUse(ctx, node, "ui")
	if err != nil {
		t.Fatal(err)
	}
	i = begin()
	rows, err = native.Query(ctx, fetchSecretSQL, [][]byte{capability, []byte(node.String()), []byte(ordinary.Ticket.String())})
	wipeQueryRows(rows)
	if err != ErrUseTicket {
		t.Fatal("ordinary ticket survived fallback replacement", err)
	}
	assertUnspent(*i)
	query(*i, nil)
	// A native issuance must refuse an open caller transaction; even raw SQL
	// issuance cannot release ciphertext until its audit transaction commits.
	command("BEGIN")
	if _, err := native.BeginFallbackUse(ctx, node, primary, target, "ui"); err != ErrConfiguration {
		t.Fatal("native uncommitted issue", err)
	}
	rows, err = native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
	if err != nil {
		t.Fatal(err)
	}
	uncommitted, err := parseFallbackUseIntent(rows, native.admission, node, primary, target)
	wipeQueryRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	query(*uncommitted, ErrUseTicket)
	command("ROLLBACK")
	for _, role := range []string{"user", "admin"} {
		script("BEGIN; SET LOCAL SESSION AUTHORIZATION wh_testscope_" + role)
		r := admin.ExecParams(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")}, nil, nil, nil).Read()
		var p *pgconn.PgError
		if !errors.As(r.Err, &p) || p.Code != "WH001" || len(r.Rows) != 0 {
			t.Fatal("bare role bypassed device admission", r.Err)
		}
		script("ROLLBACK")
	}
	for _, column := range []int{1, 2, 3} {
		p := [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")}
		p[column] = nil
		rows, err := native.Query(ctx, beginFallbackUseSQL, p)
		wipeQueryRows(rows)
		if err == nil {
			t.Fatal("null fallback selector accepted", column)
		}
	}
	rows, err = native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(uuid.NewString()), []byte(target.String()), []byte("ui")})
	wipeQueryRows(rows)
	if err != ErrQuery {
		t.Fatal("unselected primary accepted", err)
	}
	for _, mode := range []string{"expired", "server-restarted"} {
		i = begin()
		if mode == "expired" {
			exec("UPDATE wormhole_data.use_tickets SET issued_at=issued_at-interval '60 seconds',expires_at=expires_at-interval '60 seconds' WHERE ticket_id=$1::uuid", []byte(i.Ticket.String()))
		} else {
			exec("UPDATE wormhole_data.use_tickets SET server_started_at=server_started_at-interval '1 second' WHERE ticket_id=$1::uuid", []byte(i.Ticket.String()))
		}
		query(*i, ErrUseTicket)
		assertUnspent(*i)
	}
	// Wrong node, source, target or ticket cannot advance the sequence.
	for _, mode := range []string{"node", "primary", "target", "ticket"} {
		i = begin()
		bad := *i
		switch mode {
		case "node":
			bad.Node = uuid.New()
		case "primary":
			bad.PrimaryTunnel = uuid.New()
		case "target":
			bad.FallbackTunnel = uuid.New()
		case "ticket":
			bad.Ticket = uuid.New()
		}
		query(bad, ErrUseTicket)
		assertUnspent(*i)
		query(*i, nil)
	}
	for _, savepoint := range []bool{false, true} {
		i = begin()
		command("BEGIN")
		if savepoint {
			command("SAVEPOINT secondary")
		}
		query(*i, nil)
		if savepoint {
			command("ROLLBACK TO SAVEPOINT secondary")
			query(*i, ErrUseTicket)
		}
		command("ROLLBACK")
		query(*i, ErrUseTicket)
	}
	// Missing target ciphertext fails before the rollback-resistant claim.
	envelope, _ := vault.EncodeSharedEnvelope(d.parsed.values[0].Envelope)
	exec("DELETE FROM wormhole_data.secret_values WHERE owner_kind='tunnel' AND owner_id=$1::uuid", []byte(target.String()))
	i = begin()
	query(*i, ErrAccountRevision)
	assertUnspent(*i)
	v := d.parsed.values[0]
	exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) VALUES('tunnel',$1::uuid,'settings',$2::uuid,1,decode($3,'hex'),1)", []byte(target.String()), []byte(v.Binding.DEK.ID.String()), hex.AppendEncode(nil, envelope))
	// Reveal without Use on the secondary boundary cannot even issue an intent.
	exec("UPDATE wormhole_data.boundary_grants SET permissions=8 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", []byte(d.parsed.manifest.BoundaryID.String()), []byte(d.f.s.UserID.String()))
	rows, err = native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
	wipeQueryRows(rows)
	if err != ErrQuery {
		t.Fatal("secondary boundary Use bypass", err)
	}
	exec("UPDATE wormhole_data.boundary_grants SET permissions=2 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", []byte(d.parsed.manifest.BoundaryID.String()), []byte(d.f.s.UserID.String()))
	for _, boundary := range []uuid.UUID{d.parsed.manifest.BoundaryID, d.parsed.source.metadata.records.Tunnel.Selection.Boundary} {
		i = begin()
		exec("UPDATE wormhole_data.boundary_grants SET permissions=8 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", []byte(boundary.String()), []byte(d.f.s.UserID.String()))
		query(*i, ErrTreeSnapshotChanged)
		rows, err := native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
		wipeQueryRows(rows)
		if err != ErrQuery {
			t.Fatal("source or target Use bypass", err)
		}
		exec("UPDATE wormhole_data.boundary_grants SET permissions=2 WHERE boundary_id=$1::uuid AND user_id=$2::uuid", []byte(boundary.String()), []byte(d.f.s.UserID.String()))
	}
	for _, mutation := range []string{"kind=1", "deleted=true"} {
		exec("UPDATE wormhole_data.tunnel_profiles SET "+mutation+" WHERE id=$1::uuid", []byte(target.String()))
		rows, err := native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
		wipeQueryRows(rows)
		if err != ErrQuery {
			t.Fatal("unavailable target authorized", err)
		}
		exec("UPDATE wormhole_data.tunnel_profiles SET kind=2,deleted=false WHERE id=$1::uuid", []byte(target.String()))
	}
	exec("UPDATE wormhole_data.tunnel_profiles SET kind=2 WHERE id=$1::uuid", []byte(primary.String()))
	rows, err = native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
	wipeQueryRows(rows)
	if err != ErrQuery {
		t.Fatal("non-IPsec source authorized", err)
	}
	exec("UPDATE wormhole_data.tunnel_profiles SET kind=9 WHERE id=$1::uuid", []byte(primary.String()))
	i = begin()
	exec("UPDATE wormhole_data.tunnel_profiles SET deleted=true WHERE id=$1::uuid", []byte(target.String()))
	query(*i, ErrTreeSnapshotChanged)
	exec("UPDATE wormhole_data.tunnel_profiles SET deleted=false WHERE id=$1::uuid", []byte(target.String()))
	// Failure of the separately identifiable audit cannot publish a new intent.
	script("CREATE FUNCTION wormhole_data.reject_fallback_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='begin_fallback_use' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_fallback_audit BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.reject_fallback_audit()")
	rows, err = native.Query(ctx, beginFallbackUseSQL, [][]byte{capability, []byte(node.String()), []byte(primary.String()), []byte(target.String()), []byte("ui")})
	wipeQueryRows(rows)
	if err != ErrAuditUnavailable {
		t.Fatal("audit failure bypass", err)
	}
	script("DROP TRIGGER reject_fallback_audit ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.reject_fallback_audit()")
	i = begin()
	query(*i, nil)
}
