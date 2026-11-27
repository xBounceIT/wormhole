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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresFetchSecretMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("fetch migration", e)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("fetch migration state", r.Err)
		}
	}
	migration, _ := deploy.FetchSecretMigration("testscope", testHintID)
	wrong, _ := deploy.FetchSecretMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.fetch_secret(bytea,uuid,uuid) RETURNS jsonb LANGUAGE sql AS 'SELECT null::jsonb'")
	reject(migration, "42723")
	check("SELECT (schema_version=34)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_api_v1.fetch_secret(bytea,uuid,uuid)")
	script(migration)
	reject(migration, "55000")
	check("SELECT has_function_privilege('wh_testscope_user','wormhole_api_v1.fetch_secret(bytea,uuid,uuid)','EXECUTE')::text")
	check("SELECT (NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.fetch_secret(bytea,uuid,uuid)','EXECUTE'))::text")
	check("SELECT (prosecdef AND 'search_path=pg_catalog, pg_temp'=ANY(proconfig))::text FROM pg_proc WHERE oid='wormhole_api_v1.fetch_secret(bytea,uuid,uuid)'::regprocedure")
}

func testPostgresFetchSecret(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, f connectionFixture, g *UnverifiedCredentialRelease, private ...[]byte) {
	t.Helper()
	openingPrivate := bytes.Repeat([]byte{17}, 32)
	if len(private) == 1 {
		openingPrivate = private[0]
	}
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	exec := func(sql string, p ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, p, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	check := func(sql string, p ...[]byte) {
		t.Helper()
		r := exec(sql, p...)
		if len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("release state")
		}
	}
	command := func(sql string) {
		t.Helper()
		rows, e := native.Query(ctx, sql, nil)
		wipeQueryRows(rows)
		if e != nil {
			t.Fatal(e)
		}
	}
	var capability []byte
	if e := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(capability)
	begin := func() *UseIntent {
		t.Helper()
		i, e := native.BeginUse(ctx, f.node(), "ui")
		if e != nil {
			t.Fatal("audit issuance", e)
		}
		return i
	}
	query := func(i UseIntent, want error) {
		t.Helper()
		rows, e := native.Query(ctx, fetchSecretSQL, [][]byte{capability, []byte(i.Node.String()), []byte(i.Ticket.String())})
		defer wipeQueryRows(rows)
		if e != want {
			t.Fatal("audited release", want, e)
		}
		if e != nil {
			if len(rows) != 0 {
				t.Fatal("partial release")
			}
			return
		}
		if parsed, e := parseSecretRelease(rows, native.admission, i); e != nil || parsed == nil {
			t.Fatal("SQL receipt", e)
		}
	}
	assertUnspent := func(intent UseIntent) {
		t.Helper()
		ticket := exec("SELECT counter_slot::text,counter_value::text FROM wormhole_data.use_tickets WHERE ticket_id=$1::uuid", []byte(intent.Ticket.String()))
		if len(ticket.Rows) != 1 {
			t.Fatal("preparation consumed ticket")
		}
		slot, err := strconv.Atoi(string(ticket.Rows[0][0]))
		if err != nil || slot < 1 || slot > 1024 {
			t.Fatal("counter slot")
		}
		counter := exec("SELECT last_value::text FROM wormhole_data.use_counter_" + strconv.Itoa(slot))
		if string(counter.Rows[0][0]) != string(ticket.Rows[0][1]) {
			t.Fatal("preparation spent counter")
		}
	}
	i := begin()
	got, e := native.FetchSecret(ctx, *i)
	if e != nil || got == nil {
		t.Fatal("typed real fetch", e)
	}
	next, verified, e := f.s.VerifyCredentialRelease(ctx, f.node(), got)
	if e != nil || verified == nil || f.s.ValidateAdvance(next) != nil {
		t.Fatal("typed real verify", e)
	}
	// Authenticate and open the ACTUAL database graph through the complete native
	// opener, then check that borrowed fields are gone after callback return.
	var fields [][]byte
	if e := verified.WithValues(ctx, next, openingPrivate, func(_ resolver.Plan, values CredentialReleaseValues) error {
		if g.inline != nil {
			if values.Primary != nil || values.Gateway != nil || values.Inline == nil || values.Inline.NodeID != f.node().String() || string(values.Inline.Fields["inlinePassword"]) != "inline-secret" {
				t.Fatal("actual SQL inline opening")
			}
			fields = append(fields, values.Inline.Fields["inlinePassword"])
		} else {
			if values.Inline != nil || values.Primary == nil || string(values.Primary.Fields["password"]) != "primary-secret" || (values.Gateway != nil) != (g.metadata.records.Gateway != nil) {
				t.Fatal("actual SQL credential opening")
			}
			fields = append(fields, values.Primary.Fields["password"])
			if values.Gateway != nil {
				if string(values.Gateway.Fields["password"]) != "gateway-secret" {
					t.Fatal("actual SQL gateway opening")
				}
				fields = append(fields, values.Gateway.Fields["password"])
			}
		}
		return nil
	}); e != nil {
		t.Fatal("actual SQL opening", e)
	}
	assertReleaseWiped(t, fields)
	if g.metadata.records.Tunnel != nil {
		// A second, separately audited release is required for tunnel settings.
		settingsIntent := begin()
		encrypted, err := native.FetchSecret(ctx, *settingsIntent)
		if err != nil {
			t.Fatal(err)
		}
		committed, prepared, err := f.s.VerifyCredentialRelease(ctx, f.node(), encrypted)
		if err != nil {
			t.Fatal(err)
		}
		var settings []byte
		if err := prepared.WithTunnelValues(ctx, committed, openingPrivate, func(_ resolver.Plan, values CredentialReleaseValues) error {
			if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil || string(values.Tunnel.Fields["settings"]) != "tunnel-secret" {
				t.Fatal("audited tunnel settings")
			}
			settings = values.Tunnel.Fields["settings"]
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertReleaseWiped(t, [][]byte{settings})
		query(*settingsIntent, ErrUseTicket)
		// Missing settings must fail before spending the sequence generation.
		tunnelID := []byte(g.metadata.plan.TunnelID)
		saved := exec("SELECT to_jsonb(v)::text FROM wormhole_data.secret_values v WHERE v.owner_kind='tunnel' AND v.owner_id=$1::uuid AND v.field='settings'", tunnelID)
		if len(saved.Rows) != 1 {
			t.Fatal("fixture settings")
		}
		exec("DELETE FROM wormhole_data.secret_values WHERE owner_kind='tunnel' AND owner_id=$1::uuid AND field='settings'", tunnelID)
		missing := begin()
		query(*missing, ErrAccountRevision)
		assertUnspent(*missing)
		exec("INSERT INTO wormhole_data.secret_values SELECT * FROM jsonb_populate_record(NULL::wormhole_data.secret_values,$1::jsonb)", saved.Rows[0][0])
		restored := begin()
		query(*restored, nil)

	}
	check("SELECT (count(*)=1)::text FROM wormhole_data.audit_log WHERE ticket_id=$1::uuid AND action='begin_use' AND outcome='issued'", []byte(i.Ticket.String()))
	query(*i, ErrUseTicket)
	// A policy changed after issuance must be returned by this very release,
	// rather than letting a long-lived owner decrypt under its admission policy.
	i = begin()
	policy, e := vault.DecodeSignedPolicy(f.s.SignedProfile)
	if e != nil {
		t.Fatal(e)
	}
	policy.Policy.Sequence++
	policy, e = vault.SignPolicy(policy.Policy, f.s.SignerKeyID, f.s.SignerKeyVersion, f.org)
	if e != nil {
		t.Fatal(e)
	}
	newPolicy, e := vault.EncodeSignedPolicy(policy)
	if e != nil {
		t.Fatal(e)
	}
	exec("UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')", hex.AppendEncode(nil, newPolicy))
	changed, e := native.FetchSecret(ctx, *i)
	if e != nil {
		t.Fatal("fresh SQL policy", e)
	}
	observed, prepared, e := f.s.VerifyCredentialRelease(ctx, f.node(), changed)
	if e != ErrProfileChanged || prepared != nil || observed.PolicySequence != policy.Policy.Sequence || f.s.ValidateAdvance(observed) != nil {
		t.Fatal("stale admission policy used", e)
	}
	exec("UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')", hex.AppendEncode(nil, f.s.SignedProfile))
	i = begin()
	rolledBack, e := native.FetchSecret(ctx, *i)
	if e != nil {
		t.Fatal(e)
	}
	if next, prepared, e := observed.VerifyCredentialRelease(ctx, f.node(), rolledBack); e != ErrProfileRollback || prepared != nil || next.PolicySequence != observed.PolicySequence {
		t.Fatal("policy replay after fresh release", e)
	}
	exec("UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')", hex.AppendEncode(nil, newPolicy))
	// A wrong node/ticket cannot consume the correct pending capability.
	i = begin()
	wrong := *i
	wrong.Node = uuid.New()
	query(wrong, ErrUseTicket)
	wrong = *i
	wrong.Ticket = uuid.New()
	query(wrong, ErrUseTicket)
	query(*i, nil)
	// The actual public API must preserve the claim's nontransactional replay
	// protection, even when its ciphertext result was rolled back by the caller.
	for _, savepoint := range []bool{false, true} {
		i = begin()
		command("BEGIN")
		if savepoint {
			command("SAVEPOINT spent")
		}
		query(*i, nil)
		if savepoint {
			command("ROLLBACK TO SAVEPOINT spent")
			query(*i, ErrUseTicket)
		}
		command("ROLLBACK")
		query(*i, ErrUseTicket)
	}
	// Issuance and release in the same transaction cannot bypass durable audit.
	command("BEGIN")
	rows, e := native.Query(ctx, beginUseSQL, [][]byte{capability, []byte(f.node().String()), []byte("ui")})
	if e != nil {
		t.Fatal(e)
	}
	uncommitted, e := parseUseIntent(rows, native.admission, f.node())
	wipeQueryRows(rows)
	if e != nil {
		t.Fatal(e)
	}
	query(*uncommitted, ErrUseTicket)
	command("ROLLBACK")
	// Authorization applies separately to both selected account boundaries.
	for _, account := range g.accounts {
		exec("UPDATE wormhole_data.boundary_grants SET permissions=8 WHERE boundary_id=$1::uuid", []byte(account.boundary.String()))
		i = begin()
		query(*i, ErrQuery)
		exec("UPDATE wormhole_data.boundary_grants SET permissions=2 WHERE boundary_id=$1::uuid", []byte(account.boundary.String()))
	}
	i = begin()
	exec("UPDATE wormhole_data.grants SET permissions=8 WHERE node_id=$1::uuid", []byte(f.node().String()))
	query(*i, ErrTreeSnapshotChanged)
	exec("UPDATE wormhole_data.grants SET permissions=2 WHERE node_id=$1::uuid", []byte(f.node().String()))
	// Expiry and identity are checked again by the private claim.
	i = begin()
	exec("UPDATE wormhole_data.use_tickets SET issued_at=issued_at-interval '1 minute',expires_at=expires_at-interval '1 minute' WHERE ticket_id=$1::uuid", []byte(i.Ticket.String()))
	query(*i, ErrUseTicket)
	i = begin()
	r := admin.ExecParams(ctx, fetchSecretSQL, [][]byte{capability, []byte(i.Node.String()), []byte(i.Ticket.String())}, nil, nil, nil).Read()
	var pe *pgconn.PgError
	if !errors.As(r.Err, &pe) || pe.Code != "WH001" || len(r.Rows) != 0 {
		t.Fatal("non-device bypass", r.Err)
	}
	// Missing ciphertext/key material is detected BEFORE claim_use spends the
	// sequence generation. Check the actual sequence, not just a rolled-back row.
	copy := g.roots[0]
	exec("DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid AND key_version=$2::int", []byte(copy.Binding.Key.ID.String()), []byte(strconv.Itoa(int(copy.Binding.Key.Version))))
	i = begin()
	query(*i, ErrAccountRevision)
	assertUnspent(*i)
	// Reinstall the exact encrypted copy and obtain a fresh snapshot ticket.
	b := copy.Binding
	exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,$2::int,$3::uuid,$4::int,2,decode($5,'hex'),decode($6,'hex'),$7::uuid,$8::int,decode($9,'hex'))", []byte(b.Key.ID.String()), []byte(strconv.Itoa(int(b.Key.Version))), []byte(b.Holder.ID.String()), []byte(strconv.Itoa(int(b.Holder.Version))), hex.AppendEncode(nil, copy.Copy.Envelope.Enc), hex.AppendEncode(nil, copy.Copy.Envelope.Ciphertext), []byte(b.Issuer.ID.String()), []byte(strconv.Itoa(int(b.Issuer.Version))), hex.AppendEncode(nil, copy.Copy.Signature))
	i = begin()
	query(*i, nil)
	for _, column := range []int{1, 2} {
		script("BEGIN")
		script("SET LOCAL SESSION AUTHORIZATION \"wh_testscope_d_" + native.admission.DeviceID.String() + "\"")
		p := [][]byte{capability, []byte(f.node().String()), []byte(i.Ticket.String())}
		p[column] = nil
		r := admin.ExecParams(ctx, fetchSecretSQL, p, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "22023" || len(r.Rows) != 0 {
			t.Fatal("null release", r.Err)
		}
		script("ROLLBACK")
	}
}
