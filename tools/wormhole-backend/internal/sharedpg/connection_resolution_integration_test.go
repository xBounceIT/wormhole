package sharedpg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresConnectionResolution(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	testPostgresConnectionResolutionCases(t, ctx, admin, false)
}
func testPostgresConnectionResolutionCases(t *testing.T, ctx context.Context, admin *pgconn.PgConn, snapshot bool) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	exec := func(sql string, args ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	check := func(sql string) {
		t.Helper()
		r := exec(sql)
		if len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("connection migration state")
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("connection migration rejection", e)
		}
		script("ROLLBACK")
	}
	if !snapshot {
		migration, _ := deploy.ConnectionResolutionMigration("testscope", testHintID)
		wrong, _ := deploy.ConnectionResolutionMigration("testscope", uuid.NewString())
		reject(wrong, "55000")
		script("CREATE FUNCTION wormhole_data.resolve_connection(uuid,uuid,bigint,bigint) RETURNS jsonb LANGUAGE sql AS 'SELECT null::jsonb'")
		reject(migration, "42723")
		check("SELECT (schema_version=27)::text FROM wormhole_data.workspace_meta")
		script("DROP FUNCTION wormhole_data.resolve_connection(uuid,uuid,bigint,bigint)")
		script(migration)
		reject(migration, "55000")
		for _, role := range []string{"user", "admin", "enroll"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.resolve_connection(uuid,uuid,bigint,bigint)','EXECUTE'))::text")
		}
	}
	for _, mode := range []string{"saved", "sftp", "vnc", "inherited-saved", "none", "inline", "override", "deleted-override", "slot-default", "slot-personal", "slot-deleted-value", "gateway", "gateway-same", "missing-profile", "deleted-profile", "missing-slot", "deleted-slot", "wrong-slot-protocol", "wrong-profile-protocol", "wrong-gateway-protocol", "missing-gateway", "unassigned-slot", "other-user-override", "other-user-value"} {
		t.Run("connection-"+mode, func(t *testing.T) {
			f := newConnectionFixture(t)
			switch mode {
			case "sftp", "vnc":
				protocol := 7
				if mode == "vnc" {
					protocol = 6
					f.records.Credential.Credential.Record.Metadata.Protocol = "vnc"
				}
				f.records.Chain[0].Node.Metadata.Protocol = &protocol
			case "inherited-saved":
				mode := 2
				f.records.Chain[1].Node.Metadata.CredentialMode = &mode
				f.records.Chain[1].Node.Metadata.CredentialID = f.records.Chain[0].Node.Metadata.CredentialID
				f.records.Chain[0].Node.Metadata.CredentialMode = nil
				f.records.Chain[0].Node.Metadata.CredentialID = nil
			case "none":
				v := 1
				f.records.Chain[0].Node.Metadata.CredentialMode = &v
				f.records.Credential = nil
			case "inline":
				v := true
				f.records.Chain[0].Node.Metadata.UseInlinePassword = &v
				f.records.Credential = nil
			case "override", "deleted-override", "other-user-override":
				r := sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID}
				if mode == "deleted-override" {
					r.Deleted = true
					r.CredentialID = ""
				}
				f.records.Override = f.selection(t, r)
			case "slot-default", "slot-personal", "slot-deleted-value", "missing-slot", "deleted-slot", "wrong-slot-protocol", "unassigned-slot", "other-user-value":
				f.slot(t, mode == "slot-personal" || mode == "other-user-value")
				r := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
				if mode == "slot-deleted-value" {
					f.records.SlotValue = f.selection(t, sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: r.ID, UserID: f.s.UserID.String(), Deleted: true})
				}
				if mode == "deleted-slot" {
					r.Deleted = true
				}
				if mode == "wrong-slot-protocol" {
					r.Protocol = "rdp"
				}
				if mode == "unassigned-slot" {
					r.DefaultCredentialID = ""
				}
				f.records.Slot = f.selection(t, r)
			case "gateway", "gateway-same", "wrong-gateway-protocol", "missing-gateway":
				protocol, method, host := 1, 1, "gateway.example"
				f.records.Chain[0].Node.Metadata.Protocol = &protocol
				f.records.Chain[0].Node.Metadata.RDPGatewayUsageMethod = &method
				f.records.Chain[0].Node.Metadata.RDPGatewayHostname = &host
				f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
				f.records.Gateway = f.profile(t, "rdp")
				f.records.Chain[0].Node.Metadata.RDPGatewayCredentialID = &f.records.Gateway.Credential.Record.Metadata.ID
				if mode == "gateway-same" {
					v := true
					f.records.Chain[0].Node.Metadata.RDPGatewayUseSameCreds = &v
				}
				if mode == "wrong-gateway-protocol" {
					f.records.Gateway.Credential.Record.Metadata.Protocol = "ssh"
				}
			case "deleted-profile":
				f.records.Credential.Credential.Record.Deleted = true
			case "wrong-profile-protocol":
				f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
			}
			// Keep names unique relative to earlier integration fixtures.
			for _, c := range []*UnverifiedCredentialRecord{f.records.Credential, f.records.Gateway} {
				if c != nil {
					c.Credential.Record.Metadata.Name = uuid.NewString()
					f.signProfile(t, c, 1)
				}
			}
			f.signChain(t)
			script("BEGIN")
			defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
			if snapshot {
				exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(f.records.Chain[0].Node.Boundary.String()))
			}
			a := f.records.Chain[0].Author
			cert := a.Certificate
			text := func(v any) []byte {
				raw, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			insert := func(table string, v map[string]any) {
				t.Helper()
				exec("INSERT INTO wormhole_data."+table+" SELECT * FROM jsonb_populate_record(NULL::wormhole_data."+table+",$1::jsonb)", text(v))
			}
			hexval := func(b []byte) string { return "\\x" + hex.EncodeToString(b) }
			insert("keys", map[string]any{"key_id": cert.Signer.ID, "key_version": cert.Signer.Version, "kind": "org-sign", "status": "pending", "suite": 1, "public_key": hexval(f.s.PublicKey), "row_version": 1, "created_at": "2026-11-05T00:00:00Z"})
			insert("keys", map[string]any{"key_id": a.Key.ID, "key_version": a.Key.Version, "kind": "user-sign", "owner_id": f.s.UserID, "status": "pending", "suite": 1, "public_key": hexval(cert.PublicKey), "cert_signer_key_id": cert.Signer.ID, "cert_signer_key_version": cert.Signer.Version, "cert_revision": cert.Revision, "cert_signature": hexval(cert.Signature), "row_version": 1, "created_at": "2026-11-05T00:00:00Z"})
			state, e := vault.EncodeUserKeyState(*a.State)
			if e != nil {
				t.Fatal(e)
			}
			exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=$2::bytea WHERE user_id=$3::uuid", []byte(strconv.FormatUint(a.State.Sequence, 10)), []byte(hexval(state)), []byte(f.s.UserID.String()))
			sealFields := func(boundary uuid.UUID, s vault.RecordSeal) map[string]any {
				return map[string]any{"boundary_id": boundary, "row_version": s.Revision, "seal_suite": 2, "seal_signer_key_id": s.SignerKeyID, "seal_signer_key_version": s.SignerKeyVersion, "seal": hexval(s.Signature)}
			}
			for i := len(f.records.Chain) - 1; i >= 0; i-- {
				n := f.records.Chain[i].Node
				m := n.Metadata
				v := sealFields(n.Boundary, n.Seal)
				for k, x := range map[string]any{"id": m.ID, "parent_id": m.ParentID, "kind": m.Kind, "name": m.Name, "sort_order": 0, "protocol": m.Protocol, "host": m.Host, "username": m.Username, "credential_id": m.CredentialID, "credential_mode": m.CredentialMode, "credential_slot_id": m.CredentialSlotID, "use_inline_password": m.UseInlinePassword, "rdp_domain": m.RDPDomain, "rdp_gateway_usage_method": m.RDPGatewayUsageMethod, "rdp_gateway_hostname": m.RDPGatewayHostname, "rdp_gateway_credential_id": m.RDPGatewayCredentialID, "rdp_gateway_use_same_creds": m.RDPGatewayUseSameCreds} {
					v[k] = x
				}
				insert("nodes", v)
			}
			for _, c := range []*UnverifiedCredentialRecord{f.records.Credential, f.records.Gateway} {
				if c == nil {
					continue
				}
				if (mode == "missing-profile" && c == f.records.Credential) || (mode == "missing-gateway" && c == f.records.Gateway) {
					continue
				}
				r := c.Credential
				m := r.Record.Metadata
				v := sealFields(r.Boundary, r.Seal)
				for k, x := range map[string]any{"id": m.ID, "name": m.Name, "protocol": m.Protocol, "kind": m.Kind, "username": m.Username, "domain": m.Domain, "provider": m.Provider, "bitwarden_item_id": "", "bitwarden_item_name": "", "bitwarden_field_path": "", "private_key_name": "", "certificate_name": "", "fields": []any{}, "deleted": r.Record.Deleted} {
					v[k] = x
				}
				insert("credential_profiles", v)
			}
			// The default is deliberately a different existing signed profile for personal values.
			if mode == "slot-personal" || mode == "other-user-value" {
				r := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
				c := f.profile(t, "ssh")
				c.Credential.Record.Metadata.ID = r.DefaultCredentialID
				c.Credential.Record.Metadata.Name = uuid.NewString()
				c.Credential.Record.Metadata.Username = "default-user"
				c.Credential.Record.Metadata.Domain = ""
				f.signProfile(t, c, 1)
				v := sealFields(c.Credential.Boundary, c.Credential.Seal)
				for k, x := range map[string]any{"id": r.DefaultCredentialID, "name": c.Credential.Record.Metadata.Name, "protocol": "ssh", "kind": "password", "username": "default-user", "domain": "", "provider": "local", "bitwarden_item_id": "", "bitwarden_item_name": "", "bitwarden_field_path": "", "private_key_name": "", "certificate_name": "", "fields": []any{}, "deleted": false} {
					v[k] = x
				}
				insert("credential_profiles", v)
			}
			other := uuid.NewString()
			if mode == "other-user-override" || mode == "other-user-value" {
				exec("INSERT INTO wormhole_data.users(id,login_name,name) VALUES($1::uuid,$2,'Other')", []byte(other), []byte(other))
			}
			for _, r := range []*UnverifiedSelectionRecord{f.records.Slot, f.records.SlotValue, f.records.Override} {
				if r == nil {
					continue
				}
				v := sealFields(r.Selection.Boundary, r.Selection.Seal)
				var table string
				switch x := r.Selection.Record.(type) {
				case sharedcatalog.SlotRecord:
					table = "credential_slots"
					v["id"] = x.ID
					v["name"] = x.Name
					v["protocol"] = x.Protocol
					v["allow_self_service"] = x.AllowSelfService
					v["deleted"] = x.Deleted
					if x.DefaultCredentialID != "" {
						v["default_credential_id"] = x.DefaultCredentialID
					}
					if mode == "missing-slot" {
						continue
					}
				case sharedcatalog.SlotValueRecord:
					table = "credential_slot_values"
					v["id"] = x.ID
					v["slot_id"] = x.SlotID
					v["user_id"] = x.UserID
					v["deleted"] = x.Deleted
					if x.CredentialID != "" {
						v["credential_id"] = x.CredentialID
					}
					if mode == "other-user-value" {
						v["user_id"] = other
					}
				case sharedcatalog.OverrideRecord:
					table = "user_node_overrides"
					v["node_id"] = x.NodeID
					v["user_id"] = x.UserID
					v["deleted"] = x.Deleted
					if x.CredentialID != "" {
						v["credential_id"] = x.CredentialID
					}
					if mode == "other-user-override" {
						v["user_id"] = other
					}
				}
				insert(table, v)
			}
			if snapshot {
				_, _, _, m, _ := boundaryTrustFixture(t)
				m.WorkspaceID = f.s.WorkspaceID
				m.BoundaryID = f.records.Chain[0].Node.Boundary
				m.Signer = f.records.Chain[0].Author.Certificate.Signer
				m, e := vault.SignBoundaryManifest(m, f.org)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := vault.EncodeBoundaryManifest(m)
				if e != nil {
					t.Fatal(e)
				}
				exec("INSERT INTO wormhole_data.boundary_manifests(boundary_id,version,body,signer_key_id,signer_key_version,signature) VALUES($1::uuid,1,decode($2,'hex'),$3::uuid,$4::int,decode($5,'hex'))", []byte(m.BoundaryID.String()), hex.AppendEncode(nil, raw), []byte(m.Signer.ID.String()), []byte(strconv.Itoa(int(m.Signer.Version))), hex.AppendEncode(nil, m.Signature))
			}
			epoch := exec("SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta").Rows[0]
			query := "SELECT wormhole_data.resolve_connection($1::uuid,$2::uuid,$3::bigint,$4::bigint)::text"
			args := [][]byte{[]byte(f.node().String()), []byte(f.s.UserID.String()), epoch[0], epoch[1]}
			result := admin.ExecParams(ctx, query, args, nil, nil, nil).Read()
			bad := mode == "missing-profile" || mode == "deleted-profile" || mode == "missing-slot" || mode == "deleted-slot" || mode == "wrong-slot-protocol" || mode == "wrong-profile-protocol" || mode == "wrong-gateway-protocol" || mode == "missing-gateway" || mode == "unassigned-slot"
			if bad {
				var pe *pgconn.PgError
				if !errors.As(result.Err, &pe) || pe.Code != "WH018" || len(result.Rows) != 0 {
					t.Fatal("invalid selected record", result.Err)
				}
				return
			}
			if result.Err != nil || len(result.Rows) != 1 {
				t.Fatal("connection resolution", result.Err)
			}
			if mode == "other-user-override" {
				f.records.Override = nil
			}
			if mode == "other-user-value" {
				f.records.SlotValue = nil
				slot := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
				f.records.Credential.Credential.Record.Metadata.ID = slot.DefaultCredentialID
				f.records.Credential.Credential.Record.Metadata.Username = "default-user"
				f.records.Credential.Credential.Record.Metadata.Domain = ""
				f.signProfile(t, f.records.Credential, 1)
			}
			if mode == "gateway-same" {
				f.records.Gateway = nil
			}
			_, want, e := f.s.ResolveCatalogConnection(ctx, f.node(), f.records)
			if e != nil {
				t.Fatal("native counterpart", e)
			}
			var got resolver.Plan
			if json.Unmarshal(result.Rows[0][0], &got) != nil || got != want {
				t.Fatal("SQL/native connection resolution drift", mode, got, want)
			}
			if snapshot {
				script("SET LOCAL bytea_output='escape'")
				r := exec("SELECT wormhole_data.connection_snapshot($1::uuid,$2::uuid,$3::bigint,$4::bigint)::text", args...)
				epoch, e1 := strconv.ParseUint(string(epoch[0]), 10, 64)
				seq, e2 := strconv.ParseUint(string(args[3]), 10, 64)
				if e1 != nil || e2 != nil {
					t.Fatal("snapshot numbers")
				}
				snap, e := parseConnectionSnapshot(r.Rows[0][0], AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), epoch, seq)
				if e != nil {
					t.Fatal("real snapshot decode", e)
				}
				observed, p, e := f.s.VerifyConnectionSnapshot(ctx, f.node(), snap)
				if e != nil || p != want || f.s.ValidateAdvance(observed) != nil {
					t.Fatal("real snapshot native verification", e)
				}
			}
			deny := func(args [][]byte, code string) {
				t.Helper()
				script("SAVEPOINT invalid_connection")
				r := admin.ExecParams(ctx, query, args, nil, nil, nil).Read()
				var pe *pgconn.PgError
				if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
					t.Fatal("connection rejection", r.Err)
				}
				script("ROLLBACK TO SAVEPOINT invalid_connection; RELEASE SAVEPOINT invalid_connection")
			}
			for i := range args {
				invalid := append([][]byte(nil), args...)
				invalid[i] = nil
				deny(invalid, "22023")
			}
			stale := append([][]byte(nil), args...)
			stale[3] = []byte("0")
			deny(stale, "WH013")
			script("SAVEPOINT readiness")
			script("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
			deny(args, "WH002")
			script("ROLLBACK TO SAVEPOINT readiness; RELEASE SAVEPOINT readiness")
			script("SAVEPOINT version")
			script("UPDATE wormhole_data.workspace_meta SET min_api=2,max_api=2")
			deny(args, "WH004")
			script("ROLLBACK TO SAVEPOINT version; RELEASE SAVEPOINT version")
		})
	}
}
