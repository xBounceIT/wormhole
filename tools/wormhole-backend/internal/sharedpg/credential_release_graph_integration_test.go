package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const credentialReleaseGraphTestSQL = `SELECT wormhole_data.credential_release_graph($1::uuid,$2::uuid,$3::bigint,$4::bigint)::text`

func testPostgresCredentialReleaseGraph(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
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
	rejectMigration := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("graph migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.CredentialReleaseGraphMigration("testscope", testHintID)
	wrong, _ := deploy.CredentialReleaseGraphMigration("testscope", uuid.NewString())
	rejectMigration(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint) RETURNS jsonb LANGUAGE sql AS 'SELECT null::jsonb'")
	rejectMigration(migration, "42723")
	r := exec("SELECT (schema_version=33 AND to_regprocedure('wormhole_data.key_copy_wire(jsonb)') IS NULL)::text FROM wormhole_data.workspace_meta")
	if string(r.Rows[0][0]) != "true" {
		t.Fatal("graph migration rollback")
	}
	script("DROP FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint)")
	script(migration)
	rejectMigration(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, fn := range []string{"key_copy_wire(jsonb)", "credential_release_graph(uuid,uuid,bigint,bigint)"} {
			r := exec("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
			if string(r.Rows[0][0]) != "true" {
				t.Fatal("private graph ACL")
			}
		}
	}
	testPostgresFetchSecretMigration(t, ctx, admin)
	testPostgresReleasePolicyMigration(t, ctx, admin)
	testPostgresConnectionPlanMigration(t, ctx, admin)
	testPostgresRuntimeStateMigration(t, ctx, admin)
	testPostgresNodeFieldsMigration(t, ctx, admin)
	testPostgresTunnelMigration(t, ctx, admin)
	testPostgresEnrolledCatalogMigration(t, ctx, admin)
	testPostgresFallbackMigration(t, ctx, admin)
	for _, mode := range []string{"saved", "gateway", "previous", "none", "inline", "inline-empty", "inline-absent", "inline-rdp", "inline-rdp-gateway", "tunnel", "tunnel-inline", "tunnel-inline-gateway", "public-inline", "public", "public-tunnel", "enrolled", "enrolled-tunnel", "fallback", "enrolled-fallback"} {
		t.Run("release-graph-"+mode, func(t *testing.T) {
			exec := func(sql string, args ...[]byte) *pgconn.Result {
				t.Helper()
				r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
				if r.Err != nil {
					t.Fatal(r.Err)
				}
				return r
			}
			kind := mode
			if mode == "previous" {
				kind = "saved"
			}
			if mode == "public" || mode == "public-tunnel" {
				kind = "gateway"
			}
			var f connectionFixture
			var wire map[string]any
			var finalKeys *vault.UserKeys
			var fallback *fallbackTestData
			enrolled := strings.HasPrefix(mode, "enrolled")
			if strings.HasSuffix(mode, "fallback") {
				data := fallbackReleaseFixture(t, enrolled)
				fallback = &data
				f, wire, finalKeys = data.f, data.source, data.finalKeys
			} else if enrolled {
				f, wire, finalKeys = enrolledReleaseFixture(t, mode == "enrolled-tunnel")
			} else if mode == "tunnel" || mode == "tunnel-inline" || mode == "tunnel-inline-gateway" || mode == "public-tunnel" {
				tunnelKind := "saved"
				switch mode {
				case "tunnel-inline":
					tunnelKind = "inline"
				case "tunnel-inline-gateway":
					tunnelKind = "inline-gateway"
				case "public-tunnel":
					tunnelKind = "gateway"
				}
				f, wire = tunnelReleaseFixture(t, tunnelKind)
			} else if strings.HasPrefix(mode, "inline") || mode == "public-inline" {
				inlineMode := "password"
				if mode == "inline-empty" {
					inlineMode = "empty"
				} else if mode == "inline-absent" {
					inlineMode = "absent"
				} else if mode == "inline-rdp" {
					inlineMode = "rdp"
				} else if mode == "inline-rdp-gateway" {
					inlineMode = "rdp-gateway"
				}
				f, wire = inlineReleaseFixture(t, inlineMode)
			} else {
				f, wire = releaseGraphFixture(t, kind, mode != "previous", mode == "previous")
			}
			g, e := releaseParseFixture(t, f, wire)
			if e != nil {
				t.Fatal(e)
			}
			script("BEGIN; SET LOCAL bytea_output='escape'")
			exec("UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')", hex.AppendEncode(nil, f.s.SignedProfile))
			defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
			n := func(v uint64) []byte { return []byte(strconv.FormatUint(v, 10)) }
			jsonval := func(v any) []byte {
				b, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			hexval := func(v []byte) string { return "\\x" + hex.EncodeToString(v) }
			insert := func(table string, v map[string]any) {
				t.Helper()
				exec("INSERT INTO wormhole_data."+table+" SELECT * FROM jsonb_populate_record(NULL::wormhole_data."+table+",$1::jsonb)", jsonval(v))
			}
			a := f.records.Chain[0].Author
			c := a.Certificate
			if enrolled {
				c = &a.EnrollmentCertificate.BootstrapSigning
			}
			exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite,public_key) VALUES($1::uuid,$2::int,'org-sign','pending',1,decode($3,'hex'))", []byte(c.Signer.ID.String()), n(uint64(c.Signer.Version)), hex.AppendEncode(nil, f.s.PublicKey))
			exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES($1::uuid,$2::int,'user-sign',$3::uuid,'pending',1,decode($4,'hex'),$5::uuid,$6::int,$7::bigint,decode($8,'hex'))", []byte(c.Key.ID.String()), n(uint64(c.Key.Version)), []byte(f.s.UserID.String()), hex.AppendEncode(nil, c.PublicKey), []byte(c.Signer.ID.String()), n(uint64(c.Signer.Version)), n(c.Revision), hex.AppendEncode(nil, c.Signature))
			// Each fixture installs its own account selection. A preceding public
			// enrolled case must not silently select its final recipient for a
			// later bootstrap fixture.
			exec("DELETE FROM wormhole_data.user_enrollments WHERE user_id=$1::uuid", []byte(f.s.UserID.String()))
			if enrolled {
				certificate := a.EnrollmentCertificate
				exec("UPDATE wormhole_data.keys SET status='retired' WHERE owner_id=$1::uuid AND kind IN ('user-sign','user-enc') AND status='active'", []byte(f.s.UserID.String()))
				exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite,public_key) VALUES($1::uuid,1,'user-sign',$2::uuid,'active',1,decode($3,'hex'))", []byte(a.Key.ID.String()), []byte(f.s.UserID.String()), hex.AppendEncode(nil, certificate.Rekey.Public.Signing))
				exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite,public_key) VALUES($1::uuid,1,'user-enc',$2::uuid,'active',2,decode($3,'hex'))", []byte(f.s.Enrollment.Encryption.ID.String()), []byte(f.s.UserID.String()), hex.AppendEncode(nil, certificate.Rekey.Public.Encryption))
				raw, e := vault.EncodeUserEnrollmentCertificate(*certificate)
				if e != nil {
					t.Fatal(e)
				}
				exec("INSERT INTO wormhole_data.user_enrollments(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,certificate) VALUES($1::uuid,$2::uuid,1,$3::uuid,1,decode($4,'hex'))", []byte(f.s.UserID.String()), []byte(f.s.Enrollment.Encryption.ID.String()), []byte(a.Key.ID.String()), hex.AppendEncode(nil, raw))
			}

			state, _ := vault.EncodeUserKeyState(g.account)
			exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", n(g.account.Sequence), hex.AppendEncode(nil, state), []byte(f.s.UserID.String()))
			for _, m := range g.metadata.manifests {
				exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(m.BoundaryID.String()))
				body, _ := vault.EncodeBoundaryManifest(m)
				exec("INSERT INTO wormhole_data.boundary_manifests(boundary_id,version,body,signer_key_id,signer_key_version,signature) VALUES($1::uuid,$2::bigint,decode($3,'hex'),$4::uuid,$5::int,decode($6,'hex'))", []byte(m.BoundaryID.String()), n(m.Revision), hex.AppendEncode(nil, body), []byte(m.Signer.ID.String()), n(uint64(m.Signer.Version)), hex.AppendEncode(nil, m.Signature))
			}
			sealFields := func(boundary uuid.UUID, s vault.RecordSeal) map[string]any {
				return map[string]any{"boundary_id": boundary, "row_version": s.Revision, "seal_suite": 2, "seal_signer_key_id": s.SignerKeyID, "seal_signer_key_version": s.SignerKeyVersion, "seal": hexval(s.Signature)}
			}
			for i := len(f.records.Chain) - 1; i >= 0; i-- {
				r := f.records.Chain[i].Node
				m := r.Metadata
				v := sealFields(r.Boundary, r.Seal)
				for k, x := range map[string]any{"id": m.ID, "parent_id": m.ParentID, "kind": m.Kind, "name": m.Name, "sort_order": 0, "protocol": m.Protocol, "host": m.Host, "username": m.Username, "credential_id": m.CredentialID, "credential_mode": m.CredentialMode, "use_inline_password": m.UseInlinePassword, "tunnel_enabled": m.TunnelEnabled, "tunnel_config_id": m.TunnelConfigID, "rdp_gateway_usage_method": m.RDPGatewayUsageMethod, "rdp_gateway_hostname": m.RDPGatewayHostname, "rdp_gateway_credential_id": m.RDPGatewayCredentialID} {
					v[k] = x
				}
				insert("nodes", v)
			}
			for _, profile := range []*UnverifiedCredentialRecord{f.records.Credential, f.records.Gateway} {
				if profile == nil {
					continue
				}
				r := profile.Credential
				m := r.Record.Metadata
				v := sealFields(r.Boundary, r.Seal)
				for k, x := range map[string]any{"id": m.ID, "name": m.ID, "protocol": m.Protocol, "kind": m.Kind, "username": m.Username, "domain": m.Domain, "provider": m.Provider, "bitwarden_item_id": "", "bitwarden_item_name": "", "bitwarden_field_path": "", "private_key_name": "", "certificate_name": "", "fields": r.Record.Fields, "deleted": false} {
					v[k] = x
				}
				// Store precisely the signed name; tests run in separate rollbacks.
				v["name"] = m.Name
				insert("credential_profiles", v)
			}
			if g.inline != nil {
				r := g.inline.Selection
				record := r.Record.(sharedcatalog.NodeFieldsRecord)
				v := sealFields(r.Boundary, r.Seal)
				v["node_id"], v["fields"], v["deleted"] = record.NodeID, record.Fields, record.Deleted
				insert("node_secret_manifests", v)
			}
			if profile := f.records.Tunnel; profile != nil {
				r := profile.Selection
				record := r.Record.(sharedcatalog.TunnelRecord)
				v := sealFields(r.Boundary, r.Seal)
				v["id"], v["name"], v["kind"], v["configuration_version"], v["deleted"] = record.Metadata.ID, record.Metadata.Name, record.Metadata.Kind, record.ConfigurationVersion, record.Deleted
				insert("tunnel_profiles", v)
			}
			keys := map[vault.KeyRef]bool{}
			openingPrivate := bytes.Repeat([]byte{17}, 32)
			if enrolled {
				keys[f.s.Enrollment.Encryption] = true
				openingPrivate = finalKeys.EncryptionPrivate
			}
			addKey := func(ref vault.KeyRef, kind string) {
				if keys[ref] {
					return
				}
				keys[ref] = true
				exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,$2::int,$3,'pending',2)", []byte(ref.ID.String()), n(uint64(ref.Version)), []byte(kind))
			}
			addCopy := func(copy UnverifiedKeyCopy) {
				b := copy.Binding
				exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,$2::int,$3::uuid,$4::int,2,decode($5,'hex'),decode($6,'hex'),$7::uuid,$8::int,decode($9,'hex'))", []byte(b.Key.ID.String()), n(uint64(b.Key.Version)), []byte(b.Holder.ID.String()), n(uint64(b.Holder.Version)), hex.AppendEncode(nil, copy.Copy.Envelope.Enc), hex.AppendEncode(nil, copy.Copy.Envelope.Ciphertext), []byte(b.Issuer.ID.String()), n(uint64(b.Issuer.Version)), hex.AppendEncode(nil, copy.Copy.Signature))
			}
			for _, copy := range g.roots {
				addKey(copy.Binding.Holder, "user-enc")
				addKey(copy.Binding.Key, "boundary-secret")
				addCopy(copy)
			}
			for _, account := range g.accounts {
				for i, value := range account.values {
					addKey(value.Binding.DEK, "dek")
					addCopy(account.copies[i])
					envelope, _ := vault.EncodeSharedEnvelope(value.Envelope)
					exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) VALUES($7,$1::uuid,$2,$3::uuid,$4::int,decode($5,'hex'),$6::bigint)", []byte(value.Binding.OwnerID.String()), []byte(value.Binding.Field), []byte(value.Binding.DEK.ID.String()), n(uint64(value.Binding.DEK.Version)), hex.AppendEncode(nil, envelope), n(value.Binding.Version), []byte(value.Binding.OwnerKind))
				}
			}
			if fallback != nil {
				installPostgresFallbackTarget(t, ctx, admin, *fallback)
			}
			args := func() ([][]byte, uint64, uint64) {
				r := exec("SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta").Rows[0]
				epoch, _ := strconv.ParseUint(string(r[0]), 10, 64)
				seq, _ := strconv.ParseUint(string(r[1]), 10, 64)
				return [][]byte{[]byte(f.node().String()), []byte(f.s.UserID.String()), r[0], r[1]}, epoch, seq
			}
			params, epoch, seq := args()
			r := exec(credentialReleaseGraphTestSQL, params...)
			got, e := parseCredentialRelease(r.Rows[0][0], AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), epoch, seq)
			if e != nil {
				t.Fatal("real SQL graph", e)
			}
			next, verified, e := f.s.VerifyCredentialRelease(ctx, f.node(), got)
			if e != nil || verified == nil || f.s.ValidateAdvance(next) != nil {
				t.Fatal("real graph verification", e)
			}
			if f.records.Tunnel != nil {
				expectedSettings := []byte("tunnel-secret")
				if fallback != nil {
					expectedSettings = fallback.primary
				}
				var settings []byte
				if err := verified.WithTunnelValues(ctx, next, openingPrivate, func(_ resolver.Plan, values CredentialReleaseValues) error {
					if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil || !bytes.Equal(values.Tunnel.Fields["settings"], expectedSettings) {
						t.Fatal("actual SQL settings opening")
					}
					settings = values.Tunnel.Fields["settings"]
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				assertReleaseWiped(t, [][]byte{settings})
				id := []byte(f.records.Tunnel.Selection.Record.(sharedcatalog.TunnelRecord).Metadata.ID)
				for _, mutation := range []string{"configuration_version=0", "configuration_version=row_version+1", "kind=10", "name=''"} {
					script("SAVEPOINT tunnel_constraint")
					r := admin.ExecParams(ctx, "UPDATE wormhole_data.tunnel_profiles SET "+mutation+" WHERE id=$1::uuid", [][]byte{id}, nil, nil, nil).Read()
					var pe *pgconn.PgError
					if !errors.As(r.Err, &pe) || pe.Code != "23514" {
						t.Fatal("tunnel constraint", r.Err)
					}
					script("ROLLBACK TO SAVEPOINT tunnel_constraint; RELEASE SAVEPOINT tunnel_constraint")
				}
				for _, mutation := range []string{"owner", "version", "deleted", "missing"} {
					script("SAVEPOINT tunnel_binding")
					code := "WH010"
					switch mutation {
					case "owner":
						exec("UPDATE wormhole_data.secret_values SET owner_id=$2::uuid WHERE owner_kind='tunnel' AND owner_id=$1::uuid", id, []byte(uuid.NewString()))
					case "version":
						exec("UPDATE wormhole_data.secret_values SET row_version=row_version+1 WHERE owner_kind='tunnel' AND owner_id=$1::uuid", id)
					case "deleted":
						exec("UPDATE wormhole_data.tunnel_profiles SET deleted=true WHERE id=$1::uuid", id)
						code = "WH018"
					case "missing":
						exec("DELETE FROM wormhole_data.tunnel_profiles WHERE id=$1::uuid", id)
						code = "WH018"
					}
					p, _, _ := args()
					script("SAVEPOINT tunnel_deny")
					r := admin.ExecParams(ctx, credentialReleaseGraphTestSQL, p, nil, nil, nil).Read()
					var pe *pgconn.PgError
					if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
						t.Fatal("tunnel graph rejection", mutation, r.Err)
					}
					script("ROLLBACK TO SAVEPOINT tunnel_binding; RELEASE SAVEPOINT tunnel_binding")
				}
			}
			userPrivate, _ := ecdh.X25519().NewPrivateKey(openingPrivate)
			for _, root := range got.roots {
				for _, m := range got.metadata.manifests {
					if root.Binding.Key != m.Secret.Key && (m.PreviousSecret == nil || root.Binding.Key != m.PreviousSecret.Key) {
						continue
					}
					pub := f.s.PublicKey
					if root.Author != nil {
						pub = root.Author.signingPublic()
					}
					seed, e := vault.OpenBoundaryKeyCopy(userPrivate.Bytes(), root.Binding, root.Copy, vault.KeyCopyTrust{Issuer: root.Binding.Issuer, Public: pub}, m, vault.BoundaryTrust{WorkspaceID: f.s.WorkspaceID, BoundaryID: m.BoundaryID, Signer: m.Signer, Organisation: f.s.PublicKey}, vault.BoundarySecret)
					if e != nil || !bytes.Equal(seed, bytes.Repeat([]byte{4}, 32)) {
						t.Fatal("real SQL root copy", e)
					}
					vault.Wipe(seed)
				}
			}
			deny := func(code string, p ...[]byte) {
				t.Helper()
				script("SAVEPOINT graph_deny")
				r := admin.ExecParams(ctx, credentialReleaseGraphTestSQL, p, nil, nil, nil).Read()
				var pe *pgconn.PgError
				if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
					t.Fatal("graph rejection", code, r.Err)
				}
				script("ROLLBACK TO SAVEPOINT graph_deny; RELEASE SAVEPOINT graph_deny")
			}
			stale := append([][]byte(nil), params...)
			stale[3] = []byte("0")
			deny("WH013", stale...)
			for i := range params {
				bad := append([][]byte(nil), params...)
				bad[i] = nil
				deny("22023", bad...)
			}
			if g.inline != nil {
				for _, mutation := range []string{"revision", "boundary", "field-version", "value-owner", "tombstone"} {
					script("SAVEPOINT inline_binding")
					code := "WH010"
					switch mutation {
					case "revision":
						exec("UPDATE wormhole_data.node_secret_manifests SET row_version=row_version+1 WHERE node_id=$1::uuid", []byte(f.node().String()))
					case "boundary":
						exec("UPDATE wormhole_data.node_secret_manifests SET boundary_id=$2::uuid WHERE node_id=$1::uuid", []byte(f.node().String()), []byte(uuid.NewString()))
					case "field-version":
						if len(g.accounts[0].values) == 0 {
							script("ROLLBACK TO SAVEPOINT inline_binding; RELEASE SAVEPOINT inline_binding")
							continue
						}
						exec("UPDATE wormhole_data.secret_values SET row_version=row_version+1 WHERE owner_kind='node' AND owner_id=$1::uuid", []byte(f.node().String()))
					case "value-owner":
						if len(g.accounts[0].values) == 0 {
							script("ROLLBACK TO SAVEPOINT inline_binding; RELEASE SAVEPOINT inline_binding")
							continue
						}
						exec("UPDATE wormhole_data.secret_values SET owner_id=$2::uuid WHERE owner_kind='node' AND owner_id=$1::uuid", []byte(f.node().String()), []byte(uuid.NewString()))
					case "tombstone":
						exec("UPDATE wormhole_data.node_secret_manifests SET deleted=true,fields='[]'::jsonb WHERE node_id=$1::uuid", []byte(f.node().String()))
						code = "WH018"
					}
					p, _, _ := args()
					deny(code, p...)
					script("ROLLBACK TO SAVEPOINT inline_binding; RELEASE SAVEPOINT inline_binding")
				}
			}
			if len(g.roots) > 0 {
				for _, mutation := range []string{"missing-root", "missing-dek", "missing-state", "inline", "tunnel"} {
					script("SAVEPOINT graph_mutation")
					switch mutation {
					case "missing-root":
						exec("DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid", []byte(g.roots[0].Binding.Key.ID.String()))
					case "missing-dek":
						exec("DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid", []byte(g.accounts[0].values[0].Binding.DEK.ID.String()))
					case "missing-state":
						exec("DELETE FROM wormhole_data.user_key_states WHERE user_id=$1::uuid", []byte(f.s.UserID.String()))
					case "inline":
						if g.inline != nil {
							exec("DELETE FROM wormhole_data.node_secret_manifests WHERE node_id=$1::uuid", []byte(f.node().String()))
						} else {
							exec("UPDATE wormhole_data.nodes SET use_inline_password=true WHERE id=$1::uuid", []byte(f.node().String()))
						}
					case "tunnel":
						exec("UPDATE wormhole_data.nodes SET tunnel_enabled=true,tunnel_config_id=$1::uuid WHERE id=$2::uuid", []byte(uuid.NewString()), []byte(f.node().String()))
					}
					p, _, _ := args()
					code := "WH010"
					if mutation == "tunnel" {
						code = "WH018"
					}
					deny(code, p...)
					script("ROLLBACK TO SAVEPOINT graph_mutation; RELEASE SAVEPOINT graph_mutation")
				}
			}
			if mode == "public" || mode == "public-inline" || mode == "public-tunnel" || enrolled || fallback != nil {
				permissions := "2"
				if enrolled {
					permissions = "3"
				}
				exec("INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,"+permissions+")", []byte(f.node().String()), []byte(f.s.UserID.String()))
				for _, account := range g.accounts {
					exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES($1::uuid,$2::uuid,2) ON CONFLICT DO NOTHING", []byte(account.boundary.String()), []byte(f.s.UserID.String()))
				}
				if fallback != nil {
					exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES($1::uuid,$2::uuid,2)", []byte(fallback.parsed.manifest.BoundaryID.String()), []byte(f.s.UserID.String()))
				}
				script("COMMIT")
				if mode == "public-inline" {
					planned, err := native.ConnectionPlan(ctx, f.node())
					if err != nil {
						t.Fatal("inline public planning", err)
					}
					_, resolved, err := f.s.VerifyConnectionPlan(ctx, f.node(), planned)
					if err != nil || resolved.Plan.Credential.Kind != "inline" {
						t.Fatal("inline public plan verification", err)
					}
				} else {
					testPostgresConnectionPlan(t, ctx, admin, native, f, g)
				}
				if mode == "public" {
					t.Run("serial-plan", func(t *testing.T) { testPostgresSerialConnectionPlan(t, ctx, admin, native, f) })
				}
				if enrolled {
					_, epoch, seq := args()
					for _, output := range []string{"escape", "hex"} {
						// Exercise the optional to_jsonb bytea column on the actual
						// native connection, independently of the SQL builder's GUC.
						owned, opCtx, release, err := native.lease(ctx, 0)
						if err != nil {
							t.Fatal(err)
						}
						_, err = owned.(*pgconn.PgConn).Exec(opCtx, "SET bytea_output='"+output+"'").ReadAll()
						release()
						if err != nil {
							t.Fatal(err)
						}
						author, e := native.NodeAuthor(ctx, f.node(), epoch, seq)
						if e != nil || author == nil || author.EnrollmentCertificate == nil || author.Certificate != nil {
							t.Fatal("real enrolled node author", output, e)
						}
						if _, e := f.s.AdvanceCatalog(f.records.Chain[0].Node, *author); e != nil {
							t.Fatal("real enrolled author verification", output, e)
						}
					}
				}
				if fallback != nil {
					testPostgresFallbackRelease(t, ctx, admin, native, *fallback)
				} else {
					testPostgresFetchSecret(t, ctx, admin, native, f, g, openingPrivate)
				}
			}
		})
	}
}
