package sharedpg

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresSetupApplicationFixture(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_SETUP_APPLICATION") != "1" {
		t.Skip("subprocess fixture for the deployment wizard")
	}
	settings, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(admin)
	const role = "wormhole_wizard_dba"
	const database = "wormhole_setup_test"
	// This synthetic password is known to the protected Electron fixture. Only
	// its SCRAM verifier is used in test SQL and the cluster is loopback-only.
	verifier := postgresTestVerifier([]byte("synthetic-wizard-password"))
	for _, sql := range []string{
		"CREATE ROLE " + role + " LOGIN CREATEROLE PASSWORD '" + verifier + "'",
		"GRANT pg_read_all_stats TO " + role + " WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
		"CREATE DATABASE " + database + " OWNER " + role,
	} {
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal("could not prepare synthetic DBA role and database")
		}
	}
	settings.Database = database
	target := map[string]any{"host": settings.Endpoints[0].Host, "port": settings.Endpoints[0].Port, "database": database,
		"caPem": string(settings.CAPEM), "role": role, "schemaVersion": deploy.SchemaVersion}
	withCSR := os.Getenv("WORMHOLE_TEST_SETUP_CSR") == "1"
	withGenerated := os.Getenv("WORMHOLE_TEST_SETUP_GENERATED") == "1"
	if withCSR {
		target["csr"] = string(postgresFixtureCSR(t, postgresFixtureDataDirectory(t, ctx, admin)))
	}
	if err := json.NewEncoder(os.Stdout).Encode(target); err != nil {
		t.Fatal("could not publish public test settings")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 16*1024), 256*1024)
	var rotationLock *pgconn.PgConn
	defer func() {
		if rotationLock != nil {
			closeDeploymentConnection(rotationLock)
		}
	}()
	for scanner.Scan() {
		var command struct {
			Action, WorkspaceID, RoleTag, Digest, BoundaryID string
			HBA                                              string
			CAPEM, ServerPEM, KeyPEM                         string
			CheckInitialRecoveryExport                       bool
			GroupHandoff                                     bool
		}
		if json.Unmarshal(scanner.Bytes(), &command) != nil || deploy.ValidateIdentity(command.RoleTag, command.WorkspaceID) != nil {
			t.Fatal("invalid fixture command")
		}
		if command.Action == "releaseRotationLock" {
			if rotationLock == nil {
				t.Fatal("rotation lock was not held")
			}
			closeDeploymentConnection(rotationLock)
			rotationLock = nil
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"released": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "lockGroupBoundary" {
			if rotationLock != nil {
				t.Fatal("rotation lock is already held")
			}
			var err error
			rotationLock, err = Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			// Verify the newly published roster, then model a group last issued on
			// schema 89. The worker must reconstruct the signed two-member roster.
			if !command.GroupHandoff {
				if _, err := readDeploymentRow(ctx, rotationLock, `UPDATE wormhole_data.groups g SET key_roster=NULL
			    WHERE g.name='Suspension recipients' AND jsonb_array_length(convert_from(g.key_roster,'UTF8')::jsonb)=2
			        AND encode(wormhole_data.group_key_review(g.id,(convert_from(g.key_manifest,'UTF8')::jsonb->>'groupRevision')::bigint,g.key_roster),'base64')
			            =convert_from(g.key_manifest,'UTF8')::jsonb->>'rosterDigest'
			    RETURNING g.id::text`, 1); err != nil {
					t.Fatal("the signed roster for the original group key was not retained", err)
				}
			}
			if _, err := rotationLock.Exec(ctx, "BEGIN").ReadAll(); err != nil {
				t.Fatal(err)
			}
			// Keep the group key itself active until the suspending device exits.
			if command.GroupHandoff {
				if _, err := readDeploymentRow(ctx, rotationLock, `SELECT id::text FROM wormhole_data.groups
				    WHERE name='Suspension recipients' FOR NO KEY UPDATE`, 1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readDeploymentRow(ctx, rotationLock, `SELECT boundary_id::text FROM wormhole_data.boundary_manifests
                WHERE boundary_id=$1::uuid FOR UPDATE`, 1, []byte(command.BoundaryID)); err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"locked": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "checkCustodianHandoff" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			row, err := readDeploymentRow(ctx, conn, `SELECT EXISTS (
			    SELECT FROM wormhole_data.account_suspensions s
			    JOIN wormhole_data.users target ON target.id=s.account_id AND target.disabled
			    JOIN wormhole_data.users issuer ON issuer.id=s.rotation_actor
			    JOIN wormhole_data.workspace_meta m ON m.singleton AND m.epoch=s.rotation_epoch
			    JOIN wormhole_data.account_suspension_roots r ON r.account_id=s.account_id
			    JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(r.root_id,r.root_version)
			    JOIN wormhole_data.audit_log a ON a.access_account_id=target.id AND a.admin_boundary_id=r.boundary_id
			    JOIN wormhole_data.users custodian ON custodian.id=a.user_id
			    WHERE issuer.login_name='first-admin' AND custodian.login_name='recovered-admin'
			        AND target.login_name='restart-test-account' AND target.row_version=s.revision
			        AND octet_length(s.rotation_signature)=64 AND k.status='retired'
			        AND a.action='account_boundary_rotation' AND a.outcome='success')::text`, 1)
			closeDeploymentConnection(conn)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("the second custodian did not retire the key for the signed suspension", err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "checkSuspendedGroupRotation" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			row, err := readDeploymentRow(ctx, conn, `WITH rotation AS (
                SELECT j.* FROM wormhole_data.group_member_rotation_jobs j
                JOIN wormhole_data.groups g ON g.id=j.group_id AND g.name='Suspension recipients'
                    AND jsonb_array_length(convert_from(g.key_roster,'UTF8')::jsonb)=1
                    AND encode(wormhole_data.group_key_review(g.id,(convert_from(g.key_manifest,'UTF8')::jsonb->>'groupRevision')::bigint,g.key_roster),'base64')
                        =convert_from(g.key_manifest,'UTF8')::jsonb->>'rosterDigest'
                JOIN wormhole_data.users u ON u.id=j.removed_user_id AND u.login_name='recovered-admin' AND u.disabled
                WHERE j.complete
            ), recipients AS (
                SELECT u.login_name FROM rotation j
                JOIN wormhole_data.key_copies c ON c.key_id=j.key_id AND c.key_version=j.retired_version+1
                JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version) AND k.kind='user-enc'
                JOIN wormhole_data.users u ON u.id=k.owner_id
            ), roots AS (
                SELECT r.* FROM rotation j JOIN wormhole_data.account_suspension_roots r
                ON r.account_id=j.removed_user_id AND j.group_id=ANY(r.groups)
            )
            SELECT ((SELECT count(*) FROM rotation)=1
                AND (SELECT count(*) FROM recipients)=1 AND EXISTS (SELECT FROM recipients WHERE login_name='first-admin')
                AND EXISTS (SELECT FROM rotation j JOIN wormhole_data.keys k
                    ON (k.key_id,k.key_version)=(j.key_id,j.retired_version) AND k.status='retired')
                AND (SELECT count(DISTINCT purpose) FROM roots)=2
                AND (NOT $1::boolean OR EXISTS (
                    SELECT FROM rotation j JOIN wormhole_data.account_suspensions s ON s.account_id=j.removed_user_id
                    JOIN wormhole_data.users issuer ON issuer.id=s.rotation_actor AND issuer.login_name='group-issuer'
                    JOIN wormhole_data.users subject ON subject.id=s.account_id AND subject.disabled AND subject.row_version=s.revision
                    JOIN wormhole_data.workspace_meta m ON m.singleton AND m.epoch=s.rotation_epoch
                    JOIN wormhole_data.users actor ON actor.login_name='first-admin'
                    WHERE octet_length(s.rotation_signature)=64
                    AND EXISTS (SELECT FROM wormhole_data.audit_log a WHERE a.action='group_member_rotation' AND a.outcome='success'
                        AND (a.user_id,a.admin_group_id,a.admin_subject_id)=(actor.id,j.group_id,subject.id))
                    AND NOT EXISTS (SELECT FROM roots r WHERE NOT EXISTS (SELECT FROM wormhole_data.audit_log a
                        WHERE a.action='member_boundary_rotation' AND a.outcome='success'
                        AND (a.user_id,a.admin_group_id,a.admin_subject_id,a.admin_boundary_id)=(actor.id,j.group_id,subject.id,r.boundary_id)))))
                AND NOT EXISTS (SELECT FROM roots r WHERE NOT EXISTS (SELECT FROM wormhole_data.keys k
                    WHERE (k.key_id,k.key_version)=(r.root_id,r.root_version) AND k.status='retired')
                    OR NOT EXISTS (SELECT FROM wormhole_data.keys k
                    JOIN wormhole_data.key_copies c USING (key_id,key_version)
                    JOIN rotation j ON (c.holder_key_id,c.holder_key_version)=(j.key_id,j.retired_version+1)
                    WHERE k.key_id=r.root_id AND k.key_version>r.root_version AND k.status='active')))::text`, 1, []byte(strconv.FormatBool(command.GroupHandoff)))
			closeDeploymentConnection(conn)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("group rotation did not retire both roots and retain only the certified account", err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "seedSuspensionAccount" || command.Action == "seedBlockedRotation" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			login := "restart-test-account"
			if command.Action == "seedSuspensionAccount" {
				login = "rotation-test-account"
				result := conn.ExecParams(ctx, `INSERT INTO wormhole_data.users(id,login_name)
                VALUES(gen_random_uuid(),'suspension-test-account')`, nil, nil, nil, nil).Read()
				if result.Err != nil || result.CommandTag.RowsAffected() != 1 {
					t.Fatal("could not prepare a workspace account for suspension review", result.Err)
				}
			}
			// Give a second synthetic account a recorded route to an existing shared
			// root. The fixture never admits that account. Publication must remove
			// this copy and authenticate all real, retained recipients independently.
			route := conn.ExecParams(ctx, `WITH subject AS (
                INSERT INTO wormhole_data.users(id,login_name) VALUES(gen_random_uuid(),$1::text) RETURNING id
            ), holder AS (
                INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite)
                SELECT gen_random_uuid(),1,'user-enc',id,2 FROM subject RETURNING key_id,key_version
            ), existing AS (
                SELECT c.* FROM wormhole_data.key_copies c JOIN wormhole_data.keys root USING(key_id,key_version)
                JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
                JOIN wormhole_data.boundaries b ON b.id=root.owner_id
                WHERE root.kind='boundary-secret' AND root.status='active' AND b.owner_user_id IS NULL AND h.kind='org-enc'
                ORDER BY root.key_id LIMIT 1
            )
            INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,
                enc,ciphertext,issuer_key_id,issuer_key_version,signature)
            SELECT e.key_id,e.key_version,h.key_id,h.key_version,e.suite,e.enc,e.ciphertext,e.issuer_key_id,e.issuer_key_version,e.signature
                FROM existing e CROSS JOIN holder h RETURNING key_id::text`, [][]byte{[]byte(login)}, nil, nil, nil).Read()
			if route.Err != nil || route.CommandTag.RowsAffected() != 1 {
				t.Fatal("could not prepare the account rotation fixture", route.Err)
			}
			if command.Action == "seedBlockedRotation" {
				rotationLock = conn
				if _, err := conn.Exec(ctx, "BEGIN").ReadAll(); err != nil {
					t.Fatal(err)
				}
				// Rotation takes a shared lock on this manifest. Inventory and
				// suspension can still commit while publication returns busy.
				if _, err := readDeploymentRow(ctx, conn, `SELECT m.boundary_id::text FROM wormhole_data.boundary_manifests m
					JOIN wormhole_data.keys k ON k.owner_id=m.boundary_id
					WHERE k.key_id=$1::uuid FOR UPDATE OF m`, 1, route.Rows[0][0]); err != nil {
					t.Fatal(err)
				}
			} else {
				closeDeploymentConnection(conn)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "checkLocalImport" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			row, err := readDeploymentRow(ctx, conn, `SELECT (
    (SELECT count(*) FROM wormhole_data.workspace_import_receipts WHERE approval IS NOT NULL AND approval_signature IS NOT NULL)=1
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='commit_workspace_import')=1
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='begin_note_view')=1
    AND (SELECT count(*) FROM wormhole_data.audit_log a JOIN wormhole_data.nodes n ON n.id=a.node_id
        WHERE a.action='node_grant_change' AND a.admin_grant_subject_kind='group' AND n.name='Shared grant folder')=2
    AND (SELECT count(*) FROM wormhole_data.audit_log a JOIN wormhole_data.groups g ON g.id=a.admin_group_id
        WHERE a.action='group_key_provision' AND g.name='Certified operators' AND g.key_manifest IS NOT NULL)=1
    AND (SELECT wormhole_data.group_keys_recoverable(workspace_id) FROM wormhole_data.workspace_meta WHERE singleton)
    AND EXISTS(SELECT FROM wormhole_data.nodes n JOIN wormhole_data.boundaries b ON b.id=n.boundary_id
        JOIN wormhole_data.secret_values v ON v.owner_kind='node' AND v.owner_id=n.id AND v.field='notes'
        WHERE n.owner_user_id IS NOT NULL AND n.owner_user_id=b.owner_user_id AND n.imported->'noteVersion'='1'::jsonb)
)::text`, 1)
			closeDeploymentConnection(conn)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("the wizard did not atomically import the selected personal note and audit its display", err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal("could not publish import verification", err)
			}
			continue
		}
		if command.Action == "enableAccountReset" || command.Action == "checkAccountResetIssued" {
			if command.Action == "enableAccountReset" {
				if _, err := admin.Exec(ctx, "ALTER DATABASE "+database+" SET log_parameter_max_length=0; ALTER DATABASE "+database+" SET log_parameter_max_length_on_error=0").ReadAll(); err != nil {
					t.Fatal("could not configure synthetic reset database", err)
				}
			} else {
				conn, err := Connect(ctx, settings, secret)
				if err != nil {
					t.Fatal(err)
				}
				row, err := readDeploymentRow(ctx, conn, `SELECT (
 (SELECT count(DISTINCT u.id) FROM wormhole_data.account_reset_offers o JOIN wormhole_data.users u
 ON u.id=o.user_id JOIN pg_catalog.pg_roles r ON r.oid=o.role_oid
 JOIN wormhole_data.users custodian ON custodian.id=o.handed_over_by
 WHERE u.login_name IN ('first-admin','recovered-admin') AND o.retired_at IS NULL AND r.rolcanlogin
       AND o.handed_over_at IS NOT NULL AND custodian.login_name='first-admin')=2
 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='publish_account_reset' AND outcome='issued')=2
 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='mark_account_reset_handover' AND outcome='handed_over')=2
 AND EXISTS(SELECT FROM wormhole_data.devices WHERE status='active')
)::text`, 1)
				closeDeploymentConnection(conn)
				if err != nil || len(row) != 1 || string(row[0]) != "true" {
					t.Fatal("application reset issue or audit was not committed exactly once", err)
				}
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal("could not publish reset fixture verification", err)
			}
			continue
		}
		if command.Action == "deployRestoreTarget" || command.Action == "checkRestoredWorkspace" {
			if command.Action == "deployRestoreTarget" {
				if _, err := DeploySchema(ctx, settings, secret, command.RoleTag, command.WorkspaceID); err != nil {
					t.Fatal("could not prepare a restore fixture", err)
				}
			}
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			if command.Action == "deployRestoreTarget" {
				deployer := "wh_" + command.RoleTag + "_deployer"
				for _, sql := range []string{
					"ALTER ROLE " + deployer + " PASSWORD '" + verifier + "'",
					"ALTER ROLE " + deployer + " SET log_parameter_max_length=0",
					"ALTER ROLE " + deployer + " SET log_parameter_max_length_on_error=0",
				} {
					if _, err := conn.Exec(ctx, sql).ReadAll(); err != nil {
						t.Fatal("could not enable synthetic restore deployer", err)
					}
				}
			} else if row, err := readDeploymentRow(ctx, conn, `SELECT (
    (SELECT count(*) FROM wormhole_data.users WHERE login_name='first-admin' AND is_admin AND NOT disabled)=1
    AND NOT EXISTS(SELECT FROM wormhole_data.account_auth)
    AND NOT EXISTS(SELECT FROM wormhole_data.devices)
    AND NOT EXISTS(SELECT FROM wormhole_data.invites)
    AND EXISTS(SELECT FROM wormhole_data.workspace_meta WHERE singleton AND state='ready' AND epoch>1)
    AND (SELECT count(*) FROM wormhole_data.key_copies c
         JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
         JOIN wormhole_data.user_enrollments e ON (e.signing_key_id,e.signing_key_version)=(c.issuer_key_id,c.issuer_key_version)
         WHERE h.kind='org-enc' AND h.cert_signature IS NOT NULL
           AND (c.key_id,c.key_version) IN ((e.encryption_key_id,e.encryption_key_version),(e.signing_key_id,e.signing_key_version)))=2
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='restore_workspace')=1
)::text`, 1); err != nil || string(row[0]) != "true" {
				t.Fatal("application restore did not preserve the expected boundary", err)
			}
			closeDeploymentConnection(conn)
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal("could not publish fixture restore verification")
			}
			continue
		}
		if command.Action == "enableRecoveryDeployer" || command.Action == "checkRecoveryAdministrator" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			if command.Action == "enableRecoveryDeployer" {
				// The role tag was accepted by ValidateIdentity. The fixture's
				// synthetic password is used by the isolated Electron harness.
				_, err = conn.Exec(ctx, "ALTER ROLE wh_"+command.RoleTag+"_deployer PASSWORD '"+verifier+"'").ReadAll()
			} else {
				row, readErr := readDeploymentRow(ctx, conn, `SELECT (EXISTS(
    SELECT FROM wormhole_data.users u JOIN wormhole_data.devices d ON d.user_id=u.id
    WHERE u.login_name='recovered-admin' AND u.is_admin AND NOT u.disabled AND d.status='active'
 ) AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='break_glass_recovery')=1
   AND (SELECT count(*) FROM wormhole_data.workspace_admin_recovery)=1)::text`, 1)
				if readErr != nil || len(row) != 1 || string(row[0]) != "true" {
					t.Fatal("recovery administrator, enrollment or audit mismatch", readErr)
				}
			}
			closeDeploymentConnection(conn)
			if err != nil || json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}) != nil {
				t.Fatal("administrator recovery fixture could not confirm its state", err)
			}
			continue
		}
		if withCSR && command.Action == "damageRecoveryRecipient" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			update := conn.ExecParams(ctx, `UPDATE wormhole_data.keys
SET cert_signature=pg_catalog.decode(pg_catalog.repeat('00',64),'hex')
WHERE kind='org-enc' AND status='active' AND cert_signature IS NOT NULL`, nil, nil, nil, nil).Read()
			closeDeploymentConnection(conn)
			if update.Err != nil || update.CommandTag.RowsAffected() != 1 {
				t.Fatal("could not alter the synthetic recovery recipient", update.Err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
				t.Fatal("could not publish fixture custody status")
			}
			continue
		}
		if withCSR && (command.Action == "demoteFixtureAdmin" || command.Action == "restoreFixtureAdmin") {
			demote := command.Action == "demoteFixtureAdmin"
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			value := "true"
			if demote {
				value = "false"
			}
			update := conn.ExecParams(ctx, "UPDATE wormhole_data.users SET is_admin=$1::boolean WHERE login_name='first-admin'", [][]byte{[]byte(value)}, nil, nil, nil).Read()
			closeDeploymentConnection(conn)
			if update.Err != nil || update.CommandTag.RowsAffected() != 1 {
				t.Fatal("could not change the fixture user's administrative role", update.Err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"demoted": demote}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "installTLS" {
			if (!withCSR && !withGenerated) || !validDeploymentCABundle([]byte(command.CAPEM)) {
				t.Fatal("invalid fixture TLS install")
			}
			data := postgresFixtureDataDirectory(t, ctx, admin)
			if withGenerated {
				installGeneratedFixtureKey(t, data, command.KeyPEM)
			}
			if err := os.WriteFile(filepath.Join(data, "server.crt"), []byte(command.ServerPEM), 0600); err != nil {
				t.Fatal("fixture certificate write failed")
			}
			settings.CAPEM = []byte(command.CAPEM)
			pinned, err := PinDeploymentServerCertificate(settings, command.ServerPEM)
			if err != nil {
				t.Fatal("fixture could not pin the requested leaf certificate", err)
			}
			reloadPostgresFixtureTLS(t, ctx, admin, pinned, secret)
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"installed": true}); err != nil {
				t.Fatal("fixture TLS confirmation unavailable")
			}
			continue
		}
		if withCSR && command.Action == "rotationCA" {
			inspect, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			result := inspect.ExecParams(ctx, `SELECT pg_catalog.convert_from(tls_bundle,'UTF8') FROM wormhole_data.workspace_meta WHERE singleton`, nil, nil, nil, nil).Read()
			closeDeploymentConnection(inspect)
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("could not read rotation overlap", result.Err)
			}
			bundle, err := DecodeTLSTrustBundle(result.Rows[0][0])
			if err != nil || bundle.Sequence != 2 || bundle.WorkspaceCA == nil || bundle.WorkspaceCA.PreviousCA == "" {
				t.Fatal("rotation overlap was not published", err)
			}
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bundle.workspaceIssuer()})
			if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"caPem": string(cert)}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "installHBA" {
			expected, err := DeploymentHBARules(database, command.RoleTag, command.WorkspaceID, []string{"127.0.0.1", "::1"})
			if err != nil || expected != command.HBA {
				t.Fatal("unexpected desktop HBA export", err)
			}
			installFixtureHBARules(t, ctx, admin, database, command.RoleTag, command.HBA)
			if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"installed": true}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if command.Action == "enableRowSecurity" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			// Role tag and workspace UUID are validated before dispatch.
			_, err = conn.Exec(ctx, "BEGIN; SET LOCAL ROLE wh_"+command.RoleTag+"_owner; SELECT wormhole_data.set_row_security('"+command.WorkspaceID+"',true); COMMIT").ReadAll()
			closeDeploymentConnection(conn)
			if err != nil || json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}) != nil {
				t.Fatal("could not enable workspace row security", err)
			}
			continue
		}
		if command.Action == "changeRoutineConfiguration" || command.Action == "restoreRoutineConfiguration" {
			conn, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			option := "RESET application_name"
			if command.Action == "changeRoutineConfiguration" {
				option = "SET application_name='catalog-fixture'"
			}
			_, err = conn.Exec(ctx, "ALTER FUNCTION wormhole_api_v1.unencrypted_clients(bytea,uuid) "+option).ReadAll()
			closeDeploymentConnection(conn)
			if err != nil || json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}) != nil {
				t.Fatal("could not change fixture routine configuration", err)
			}
			continue
		}
		if command.Action == "applyExport" {
			script, err := deploy.SchemaScript(command.RoleTag, command.WorkspaceID)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(script))
			if hex.EncodeToString(digest[:]) != command.Digest {
				t.Fatal("app export differs from the expected workspace script")
			}
			exporter := settings
			exporter.DeviceRole = role
			conn, err := Connect(ctx, exporter, []byte("synthetic-wizard-password"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Exec(ctx, script).ReadAll()
			closeDeploymentConnection(conn)
			if err != nil {
				t.Fatal("fixture could not apply exported schema")
			}
		} else if command.Action != "check" && command.Action != "checkUnpublished" && command.Action != "checkAdministrator" {
			t.Fatal("unexpected setup fixture action")
		}
		state, err := CheckSchemaDeployment(ctx, settings, secret, command.RoleTag, command.WorkspaceID)
		wantProvisioning := command.Action != "checkAdministrator"
		if err != nil || state.Provisioning != wantProvisioning || !state.RequiresTLS {
			t.Fatal("independent schema verification failed", err)
		}
		if command.Action == "checkUnpublished" || command.Action == "checkAdministrator" {
			inspect, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			query := `SELECT (NOT EXISTS(SELECT FROM wormhole_data.users) AND NOT EXISTS(SELECT FROM wormhole_data.workspace_bootstrap))::text`
			if command.Action == "checkAdministrator" {
				query = `SELECT (
 (SELECT count(*) FROM wormhole_data.users WHERE is_admin AND NOT disabled)=1
 AND (SELECT count(*) FROM wormhole_data.workspace_bootstrap WHERE singleton)=1
 AND (SELECT count(*) FROM wormhole_data.invites WHERE used_at IS NOT NULL AND bootstrap_envelope IS NULL)=1
 AND (SELECT count(*) FROM wormhole_data.device_confirmations)=1
 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='bootstrap_workspace')=1
 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='join_workspace')=1
 AND NOT EXISTS(SELECT FROM wormhole_data.invitation_logins WHERE NOT revoked)
)::text`
				if withCSR || withGenerated {
					query = `SELECT ((` + query + `)::boolean AND EXISTS(
 SELECT FROM wormhole_data.workspace_bootstrap
 WHERE pg_catalog.convert_from(recovery_capsule,'UTF8')::jsonb->>'version'='2'
   AND pg_catalog.convert_from(recovery_capsule,'UTF8')::jsonb->'ca'->'copy'->>'signature' IS NOT NULL
 ) AND EXISTS(
 SELECT FROM wormhole_data.workspace_meta
 WHERE pg_catalog.convert_from(tls_bundle,'UTF8')::jsonb->'hosts'='["127.0.0.1","db.example.test"]'::jsonb
))::text`
				}
				if withCSR {
					query = `SELECT ((` + query + `)::boolean
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='export_workspace' AND outcome='recovery_snapshot_released')=1
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='store_account_recovery' AND outcome='escrow_written')=1
)::text`
				}
				if withCSR && command.CheckInitialRecoveryExport {
					query = `SELECT ((` + query + `)::boolean
 AND (SELECT tls_sequence=1 FROM wormhole_data.workspace_meta WHERE singleton)
)::text`
				}
				if withCSR && !command.CheckInitialRecoveryExport {
					query = `SELECT ((` + query + `)::boolean
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='server_certificate_renewal' AND outcome='key_copy_released')=2
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='server_ca_rotation' AND outcome='publish_overlap')=1
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='server_ca_rotation' AND outcome='retire_previous')=1
 AND (SELECT count(*) FROM wormhole_data.audit_log
      WHERE action='workspace_recovery_kit_refresh' AND outcome='key_copy_released')=3
 AND (SELECT tls_sequence=3 AND pg_catalog.jsonb_array_length(pg_catalog.convert_from(tls_bundle,'UTF8')::jsonb->'cas')=1
      FROM wormhole_data.workspace_meta WHERE singleton)
)::text`
				}
			}
			row, err := readDeploymentRow(ctx, inspect, query, 1)
			closeDeploymentConnection(inspect)
			if err != nil || string(row[0]) != "true" {
				t.Fatal("unexpected bootstrap transaction or device confirmation state", err)
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(state.SchemaDeployment); err != nil {
			t.Fatal("could not publish public schema status")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func installGeneratedFixtureKey(t *testing.T, data, key string) {
	t.Helper()
	block, remaining := pem.Decode([]byte(key))
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(remaining) != 0 {
		t.Fatal("fixture did not receive an encrypted PKCS#8 key")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("could not locate synthetic passphrase helper")
	}
	command := `"` + executable + `" -test.run=TestPostgresSetupPassphraseFixture`
	command = strings.NewReplacer(`\`, `\\`, "'", "''").Replace(command)
	config, err := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("could not configure fixture passphrase helper")
	}
	_, writeErr := config.WriteString("\nssl_passphrase_command = '" + command + "'\nssl_passphrase_command_supports_reload = on\n")
	closeErr := config.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("could not persist fixture passphrase helper")
	}
	if err := os.WriteFile(filepath.Join(data, "server.key"), []byte(key), 0600); err != nil {
		t.Fatal("fixture key installation failed")
	}
}

// This entry point is available only in the opt-in fixture's test executable.
// PostgreSQL loads the synthetic passphrase from stdout without a persisted
// plaintext passphrase or one embedded in its command line.
func TestPostgresSetupPassphraseFixture(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_SETUP_GENERATED") != "1" {
		t.Skip("subprocess for the encrypted server key fixture")
	}
	value := os.Getenv("WORMHOLE_TEST_SETUP_KEY_PASSPHRASE")
	if value == "" {
		os.Exit(1)
	}
	if _, err := io.WriteString(os.Stdout, value+"\n"); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
