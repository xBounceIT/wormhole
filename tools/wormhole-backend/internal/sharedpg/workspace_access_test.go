package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresWorkspaceAccess(t *testing.T) {
	settings, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	workspace := uuid.New()
	const tag = "workaccess"
	if _, err := DeploySchema(ctx, settings, secret, tag, workspace.String()); err != nil {
		t.Fatal(err)
	}
	draft, factors, err := prepareWorkspaceBootstrapFromDeployment(ctx, settings, secret, workspace, tag, "first-admin", vault.Standard, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer factors.wipe()
	if _, err := publishWorkspaceBootstrap(ctx, draft, settings.DeviceRole, secret, factors.invitationCode[:]); err != nil {
		t.Fatal(err)
	}
	dba, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(dba)
	ask := bytes.Repeat([]byte{84}, 32)
	defer vault.Wipe(ask)
	joinTestAdministrator(t, ctx, draft.invitation, factors.invitationCode[:], draft.organisation.Signing, draft.recovery.Signing, ask, nil,
		func(admin *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) {
			if supported, err := admin.WorkspaceAccessSupported(ctx); err != nil || !supported {
				t.Fatal("access capability unavailable", err)
			}
			account, device := uuid.NewString(), uuid.NewString()
			roleName := "wh_" + tag + "_d_" + device
			role := pgx.Identifier{roleName}.Sanitize()
			material := vault.NewRecoveryKey()
			defer vault.Wipe(material)
			login, err := EncodeLoginSecret(material)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(login)
			verifier, err := NewSCRAMVerifier(material)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(verifier)
			exec := func(statement string) {
				t.Helper()
				if _, err := dba.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatal("fixture command failed", err)
				}
			}
			exec("SET ROLE wh_" + tag + "_owner; CREATE ROLE " + role + " LOGIN NOINHERIT PASSWORD '" + string(verifier) +
				"'; GRANT wh_" + tag + "_user TO " + role + " WITH INHERIT TRUE, SET FALSE; RESET ROLE")
			exec("INSERT INTO wormhole_data.users(id,login_name,name) VALUES ('" + account + "','test-member','Member name'); " +
				"INSERT INTO wormhole_data.devices(id,user_id,role_name,name,status) VALUES ('" + device + "','" + account + "','" + roleName + "','Member device','active')")
			offer := uuid.NewString()
			resetRole := "wh_" + tag + "_r_" + offer
			exec("SET ROLE wh_" + tag + "_owner; CREATE ROLE " + pgx.Identifier{resetRole}.Sanitize() + " LOGIN NOINHERIT; RESET ROLE")
			exec(`INSERT INTO wormhole_data.account_reset_offers(id,user_id,issuer_id,role_oid,role_name,expires_at,subject,
				offer_hash,commit_hash,policy_hash,tls_hash,capsule)
				SELECT '` + offer + `','` + account + `','` + trust.UserID.String() + `',oid,rolname,now()+interval '1 hour','{}',
				decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),
				decode(repeat('00',32),'hex'),decode(repeat('00',16),'hex')
				FROM pg_catalog.pg_roles WHERE rolname='` + resetRole + `'`)
			seed := dba.ExecParams(ctx, `INSERT INTO wormhole_data.account_auth(user_id,auth_epoch,iterations,salt,stored_key,server_key)
				SELECT $1::uuid,1,iterations,salt,stored_key,server_key FROM wormhole_data.parse_scram_verifier($2)`,
				[][]byte{[]byte(account), verifier}, nil, nil, nil).Read()
			if seed.Err != nil {
				t.Fatal("could not set native proof for member", seed.Err)
			}
			memberSettings := Settings{Endpoints: settings.Endpoints, Database: settings.Database, DeviceRole: roleName, TLS: TLSVerified, TLSBundle: tls, Profile: vault.Standard}
			admit := func() *Session {
				t.Helper()
				member := NewSession()
				t.Cleanup(func() { _ = member.Close(context.Background()) })
				if err := member.Open(ctx, memberSettings, login, ChangePolicy{TransactionPooler: true}); err != nil {
					t.Fatal("member PostgreSQL login failed", err)
				}
				result, err := member.AuthenticateSession(ctx, AdmissionRequest{WorkspaceID: workspace, UserID: uuid.MustParse(account), DeviceID: uuid.MustParse(device),
					API: 1, AppVersion: "2.4.3", Source: "ui"}, material)
				if err != nil || result.IsAdmin {
					t.Fatal("member credential proof failed", err)
				}
				return member
			}
			member := admit()
			resident, err := Connect(ctx, memberSettings, login)
			if err != nil {
				t.Fatal("could not keep a second PostgreSQL connection open", err)
			}
			defer closeDeploymentConnection(resident)
			var oldCapability []byte
			if err := member.capability.With(func(value []byte) error {
				oldCapability = hex.AppendEncode(nil, value)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(oldCapability)
			residentCheck := func(wantSQLState string) {
				t.Helper()
				result := resident.ExecParams(ctx, `SELECT * FROM wormhole_api_v1.admin_inventory(pg_catalog.decode($1,'hex'),'accounts',NULL,NULL)`,
					[][]byte{oldCapability}, nil, nil, nil).Read()
				if !hasSQLState(result.Err, wantSQLState, 0) {
					t.Fatal("resident connection unexpectedly accepted the original capability", result.Err)
				}
			}
			call := func(request WorkspaceAccessRequest, want string) WorkspaceAccessReply {
				t.Helper()
				result, err := admin.WorkspaceAccess(ctx, trust, request)
				if err != nil || result.Status != want || (result.Review != nil) != (want == "review") {
					t.Fatalf("%s returned %q, wanted %q: %v", request.Action, result.Status, want, err)
				}
				return result
			}
			call(WorkspaceAccessRequest{Action: "disable-account", TargetID: trust.UserID.String()}, "unavailable")
			disable := WorkspaceAccessRequest{Action: "disable-account", TargetID: account}
			review := call(disable, "review").Review
			if review.Login != "test-member" || review.Name != "Member name" || review.CurrentDevice {
				t.Fatal("review identifies the wrong account")
			}
			call(WorkspaceAccessRequest{Action: disable.Action, TargetID: account, Revision: "2"}, "stale")
			// A target operation holding an account lock wins. Suspension waits for
			// a new review/confirmation and leaves all current admissions intact.
			exec("BEGIN; SELECT 1 FROM wormhole_data.users WHERE id='" + account + "' FOR SHARE")
			call(review.WorkspaceAccessRequest, "busy")
			exec("ROLLBACK")
			epochFromDB, err := readDeploymentRow(ctx, dba, "SELECT epoch::text FROM wormhole_data.workspace_meta WHERE singleton", 1)
			if err != nil {
				t.Fatal(err)
			}
			epoch, err := strconv.ParseInt(string(epochFromDB[0]), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			pin, err := trust.AccountTrust()
			if err != nil {
				t.Fatal(err)
			}
			if accounts, err := admin.ReadSuspensionReceipts(ctx, pin, epoch, uuid.Nil); err != nil || len(accounts) != 0 {
				t.Fatal("initial suspension receipt discovery", err)
			}
			// A rejected proof ends the native session using that connection.
			// Exercise the rollback through a second, independently owned socket.
			probe, err := Connect(ctx, settings, secret)
			if err != nil {
				t.Fatal(err)
			}
			defer closeDeploymentConnection(probe)
			actorRole := pgx.Identifier{"wh_" + tag + "_d_" + trust.DeviceID.String()}.Sanitize()
			if _, err := probe.Exec(ctx, "SET SESSION AUTHORIZATION "+actorRole).ReadAll(); err != nil {
				t.Fatal(err)
			}
			state, err := vault.EncodeUserKeyState(*trust.Account)
			if err != nil {
				t.Fatal(err)
			}
			stateHash := sha256.Sum256(state)
			err = admin.capability.With(func(value []byte) error {
				capability := hex.AppendEncode(nil, value)
				defer vault.Wipe(capability)
				args := [][]byte{capability, []byte(account), []byte(review.Revision), epochFromDB[0], bytes.Repeat([]byte("00"), 64),
					hex.AppendEncode(nil, trust.PolicyDigest), hex.AppendEncode(nil, stateHash[:])}
				return probe.ExecParams(ctx, signedSuspensionSQL, args, nil, nil, nil).Read().Err
			})
			if !hasSQLState(err, "WH023", 0) {
				t.Fatal("expected the database to reject an unsigned suspension", err)
			}
			if got := call(disable, "review").Review; got.Revision != review.Revision {
				t.Fatal("invalid signature changed the target")
			}
			signed, err := admin.SuspendWithReceipt(ctx, trust, tls, epoch, review.WorkspaceAccessRequest, keys)
			if err != nil || signed.Status != "changed" {
				t.Fatal("signed suspension", signed.Status, err)
			}
			stored := dba.ExecParams(ctx, `SELECT rotation_actor::text,account_id::text,revision::text,encode(rotation_signature,'hex')
			    FROM wormhole_data.account_suspensions WHERE account_id=$1::uuid`, [][]byte{[]byte(account)}, nil, nil, nil).Read()
			if stored.Err != nil || len(stored.Rows) != 1 {
				t.Fatal("missing suspension receipt", stored.Err)
			}
			accounts, err := verifySuspensionReceipts(stored.Rows, pin, epoch, uuid.Nil)
			if err != nil || len(accounts) != 1 || accounts[0].ID.String() != account {
				t.Fatal("stored receipt failed independent verification", err)
			}
			if supported, err := admin.AccountSuspensionSupported(ctx); err != nil || !supported {
				t.Fatal("account suspension inventory capability missing", err)
			}
			scope, err := admin.AccountSuspensionInventory(ctx, trust, AccountSuspensionRequest{AccountID: account, Kind: "roots"})
			if err != nil || scope.Page == nil || len(scope.Page.Entries) != 0 {
				t.Fatal("an account with no certified keys had a nonempty inventory", scope.Status, err)
			}
			// Exercise receipt discovery independently of the rotation worker. Keep
			// a real boundary key pending while the account, cursor and role vary.
			pending := dba.ExecParams(ctx, `INSERT INTO wormhole_data.account_suspension_roots
			    (account_id,position,boundary_id,purpose,root_id,root_version,held_directly,groups)
			    SELECT $1::uuid,1,k.owner_id,2,k.key_id,k.key_version,true,'{}'::uuid[] FROM wormhole_data.keys k
			    JOIN wormhole_data.boundaries b ON b.id=k.owner_id AND b.owner_user_id IS NULL
			    WHERE k.kind='boundary-secret' AND k.status='active' ORDER BY k.key_id LIMIT 1`,
				[][]byte{[]byte(account)}, nil, nil, nil).Read()
			if pending.Err != nil || pending.CommandTag.RowsAffected() != 1 {
				t.Fatal("could not stage a pending boundary", pending.Err)
			}
			subject := uuid.MustParse(account)
			discover := func(workspaceEpoch int64, cursor uuid.UUID, want bool) {
				t.Helper()
				page, err := admin.ReadSuspensionReceipts(ctx, pin, workspaceEpoch, cursor)
				if err != nil || (want && (len(page) != 1 || page[0] != accounts[0])) || (!want && len(page) != 0) {
					t.Fatal("unexpected discovery for epoch, cursor and current account role", workspaceEpoch, cursor, want, err)
				}
			}
			discover(epoch, uuid.Nil, true)
			discover(epoch, subject, false)
			discover(epoch+1, uuid.Nil, false)
			exec("UPDATE wormhole_data.users SET is_admin=false WHERE id='" + trust.UserID.String() + "'")
			discover(epoch, uuid.Nil, false)
			exec("UPDATE wormhole_data.users SET is_admin=true WHERE id='" + trust.UserID.String() + "'")
			discover(epoch, uuid.Nil, true)
			exec("DELETE FROM wormhole_data.account_suspensions WHERE account_id='" + account + "'")
			scope, err = admin.AccountSuspensionInventory(ctx, trust, AccountSuspensionRequest{AccountID: account, Kind: "roots"})
			if err != nil || scope.Status != "not-recorded" {
				t.Fatal("a pre-migration suspension looked like a recorded empty inventory", scope.Status, err)
			}
			if _, err := member.AdminInventory(ctx, AdminInventoryRequest{Kind: "accounts"}); !errors.Is(err, ErrIdentityUnavailable) {
				t.Fatal("an already admitted member survived suspension", err)
			}
			residentCheck("WH001")
			check := func(sql string) {
				t.Helper()
				row, err := readDeploymentRow(ctx, dba, sql, 1)
				if err != nil || string(row[0]) != "true" {
					t.Fatal("access-state assertion failed", err)
				}
			}
			check("SELECT (NOT EXISTS(SELECT FROM wormhole_data.device_admissions WHERE device_id='" + device + "'))::text")
			call(review.WorkspaceAccessRequest, "stale")
			call(disable, "unchanged")
			enable := call(WorkspaceAccessRequest{Action: "enable-account", TargetID: account}, "review").Review
			call(enable.WorkspaceAccessRequest, "changed")
			residentCheck("WH007")
			check("SELECT (NOT r.rolcanlogin AND o.retired_at IS NOT NULL AND o.capsule IS NULL)::text " +
				"FROM wormhole_data.account_reset_offers o JOIN pg_catalog.pg_roles r ON r.oid=o.role_oid WHERE o.id='" + offer + "'")
			closeDeploymentConnection(resident)
			_ = member.Close(ctx)
			member = admit()
			revoke := call(WorkspaceAccessRequest{Action: "revoke-device", TargetID: device}, "review").Review
			if revoke.Name != "Member device" || revoke.CurrentDevice {
				t.Fatal("review identifies the wrong device")
			}
			// Assert transactional DDL rollback through an admitted capability on a
			// second server connection. Keep the native owner's connection alive.
			exec("ALTER TABLE wormhole_data.audit_log RENAME TO unavailable_audit")
			err = admin.capability.With(func(value []byte) error {
				capability := hex.AppendEncode(nil, value)
				defer vault.Wipe(capability)
				args := [][]byte{capability, []byte(revoke.Action), []byte(revoke.TargetID), []byte(revoke.Revision),
					hex.AppendEncode(nil, trust.PolicyDigest), hex.AppendEncode(nil, stateHash[:])}
				return probe.ExecParams(ctx, workspaceAccessSQL, args, nil, nil, nil).Read().Err
			})
			exec("ALTER TABLE wormhole_data.unavailable_audit RENAME TO audit_log")
			if !hasSQLState(err, "WH005", 0) {
				t.Fatal("revocation with an unavailable audit committed", err)
			}
			check("SELECT (rolcanlogin AND rolpassword IS NOT NULL AND EXISTS(SELECT FROM wormhole_data.device_admissions WHERE device_id='" +
				device + "') AND EXISTS(SELECT FROM wormhole_data.devices WHERE id='" + device + "' AND status='active'))::text " +
				"FROM pg_catalog.pg_authid WHERE rolname='" + roleName + "'")
			call(revoke.WorkspaceAccessRequest, "changed")
			if _, err := member.AdminInventory(ctx, AdminInventoryRequest{Kind: "accounts"}); !errors.Is(err, ErrIdentityUnavailable) {
				t.Fatal("an already admitted device survived revocation", err)
			}
			conn, err := Connect(ctx, memberSettings, login)
			if conn != nil {
				closeDeploymentConnection(conn)
			}
			if !errors.Is(err, ErrAuthentication) {
				t.Fatal("revoked device could still log in over PostgreSQL", err)
			}
			check("SELECT (NOT rolcanlogin AND rolpassword IS NULL)::text FROM pg_catalog.pg_authid WHERE rolname='" + roleName + "'")
			check("SELECT (count(*)=3)::text FROM wormhole_data.audit_log WHERE user_id='" + trust.UserID.String() +
				"' AND access_account_id='" + account + "' AND ((action='revoke_device' AND access_device_id='" + device +
				"') OR (action IN ('disable_account','enable_account') AND access_device_id IS NULL))")
			// Demoted clients retain control of their own device, with the current
			// account role read under the same lock as the capability check.
			exec("UPDATE wormhole_data.users SET is_admin=false WHERE id='" + trust.UserID.String() + "'")
			call(disable, "unavailable")
			call(WorkspaceAccessRequest{Action: "revoke-device", TargetID: device}, "unavailable")
			own, err := admin.AdminInventory(ctx, AdminInventoryRequest{Kind: "my-devices"})
			if err != nil || own == nil || len(own.Entries) != 1 || own.Entries[0].ID != trust.DeviceID {
				t.Fatal("the device page did not have the caller's exact scope", err)
			}
			self := call(WorkspaceAccessRequest{Action: "revoke-device", TargetID: trust.DeviceID.String()}, "review").Review
			if !self.CurrentDevice {
				t.Fatal("current-device revocation was not identified")
			}
			exec("UPDATE wormhole_data.users SET is_admin=true WHERE id='" + trust.UserID.String() + "'")
			exec("CREATE TEMP TABLE saved_org_copy AS SELECT * FROM wormhole_data.key_copies WITH NO DATA")
			removed := dba.ExecParams(ctx, `WITH removed AS (DELETE FROM wormhole_data.key_copies WHERE key_id=$1::uuid AND holder_key_id=$2::uuid RETURNING *)
			    INSERT INTO pg_temp.saved_org_copy SELECT * FROM removed`,
				[][]byte{[]byte(pin.Signer.ID.String()), []byte(trust.Enrollment.Encryption.ID.String())}, nil, nil, nil).Read()
			if removed.Err != nil || removed.CommandTag.RowsAffected() != 1 {
				t.Fatal("could not exercise administration without organisation custody", removed.Err)
			}
			again := call(disable, "review").Review
			unsigned, err := admin.SuspendWithReceipt(ctx, trust, tls, epoch, again.WorkspaceAccessRequest, keys)
			if err != nil || unsigned.Status != "changed" {
				t.Fatal("administrator without organisation custody could not suspend", err)
			}
			check("SELECT (rotation_signature IS NULL AND rotation_actor IS NULL AND rotation_epoch IS NULL)::text FROM wormhole_data.account_suspensions WHERE account_id='" + account + "'")
			exec("INSERT INTO wormhole_data.key_copies SELECT * FROM pg_temp.saved_org_copy")
		})
}

func TestWorkspaceAccessWireBounds(t *testing.T) {
	target := uuid.New()
	other := uuid.New()
	request := WorkspaceAccessRequest{Action: "revoke-device", TargetID: target.String()}
	row := func(status, action, id, revision, current string) [][]byte {
		return [][]byte{[]byte(status), []byte(`["` + action + `","` + id + `","` + revision + `","member","","` + current + `"]`)}
	}
	good := row("review", request.Action, request.TargetID, "1", "true")
	if got, err := parseWorkspaceAccessReply(good, request, target); err != nil || got.Review == nil || !got.Review.CurrentDevice {
		t.Fatal("valid confirmation rejected", err)
	}
	for _, result := range [][][]byte{
		row("review", "disable-account", request.TargetID, "1", "true"),
		row("review", request.Action, other.String(), "1", "true"),
		row("review", request.Action, request.TargetID, "01", "true"),
		row("review", request.Action, request.TargetID, "1", "false"),
		row("review", request.Action, request.TargetID, "1", "YES"),
		{[]byte("review"), []byte("null")},
		{[]byte("review"), bytes.Repeat([]byte{'x'}, workspaceAccessMaxBytes+1)},
		{[]byte("changed"), nil},
		{[]byte("unavailable"), []byte("[]")},
		{[]byte("personal-recovery-required"), nil},
	} {
		if _, err := parseWorkspaceAccessReply(result, request, target); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("accepted a mismatched reply", string(result[0]), err)
		}
	}
	enable := WorkspaceAccessRequest{Action: "enable-account", TargetID: other.String()}
	recovery := [][]byte{[]byte("personal-recovery-required"), nil}
	if result, err := parseWorkspaceAccessReply(recovery, enable, target); err != nil || result.Status != string(recovery[0]) || result.Review != nil {
		t.Fatal("valid recovery prerequisite rejected", err)
	}
	recovery[1] = []byte("[]")
	if _, err := parseWorkspaceAccessReply(recovery, enable, target); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("personal recovery status carried data", err)
	}
	request.Revision = "1"
	if _, err := parseWorkspaceAccessReply(good, request, target); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("accepted a review after confirmation", err)
	}
	for _, bad := range []WorkspaceAccessRequest{{}, {Action: "revoke-device"}, {Action: "revoke-device", TargetID: target.String(), Revision: "9223372036854775808"}} {
		if _, err := NewSession().WorkspaceAccess(context.Background(), TrustState{}, bad); !errors.Is(err, ErrConfiguration) {
			t.Fatal("accepted an invalid request", err)
		}
	}
}
