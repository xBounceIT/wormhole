package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresAdminInventoryAuthorizesEveryPage(t *testing.T) {
	settings, secret := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	workspace := uuid.New()
	const tag = "admininventory"
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
	ask := bytes.Repeat([]byte{81}, 32)
	defer vault.Wipe(ask)
	joinTestAdministrator(t, ctx, draft.invitation, factors.invitationCode[:], draft.organisation.Signing, draft.recovery.Signing, ask,
		func(raw []byte) {
			checkWorkspaceRecoveryRestore(t, ctx, dba, raw, draft, factors, ask, 0)
		},
		func(session *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) {
			sql := func(query string) {
				t.Helper()
				if _, err := dba.Exec(ctx, query).ReadAll(); err != nil {
					t.Fatal(err)
				}
			}
			if supported, err := session.AdminInventorySupported(ctx, "accounts"); err != nil || !supported {
				t.Fatal("missing schema capability", err)
			}
			checkPostgresAdminGroups(t, ctx, dba, session, trust)
			checkPostgresNodeGrantAdministration(t, ctx, dba, session, trust)
			slotCursor := checkPostgresAdminCredentialSlots(t, ctx, dba, session, trust, keys)
			if _, err := session.AdminInventory(ctx, AdminInventoryRequest{Kind: "passwords"}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid inventory kind accepted", err)
			}
			read := func(req AdminInventoryRequest) *AdminInventoryPage {
				t.Helper()
				page, err := session.AdminInventory(ctx, req)
				if err != nil || page == nil {
					t.Fatal("could not read authorized inventory", req.Kind, err)
				}
				return page
			}
			admin := read(AdminInventoryRequest{Kind: "accounts"})
			if len(admin.Entries) != 1 || admin.Entries[0].Role != "administrator" || admin.Entries[0].Login != "first-admin" {
				t.Fatal("incorrect first account page", admin)
			}
			devices := read(AdminInventoryRequest{Kind: "devices"})
			if len(devices.Entries) != 1 || devices.Entries[0].Status != "active" || devices.Entries[0].Name != "Administrator device" {
				t.Fatal("incorrect device page", devices)
			}
			sessions := read(AdminInventoryRequest{Kind: "sessions"})
			if len(sessions.Entries) == 0 || sessions.Entries[0].DeviceID != devices.Entries[0].ID.String() || sessions.Entries[0].Transport != "tls" {
				t.Fatal("incorrect recorded sessions", sessions)
			}
			checkLiveUnencryptedClients(t, ctx, settings, dba, session, trust.UserID)
			sql(`INSERT INTO wormhole_data.audit_log(at,user_id,session_id,session_role,source,action,outcome,app_version)
				SELECT now(),u.id,gen_random_uuid(),'test','ui','fixture_event','success','2.4.3'
				FROM wormhole_data.users u CROSS JOIN generate_series(1,26) n WHERE u.is_admin`)
			audit := read(AdminInventoryRequest{Kind: "audit"})
			if audit.Next == nil || len(audit.Entries) != 25 || audit.Entries[0].Action != "fixture_event" {
				t.Fatal("incorrect first audit page", audit)
			}
			next := read(AdminInventoryRequest{Kind: "audit", Next: audit.Next})
			if len(next.Entries) == 0 || next.Entries[0].ID == audit.Next.ID || next.Entries[0].Action != "fixture_event" {
				t.Fatal("audit cursor lost a tied timestamp", next)
			}
			raw, err := json.Marshal(audit)
			if err != nil || strings.Contains(string(raw), "sessionRole") || strings.Contains(string(raw), "clientAddr") {
				t.Fatal("audit returned private connection fields", err)
			}
			sql(`SET SESSION AUTHORIZATION "wh_` + tag + `_d_` + trust.DeviceID.String() + `"`)
			_, bareErr := dba.Exec(ctx, `SELECT * FROM wormhole_api_v1.admin_inventory(NULL,'audit',NULL,NULL)`).ReadAll()
			sql("RESET SESSION AUTHORIZATION")
			var denied *pgconn.PgError
			if !errors.As(bareErr, &denied) || denied.Code != "WH007" {
				t.Fatal("database login opened audit without a capability", bareErr)
			}
			sql("UPDATE wormhole_data.users SET is_admin=false WHERE id='" + trust.UserID.String() + "'")
			if _, page, err := session.AdminCredentialSlots(ctx, trust, slotCursor); err != nil || page != nil {
				t.Fatal("demoted administrator could still page through slots", err)
			}
			page, err := session.AdminInventory(ctx, AdminInventoryRequest{Kind: "audit", Next: audit.Next})
			if err != nil || page != nil {
				t.Fatal("retired authority remained valid for a previously admitted device", err)
			}
			if page, err := session.AdminInventory(ctx, AdminInventoryRequest{Kind: "unencrypted-clients"}); err != nil || page != nil {
				t.Fatal("demoted administrator could still inspect live clients", err)
			}
			groups, err := session.AdminGroups(ctx, trust, AdminGroupRequest{Action: "create", GroupID: uuid.NewString(), Name: "Denied"})
			if err != nil || groups.Status != "unavailable" || groups.Page != nil {
				t.Fatal("demoted administrator could still create groups", err)
			}
			sql("UPDATE wormhole_data.users SET is_admin=true WHERE id='" + trust.UserID.String() + "'")
			read(AdminInventoryRequest{Kind: "accounts"})
			checkPostgresGroupKeyProvisioning(t, ctx, dba, session, trust, tls, keys)
			if ok, err := session.AdminInventorySupported(ctx, "my-devices"); err != nil || !ok {
				t.Fatal("personal device inventory unavailable", err)
			}
			sql(`INSERT INTO wormhole_data.devices(id,user_id,role_name)
				SELECT d.id,u.id,'wh_admininventory_d_' || d.id::text
				FROM (SELECT gen_random_uuid() AS id FROM generate_series(1,26)) d
				CROSS JOIN wormhole_data.users u WHERE u.login_name='first-admin'`)
			own := read(AdminInventoryRequest{Kind: "my-devices"})
			if own.Next == nil || own.Next.At != "" || len(own.Entries) != adminInventoryLimit {
				t.Fatal("personal devices did not return a usable first-page cursor")
			}
			more := read(AdminInventoryRequest{Kind: "my-devices", Next: own.Next})
			if len(more.Entries) == 0 || more.Entries[0].ID.String() <= own.Next.ID.String() {
				t.Fatal("personal devices did not continue after the last displayed device")
			}
		})
}

func checkLiveUnencryptedClients(t *testing.T, ctx context.Context, settings Settings, dba *pgconn.PgConn, admin *Session, user uuid.UUID) {
	t.Helper()
	const kind = "unencrypted-clients"
	if ok, err := admin.AdminInventorySupported(ctx, kind); err != nil || !ok {
		t.Fatal("missing live inventory capability", err)
	}
	read := func(after *AdminInventoryCursor) []AdminInventoryEntry {
		t.Helper()
		page, err := admin.AdminInventory(ctx, AdminInventoryRequest{Kind: kind, Next: after})
		if err != nil || page == nil {
			t.Fatal("live client inventory unavailable", err)
		}
		return page.Entries
	}
	if len(read(nil)) != 0 {
		t.Fatal("TLS administrator appeared in the unencrypted inventory")
	}
	id := uuid.New()
	role := "wh_admininventory_d_" + id.String()
	password := []byte("synthetic-live-device-factor")
	defer vault.Wipe(password)
	if _, err := dba.Exec(ctx, `CREATE ROLE "`+role+`" LOGIN PASSWORD '`+postgresTestVerifier(password)+`' IN ROLE wh_admininventory_user`).ReadAll(); err != nil {
		t.Fatal("could not provision live test role", err)
	}
	insert := dba.ExecParams(ctx, `INSERT INTO wormhole_data.devices(id,user_id,role_name,name)
        VALUES ($1::uuid,$2::uuid,$3,'Live device')`, [][]byte{[]byte(id.String()), []byte(user.String()), []byte(role)}, nil, nil, nil).Read()
	if insert.Err != nil {
		t.Fatal(insert.Err)
	}
	open := func(s Settings) *pgconn.PgConn {
		t.Helper()
		conn, err := Connect(ctx, s, password)
		if err != nil {
			t.Fatal("could not open test device connection", err)
		}
		return conn
	}
	settings.DeviceRole = role
	secure := open(settings)
	defer closeDeploymentConnection(secure)
	settings.TLS, settings.Profile, settings.CAPEM = TLSOff, vault.Default, nil
	other := settings
	other.Database = "template1"
	foreign := open(other)
	defer closeDeploymentConnection(foreign)
	if len(read(nil)) != 0 {
		t.Fatal("TLS or another database appeared in this workspace")
	}
	first := open(settings)
	defer closeDeploymentConnection(first)
	second := open(settings)
	defer closeDeploymentConnection(second)
	entries := read(nil)
	if len(entries) != 1 || entries[0].ID != id || entries[0].Name != "Live device" || entries[0].Login != "first-admin" || !validAdminTime(entries[0].At) {
		t.Fatal("expected one registered client for two unencrypted connections")
	}
	if len(read(&AdminInventoryCursor{ID: id})) != 0 {
		t.Fatal("device cursor repeated a client")
	}
	// A confirmed device must still map to its original PostgreSQL role OID.
	deviceID := []byte(id.String())
	confirm := dba.ExecParams(ctx, `INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
		VALUES ($1::uuid,current_user::regrole::oid,decode(repeat('00',32),'hex'))`, [][]byte{deviceID}, nil, nil, nil).Read()
	if confirm.Err != nil || len(read(nil)) != 0 {
		t.Fatal("inventory attributed a connection to a different confirmed role", confirm.Err)
	}
	restore := dba.ExecParams(ctx, `UPDATE wormhole_data.device_confirmations
		SET role_oid=$2::regrole::oid WHERE device_id=$1::uuid`, [][]byte{deviceID, []byte(`"` + role + `"`)}, nil, nil, nil).Read()
	if restore.Err != nil || len(read(nil)) != 1 {
		t.Fatal("confirmed device missing from inventory", restore.Err)
	}
	// The device role cannot read the observer helper directly.
	if result := first.ExecParams(ctx, `SELECT * FROM wormhole_data.live_unencrypted_devices(NULL)`, nil, nil, nil, nil).Read(); !hasSQLState(result.Err, "42501", 0) {
		t.Fatal("unexpected observer privilege on device", result.Err)
	}
	closeDeploymentConnection(first)
	if len(read(nil)) != 1 {
		t.Fatal("disconnecting one socket removed a still-connected device")
	}
	closeDeploymentConnection(second)
	deadline := time.Now().Add(3 * time.Second)
	for len(read(nil)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("disconnected device remained in the live inventory")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAdminInventoryBoundedResponse(t *testing.T) {
	first, second := "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
	at := "2026-11-23T12:30:00.123456Z"
	accounts := AdminInventoryRequest{Kind: "accounts"}
	devices := AdminInventoryRequest{Kind: "devices"}
	sessions := AdminInventoryRequest{Kind: "sessions"}
	audit := AdminInventoryRequest{Kind: "audit"}
	for _, tc := range []struct {
		name string
		req  AdminInventoryRequest
		raw  string
	}{
		{"unknown", AdminInventoryRequest{Kind: "keys"}, `[]`},
		{"null", accounts, `null`},
		{"invalid-id", accounts, `[["oops","login","","false","false"]]`},
		{"invalid-boolean", accounts, `[["` + first + `","login","","false","bad"]]`},
		{"invalid-role", accounts, `[["` + first + `","login","","bad","false"]]`},
		{"control-name", accounts, `[["` + first + `","login","a\nb","false","false"]]`},
		{"same-account", accounts, `[["` + first + `","login","","false","false"],["` + first + `","login","","false","false"]]`},
		{"invalid-device-state", devices, `[["` + first + `","login","","disabled","` + at + `"]]`},
		{"invalid-device-date", devices, `[["` + first + `","login","","active","2026-02-30T01:01:01.123456Z"]]`},
		{"invalid-session-device", sessions, `[["` + first + `","login","oops","2.4.3","` + at + `","false"]]`},
		{"invalid-audit-actor", audit, `[["` + first + `","bad","` + second + `",null,"login","success","ui","` + at + `"]]`},
		{"invalid-audit-code", audit, `[["` + first + `","` + first + `","` + second + `",null,"unknown code","success","ui","` + at + `"]]`},
		{"timeline-tie", AdminInventoryRequest{Kind: "audit", Next: &AdminInventoryCursor{ID: uuid.MustParse(first), At: at}},
			`[["` + second + `","` + first + `","` + second + `",null,"login","success","ui","` + at + `"]]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseAdminInventory([]byte(tc.raw), tc.req); !errors.Is(err, ErrAdmissionResponse) {
				t.Fatal("invalid inventory response accepted", err)
			}
		})
	}
	page, err := parseAdminInventory([]byte(`[["`+first+`","`+first+`","`+second+`",null,"login","success","ui","`+at+`"]]`), audit)
	if err != nil || len(page.Entries) != 1 || page.Entries[0].ActorID != first || page.Entries[0].Login != "" {
		t.Fatal("historical event with a removed account was lost", err)
	}
	data := make([][]string, 26)
	for i := range data {
		data[i] = []string{uuid.UUID{15: byte(i + 1)}.String(), "login", "", "active", at}
	}
	raw, _ := json.Marshal(data)
	for _, kind := range []string{"devices", "my-devices", "unencrypted-clients"} {
		page, err = parseAdminInventory(raw, AdminInventoryRequest{Kind: kind})
		if err != nil || len(page.Entries) != 25 || page.Next == nil || page.Next.At != "" || page.Next.ID != page.Entries[24].ID {
			t.Fatal("device cursor did not bind the last visible ID", kind, err)
		}
	}
}
