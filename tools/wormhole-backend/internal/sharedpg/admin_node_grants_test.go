package sharedpg

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
)

func checkPostgresNodeGrantAdministration(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState) {
	t.Helper()
	query := func(sql string, args ...string) *pgconn.Result {
		t.Helper()
		params := make([][]byte, len(args))
		for i := range args {
			params[i] = []byte(args[i])
		}
		result := dba.ExecParams(ctx, sql, params, nil, nil, nil).Read()
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		return result
	}
	use := func(request AdminNodeGrantRequest, want string) AdminNodeGrantReply {
		t.Helper()
		result, err := session.AdminNodeGrants(ctx, trust, request)
		if err != nil || result.Status != want || (result.Page != nil) != (want == "ready") {
			t.Fatal("grant administration result", result.Status, want, err)
		}
		return result
	}
	root, leaf, personal, group, account := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	user := trust.UserID.String()
	// This fixture tests the database permission policy directly. The Electron
	// integration imports an authenticated node and verifies its signed name.
	query(`INSERT INTO wormhole_data.nodes(id,parent_id,kind,boundary_id,owner_user_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
		SELECT entry.id,entry.parent,entry.kind,b.id,entry.owner,2,e.signing_key_id,e.signing_key_version,decode(repeat('00',64),'hex')
		FROM wormhole_data.boundaries b,wormhole_data.user_enrollments e,
		(VALUES($1::uuid,NULL::uuid,0,NULL::uuid),($2::uuid,$1::uuid,1,NULL::uuid),($3::uuid,$1::uuid,1,$4::uuid))
		entry(id,parent,kind,owner) WHERE b.owner_user_id IS NULL AND e.user_id=$4::uuid`, root, leaf, personal, user)
	query(`INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,'grant-target')`, account)
	query(`INSERT INTO wormhole_data.groups(id,name) VALUES($1::uuid,'Grant target group')`, group)
	query(`INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES($1::uuid,$2::uuid)`, group, account)
	query(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,17)`, root, user)
	if supported, err := session.AdminNodeGrantsSupported(ctx); err != nil || !supported {
		t.Fatal("node grant API not advertised", err)
	}
	list := AdminNodeGrantRequest{NodeID: root, NodeRevision: "1", Kind: "group"}
	listPersonal := list
	listPersonal.NodeID = personal
	use(listPersonal, "unavailable")
	preview := use(list, "ready").Page
	if !preview.RedirectRequiresReveal || len(preview.Grants) != 0 {
		t.Fatal("group got an implicit grant", preview)
	}
	mask := permissions.Use
	edit := list
	edit.Epoch, edit.ChangeSeq, edit.SubjectID, edit.GrantRevision, edit.Mask = preview.Epoch, preview.ChangeSeq, group, "0", &mask
	use(edit, "cannot-delegate")
	mask = permissions.View
	use(edit, "changed")
	use(edit, "stale")
	verifyInherited := func(want string) {
		t.Helper()
		row := query(`SELECT wormhole_data.effective_permissions($1::uuid,$2::uuid)::text`, account, leaf)
		if len(row.Rows) != 1 || string(row.Rows[0][0]) != want {
			t.Fatal("direct group grant did not reach inherited permissions", want)
		}
	}
	verifyInherited("1")
	granted := use(list, "ready").Page
	if len(granted.Grants) != 1 || granted.Grants[0] != (AdminNodeGrant{group, "Grant target group", "1", permissions.View}) {
		t.Fatal("grant list did not return the authoritative mask and revision", granted)
	}
	edit.ChangeSeq, edit.GrantRevision = granted.ChangeSeq, "1"
	use(edit, "unchanged")
	mask = 0
	use(edit, "changed")
	verifyInherited("0")
	list.Kind = "account"
	accountPage := use(list, "ready").Page
	edit = list
	mask = permissions.View
	edit.Epoch, edit.ChangeSeq, edit.GrantRevision, edit.Login, edit.Mask = accountPage.Epoch, accountPage.ChangeSeq, "0", "Grant-target", &mask
	use(edit, "subject-unavailable")
	edit.Login = "grant-target"
	use(edit, "changed")
	verifyInherited("1")
	accountPage = use(list, "ready").Page
	edit.Login, edit.SubjectID, edit.GrantRevision, edit.ChangeSeq = "", account, "1", accountPage.ChangeSeq
	mask = permissions.View | permissions.Manage
	use(edit, "changed")
	verifyInherited("17")
	revoked := use(list, "ready").Page
	edit.ChangeSeq, edit.GrantRevision = revoked.ChangeSeq, "2"
	mask = 0
	use(edit, "changed")
	verifyInherited("0")
	query(`UPDATE wormhole_data.grants SET permissions=1 WHERE node_id=$1::uuid AND user_id=$2::uuid`, root, user)
	use(list, "unavailable")
	audit := query(`SELECT (count(*)=5 AND count(*) FILTER(WHERE admin_grant_subject_kind='group')=2
		AND count(*) FILTER(WHERE admin_grant_after=0)=2)::text FROM wormhole_data.audit_log
		WHERE node_id=$1::uuid AND action='node_grant_change'`, root)
	if len(audit.Rows) != 1 || string(audit.Rows[0][0]) != "true" {
		t.Fatal("node grant history did not match committed changes")
	}
	query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid`, root)
	query(`DELETE FROM wormhole_data.nodes WHERE id IN($1::uuid,$2::uuid,$3::uuid)`, root, leaf, personal)
	query(`DELETE FROM wormhole_data.group_members WHERE group_id=$1::uuid`, group)
	query(`DELETE FROM wormhole_data.groups WHERE id=$1::uuid`, group)
	query(`DELETE FROM wormhole_data.users WHERE id=$1::uuid`, account)
}

func TestNodeGrantProjectionRejectsUnexpectedCursorAndMasks(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000001"
	request := AdminNodeGrantRequest{NodeID: id, NodeRevision: "1", Kind: "group"}
	for _, raw := range []string{`null`, `[["` + id + `","Group","0","1"]]`, `[["` + id + `","Group","32","1"]]`,
		`[["` + id + `","Group","1","0"]]`, `[["` + id + `","Group","1","1"],["` + id + `","Other","2","1"]]`} {
		if _, err := parseAdminNodeGrantPage([][]byte{[]byte("1"), []byte("0"), []byte(raw)}, request); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("invalid grant projection accepted", err)
		}
	}
	request.Epoch, request.ChangeSeq, request.After = "1", "2", id
	if _, err := parseAdminNodeGrantPage([][]byte{[]byte("1"), []byte("3"), []byte(`[]`)}, request); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("a second page reset the permission snapshot", err)
	}
	if _, err := parseAdminNodeGrantReply([][]byte{[]byte("changed"), nil, nil, nil, nil}, request); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("read reported a mutation", err)
	}
	for _, mode := range []string{"true", "false", "invalid"} {
		row := [][]byte{[]byte("ready"), []byte("1"), []byte("2"), []byte("[]"), []byte(mode)}
		reply, err := parseAdminNodeGrantReply(row, request)
		if mode == "invalid" {
			if err == nil || reply.Page != nil {
				t.Fatal("invalid redirect policy accepted")
			}
		} else if err != nil || reply.Page == nil || reply.Page.RedirectRequiresReveal != (mode == "true") {
			t.Fatal("credential redirect rule differs from installed schema", mode, err)
		}
	}
	for _, row := range [][][]byte{
		{[]byte("ready"), []byte("1"), []byte("2"), []byte("[]")},
		{[]byte("unavailable"), nil, nil, nil, []byte("true")},
		{[]byte("ready"), []byte("1"), []byte("2"), []byte("null"), []byte("true")},
	} {
		if reply, err := parseAdminNodeGrantReply(row, request); !errors.Is(err, ErrAdmissionResponse) || reply.Page != nil {
			t.Fatal("invalid grant response exposed a permission rule", err)
		}
	}
}
