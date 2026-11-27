package sharedpg

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
)

func checkPostgresAdminGroups(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState) {
	t.Helper()
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if args == nil {
			if _, err := dba.Exec(ctx, sql).ReadAll(); err != nil {
				t.Fatal(err)
			}
		} else if err := dba.ExecParams(ctx, sql, args, nil, nil, nil).Read().Err; err != nil {
			t.Fatal(err)
		}
	}
	use := func(request AdminGroupRequest, want string) AdminGroupReply {
		t.Helper()
		reply, err := session.AdminGroups(ctx, trust, request)
		if err != nil || reply.Status != want || (reply.Page != nil) != (want == "ready") {
			t.Fatal("unexpected group reply", request.Action, reply.Status, want, err)
		}
		return reply
	}
	if supported, err := session.AdminGroupsSupported(ctx); err != nil || !supported {
		t.Fatal("missing group administration capability", err)
	}
	group := uuid.NewString()
	create := AdminGroupRequest{Action: "create", GroupID: group, Name: "Operations"}
	if _, err := session.AdminGroups(ctx, trust, AdminGroupRequest{Action: "create", Name: "missing ID"}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid group accepted", err)
	}
	exec("BEGIN; SELECT 1 FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE")
	use(create, "busy")
	exec("ROLLBACK")
	use(create, "changed")
	use(create, "unchanged")
	create.Name = "Different name"
	use(create, "stale")
	groups := use(AdminGroupRequest{Action: "list"}, "ready").Page
	if len(groups.Entries) != 1 || groups.Entries[0] != (AdminGroupEntry{ID: group, Name: "Operations", Revision: "1"}) {
		t.Fatal("group creation and read did not agree", groups)
	}
	read := AdminGroupRequest{Action: "members", GroupID: group, Revision: "1"}
	if page := use(read, "ready").Page; len(page.Entries) != 0 {
		t.Fatal("new group inherited membership", page)
	}
	root, leaf := uuid.New(), uuid.New()
	exec("INSERT INTO wormhole_data.nodes(id,kind) VALUES($1::uuid,0)", []byte(root.String()))
	exec("INSERT INTO wormhole_data.nodes(id,parent_id,kind) VALUES($1::uuid,$2::uuid,1)", []byte(leaf.String()), []byte(root.String()))
	exec("INSERT INTO wormhole_data.grants(node_id,group_id,permissions) VALUES($1::uuid,$2::uuid,1)", []byte(root.String()), []byte(group))
	access := func(want permissions.Mask) {
		t.Helper()
		got, err := session.NodePermissions(ctx, leaf)
		if err != nil || got != want {
			t.Fatal("group membership did not update inherited permissions", got, want, err)
		}
	}
	access(0)
	rename := AdminGroupRequest{Action: "rename", GroupID: group, Revision: "1", Name: "Incident response"}
	use(rename, "changed")
	use(read, "stale")
	rename.Revision = "2"
	use(rename, "unchanged")
	add := AdminGroupRequest{Action: "add-member", GroupID: group, Revision: "2", Login: "missing"}
	use(add, "account-unavailable")
	add.Login = "first-admin"
	use(add, "changed")
	access(permissions.View)
	add.Revision = "3"
	use(add, "unchanged")
	read.Revision = "3"
	page := use(read, "ready").Page
	if len(page.Entries) != 1 || page.Entries[0].ID != trust.UserID.String() || page.Entries[0].Login != "first-admin" {
		t.Fatal("wrong member added", page)
	}
	read.After = trust.UserID.String()
	if len(use(read, "ready").Page.Entries) != 0 {
		t.Fatal("member cursor repeated a member")
	}
	remove := AdminGroupRequest{Action: "remove-member", GroupID: group, Revision: "3", MemberID: trust.UserID.String()}
	del := AdminGroupRequest{Action: "delete", GroupID: group, Revision: "3"}
	use(del, "group-in-use")
	exec(`INSERT INTO wormhole_data.boundary_grants(boundary_id,group_id,permissions)
		SELECT b.id,$1::uuid,1 FROM wormhole_data.boundaries b WHERE b.owner_user_id IS NULL`, []byte(group))
	use(remove, "key-change-required")
	use(add, "key-change-required")
	use(del, "key-change-required")
	exec("DELETE FROM wormhole_data.boundary_grants WHERE group_id=$1::uuid", []byte(group))
	use(remove, "changed")
	access(0)
	use(del, "stale")
	del.Revision = "4"
	use(del, "group-in-use")
	exec("DELETE FROM wormhole_data.grants WHERE group_id=$1::uuid", []byte(group))
	exec("DELETE FROM wormhole_data.nodes WHERE id IN ($1::uuid,$2::uuid)", []byte(leaf.String()), []byte(root.String()))
	use(del, "changed")
	use(del, "stale")
	audit := dba.ExecParams(ctx, `SELECT (count(*)=5 AND count(admin_subject_id)=2
		AND bool_and(session_id<> '00000000-0000-0000-0000-000000000000'::uuid))::text
		FROM wormhole_data.audit_log WHERE admin_group_id=$1::uuid`, [][]byte{[]byte(group)}, nil, nil, nil).Read()
	if audit.Err != nil || len(audit.Rows) != 1 || string(audit.Rows[0][0]) != "true" {
		t.Fatal("group actions did not commit exactly one scoped audit record each", audit.Err)
	}
}

func TestAdminGroupResponsesValidateShapeOrderingAndRevision(t *testing.T) {
	id := "00000000-0000-0000-0000-000000000001"
	read := AdminGroupRequest{Action: "list"}
	for _, raw := range []string{`null`, `{}`, `[["bad","Group","1"]]`,
		`[["` + id + `","Group","1"],["` + id + `","Other","1"]]`, `[["` + id + `","Group","01"]]`,
		`[["` + id + `","Group","9223372036854775808"]]`, `[["` + id + `","Name\nwith controls","1"]]`} {
		if _, err := parseAdminGroupPage([]byte(raw), read); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("invalid group row accepted", raw, err)
		}
	}
	read.Action = "members"
	if _, err := parseAdminGroupPage([]byte(`[["`+id+`","alice","pending"]]`), read); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("invalid member state accepted", err)
	}
	read.Action = "list"
	rows := make([][3]string, 26)
	for i := range rows {
		rows[i] = [3]string{uuid.UUID{15: byte(i + 1)}.String(), "Group", "1"}
	}
	value, _ := json.Marshal(rows)
	page, err := parseAdminGroupPage(value, read)
	if err != nil || len(page.Entries) != 25 || page.After != rows[24][0] {
		t.Fatal("group lookahead returned a wrong next cursor", page, err)
	}
	for _, status := range []string{"changed", "key-change-required", "account-unavailable", "bogus"} {
		if _, err := parseAdminGroupReply([][]byte{[]byte(status), nil}, read); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("unrelated reply accepted", status, err)
		}
	}
}
