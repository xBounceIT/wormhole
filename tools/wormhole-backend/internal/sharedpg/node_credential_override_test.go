package sharedpg

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkNodeCredentialOverrides(t *testing.T, ctx context.Context, db *pgconn.PgConn, s *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys, ssh, rdp uuid.UUID) {
	t.Helper()
	query := func(sql string, args ...string) *pgconn.Result {
		t.Helper()
		params := make([][]byte, len(args))
		for i, v := range args {
			params[i] = []byte(v)
		}
		result := db.ExecParams(ctx, sql, params, nil, nil, nil).Read()
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		return result
	}
	user := trust.UserID.String()
	query("UPDATE wormhole_data.users SET is_admin=false WHERE id=$1::uuid", user)
	t.Cleanup(func() {
		query("DELETE FROM wormhole_data.user_node_overrides WHERE user_id=$1::uuid AND node_id IN ($2::uuid,$3::uuid)", user, ssh.String(), rdp.String())
		query("UPDATE wormhole_data.users SET is_admin=true WHERE id=$1::uuid", user)
	})
	if ok, err := s.NodeOverrideSupported(ctx); err != nil || !ok {
		t.Fatal("missing override API", err)
	}
	read := func(id uuid.UUID, scope, name, want string) *NodeOverrideReview {
		t.Helper()
		next, r, status, err := s.ReadNodeOverride(ctx, trust, tls, id, scope, name)
		if err != nil || status != want || (r == nil) != (want != "review") {
			t.Fatalf("review %s %s: %s (%v)", scope, name, status, err)
		}
		trust = next
		return r
	}
	write := func(r *NodeOverrideReview, want string) {
		t.Helper()
		next, status, err := s.CommitNodeOverride(ctx, trust, tls, r, keys)
		if err != nil || status != want {
			t.Fatalf("save %s: %s (%v)", r.Choice.NodeName, status, err)
		}
		trust = next
	}
	checkPlan := func(node uuid.UUID, path, kind, id string) {
		t.Helper()
		m, err := s.ConnectionPlanPath(ctx, node, path)
		if err != nil {
			t.Fatal("resolve", err)
		}
		next, verified, err := trust.VerifyConnectionPlan(ctx, node, m)
		if err != nil || verified.Plan.Credential.Kind != kind || (id != "" && verified.Plan.Credential.ID != id) {
			t.Fatal("unexpected connection credential", kind, err)
		}
		trust = next
	}
	read(ssh, "personal", "Imported SFTP account", "unavailable")
	read(rdp, "shared", "Desktop", "unavailable")
	read(ssh, "personal", "Desktop", "unavailable")
	read(ssh, "shared", "Missing", "unavailable")
	first := read(ssh, "shared", "Imported SFTP account", "review")
	if first.Choice.Protocol != "ssh" || first.Choice.UserID != user || first.Choice.Revision != "0" || first.Unchanged() {
		t.Fatal("initial shared credential review")
	}
	boundary := query("SELECT boundary_id FROM wormhole_data.credential_profiles WHERE id=$1::uuid", first.Choice.CredentialID)
	for _, grant := range []struct{ table, column, id string }{
		{"grants", "node_id", ssh.String()},
		{"boundary_grants", "boundary_id", string(boundary.Rows[0][0])},
	} {
		filter := " FROM wormhole_data." + grant.table + " WHERE " + grant.column + "=$1::uuid AND user_id=$2::uuid"
		before := query("SELECT permissions"+filter, grant.id, user)
		if len(before.Rows) != 1 {
			t.Fatal("missing fixture grant", grant.table)
		}
		set := "UPDATE wormhole_data." + grant.table + " SET permissions=$3::integer WHERE " + grant.column + "=$1::uuid AND user_id=$2::uuid"
		func() {
			defer query(set, grant.id, user, string(before.Rows[0][0]))
			query(set, grant.id, user, "1")
			read(ssh, "shared", "Imported SFTP account", "unavailable")
			_, status, err := s.CommitNodeOverride(ctx, trust, tls, first, keys)
			if err != nil || (status != "stale" && status != "unavailable") {
				t.Fatalf("save after revoking Use on %s: %s (%v)", grant.table, status, err)
			}
		}()
		first = read(ssh, "shared", "Imported SFTP account", "review")
	}
	write(first, "saved")
	write(first, "stale")
	current := read(ssh, "shared", "Imported SFTP account", "review")
	if !current.Unchanged() || current.Choice.Revision != "1" {
		t.Fatal("missing signed override")
	}
	write(current, "unchanged")
	checkPlan(ssh, "sftp", "override", first.Choice.CredentialID)
	write(read(ssh, "inherit", "", "review"), "saved")
	checkPlan(ssh, "sftp", "saved", "")
	inherit := read(ssh, "inherit", "", "review")
	if !inherit.Unchanged() || inherit.Choice.Revision != "2" {
		t.Fatal("missing signed tombstone")
	}
	own := read(rdp, "personal", "Desktop", "review")
	write(own, "saved")
	checkPlan(rdp, "rdp", "override", own.Choice.CredentialID)
	write(read(rdp, "inherit", "", "review"), "saved")
	if result := query("SELECT count(*)::text FROM wormhole_data.audit_log WHERE user_id=$1::uuid AND action='set_node_credential_override'", user); string(result.Rows[0][0]) != "4" {
		t.Fatal("unexpected override write history")
	}
}
