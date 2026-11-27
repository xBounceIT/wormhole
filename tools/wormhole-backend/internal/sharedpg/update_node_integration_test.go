package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func checkImportedNodeEdit(t *testing.T, ctx context.Context, db *pgconn.PgConn, s *Session, trust TrustState, node uuid.UUID, actor *vault.UserKeys) {
	t.Helper()
	if supported, err := s.NodeEditingSupported(ctx); err != nil || !supported {
		t.Fatal("missing node edit API", err)
	}
	read := func() *NodeEdit {
		t.Helper()
		r := db.ExecParams(ctx, `SELECT row_version FROM wormhole_data.nodes WHERE id=$1::uuid`, [][]byte{[]byte(node.String())}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 {
			t.Fatal("read selected version", r.Err)
		}
		rev, ok := treeNumber(r.Rows[0][0], 1, 1<<63-1)
		if !ok {
			t.Fatal("bad revision")
		}
		next, edit, err := s.ReadNodeEdit(ctx, trust, node, rev)
		if err != nil || edit == nil || edit.fields == nil || next.Revision == 0 {
			t.Fatal("verify node and field manifest", err)
		}
		trust = next
		return edit
	}
	key := ed25519.NewKeyFromSeed(actor.SigningSeed)
	defer vault.Wipe(key)
	signer := trust.Enrollment.Signing
	setGrant := func(mask string) {
		t.Helper()
		rs := db.ExecParams(ctx, `UPDATE wormhole_data.grants SET permissions=$1::int WHERE node_id=$2::uuid AND user_id=$3::uuid`, [][]byte{[]byte(mask), []byte(node.String()), []byte(trust.UserID.String())}, nil, nil, nil).Read()
		if rs.Err != nil || rs.CommandTag.RowsAffected() != 1 {
			t.Fatal("set fixture permission", rs.Err)
		}
	}
	submit := func(edit *NodeEdit, metadata vaultstore.NodeMetadata, breakSeal string, want string) {
		t.Helper()
		revision := edit.node.Seal.Revision + 1
		if breakSeal == "" {
			committed, err := s.CommitNodeEdit(ctx, trust, edit, metadata, actor)
			if err != nil || (want == "changed" && committed != revision) || (want != "changed" && committed != 0) {
				t.Fatalf("expected %s at revision %d, got %d (%v)", want, revision, committed, err)
			}
			return
		}
		seal, err := sharedcatalog.SignNode(trust.WorkspaceID, edit.node.Boundary, metadata, revision, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := sharedcatalog.SignSelection(trust.WorkspaceID, edit.node.Boundary, edit.fields.Record, revision, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		if breakSeal == "metadata" {
			seal.Signature[0] ^= 1
		}
		if breakSeal == "fields" {
			fields.Signature[0] ^= 1
		}
		raw, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		args := append([][]byte{[]byte(node.String()), strconv.AppendUint(nil, edit.epoch, 10), strconv.AppendUint(nil, edit.sequence, 10), strconv.AppendUint(nil, revision-1, 10)}, raw, []byte(signer.ID.String()), []byte(strconv.FormatUint(uint64(signer.Version), 10)), hex.AppendEncode(nil, seal.Signature), hex.AppendEncode(nil, fields.Signature))
		actual := ""
		err = s.queryAdministration(ctx, trust, updateNodeSQL, args, 128, 1, func(row [][]byte) error { actual = string(row[0]); return nil })
		if err != nil || actual != want {
			t.Fatalf("node edit: got %q want %q (%v)", actual, want, err)
		}
	}
	setGrant("5")
	t.Cleanup(func() { setGrant("31") })
	original := read()
	otherTrust := trust
	otherTrust.WorkspaceID = uuid.New()
	if _, err := s.CommitNodeEdit(ctx, otherTrust, original, original.node.Metadata, actor); err != ErrConfiguration {
		t.Fatal("edit accepted by another workspace", err)
	}
	relocated := original.node.Metadata
	parent := uuid.NewString()
	relocated.ParentID = &parent
	if _, err := s.CommitNodeEdit(ctx, trust, original, relocated, actor); err != ErrConfiguration {
		t.Fatal("metadata edit accepted a folder move", err)
	}
	inlineChange := original.node.Metadata
	inline := inlineChange.UseInlinePassword == nil || !*inlineChange.UseInlinePassword
	inlineChange.UseInlinePassword = &inline
	submit(original, inlineChange, "", "unavailable")
	metadata := original.node.Metadata
	metadata.Name = "SSH <A&B> \"🙂\" \u2028\u2029"
	if _, err := s.CommitNodeEdit(ctx, trust, original, metadata, nil); err != ErrConfiguration {
		t.Fatal("unsigned edit was accepted", err)
	}
	submit(original, metadata, "metadata", "unavailable")
	submit(original, metadata, "fields", "unavailable")
	submit(original, metadata, "", "changed")
	submit(original, metadata, "", "stale")
	renamed := read()
	if !original.Matches(renamed, metadata) || original.Matches(renamed, original.node.Metadata) || renamed.node.Metadata.Name != metadata.Name || renamed.node.Seal.Revision != original.node.Seal.Revision+1 {
		t.Fatal("rename receipt did not verify")
	}
	hostname := "changed.example"
	metadata.Host = &hostname
	submit(renamed, metadata, "", "unavailable")
	rejected := read()
	if rejected.sequence != renamed.sequence || rejected.node.Seal.Revision != renamed.node.Seal.Revision || !bytes.Equal(rejected.fields.Seal.Signature, renamed.fields.Seal.Signature) {
		t.Fatal("denied edit changed catalog or field version")
	}
	setGrant("15")
	t.Run("other-users-resulting-credential", func(t *testing.T) {
		addPrivateEditAccount(t, ctx, db, trust, node, key)
		before := read()
		submit(before, metadata, "", "unavailable")
		after := read()
		if before.sequence != after.sequence || before.node.Seal.Revision != after.node.Seal.Revision {
			t.Fatal("private credential denial changed the node")
		}
	})
	submit(read(), metadata, "", "changed")
	after := read()
	if after.node.Metadata.Host == nil || *after.node.Metadata.Host != hostname || after.node.Seal.Revision != renamed.node.Seal.Revision+1 {
		t.Fatal("authorized host edit did not verify")
	}
	setGrant("3")
	metadata.Name = "no permission"
	submit(after, metadata, "", "stale")
	if _, unavailable, err := s.ReadNodeEdit(ctx, trust, node, after.node.Seal.Revision); err != nil || unavailable != nil {
		t.Fatal("Read permitted without Write", err)
	}
	setGrant("31")
	// Restore the node used by subsequent release and recovery scenarios.
	submit(read(), original.node.Metadata, "", "changed")
	t.Run("inherited-folder-host", func(t *testing.T) {
		checkInheritedFolderEdit(t, ctx, db, s, trust, original.node.Boundary, actor)
	})
	rs := db.ExecParams(ctx, `SELECT count(*) FROM wormhole_data.audit_log WHERE node_id=$1::uuid AND action='update_node'`, [][]byte{[]byte(node.String())}, nil, nil, nil).Read()
	if rs.Err != nil || len(rs.Rows) != 1 || string(rs.Rows[0][0]) != "3" {
		t.Fatal("unexpected edit audit count", rs.Err)
	}
}

func checkInheritedFolderEdit(t *testing.T, ctx context.Context, db *pgconn.PgConn, session *Session, trust TrustState, boundary uuid.UUID, actor *vault.UserKeys) {
	t.Helper()
	query := func(statement string, args ...string) *pgconn.Result {
		t.Helper()
		params := make([][]byte, len(args))
		for i, arg := range args {
			params[i] = []byte(arg)
		}
		r := db.ExecParams(ctx, statement, params, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal("folder fixture", r.Err)
		}
		return r
	}
	accountRow := query(`SELECT id FROM wormhole_data.credential_profiles WHERE owner_user_id IS NULL AND protocol='ssh' AND NOT deleted LIMIT 1`)
	if len(accountRow.Rows) != 1 {
		t.Fatal("missing shared SSH account")
	}
	account := string(accountRow.Rows[0][0])
	folder, child := uuid.NewString(), uuid.NewString()
	protocol, mode := 0, 2
	firstHost, secondHost := "folder.example", "another.example"
	root := vaultstore.NodeMetadata{ID: folder, Name: "Office", Kind: 0, Protocol: &protocol, Host: &firstHost}
	leaf := vaultstore.NodeMetadata{ID: child, ParentID: &folder, Name: "Session", Kind: 1, CredentialMode: &mode, CredentialID: &account}
	signer := trust.Enrollment.Signing
	key := ed25519.NewKeyFromSeed(actor.SigningSeed)
	defer vault.Wipe(key)
	insertNode := func(t *testing.T, n vaultstore.NodeMetadata) {
		t.Helper()
		seal, err := sharedcatalog.SignNode(trust.WorkspaceID, boundary, n, 1, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		query(`INSERT INTO wormhole_data.nodes(id,parent_id,kind,name,protocol,host,credential_mode,credential_id,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
            SELECT n.id,n.parent_id,n.kind,n.name,n.protocol,n.host,n.credential_mode,n.credential_id,$2::uuid,2,$3::uuid,$4::int,decode($5,'hex')
            FROM jsonb_populate_record(NULL::wormhole_data.nodes,wormhole_data.import_columns($1::jsonb)) n`,
			string(raw), boundary.String(), signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
		t.Cleanup(func() { query(`DELETE FROM wormhole_data.nodes WHERE id=$1::uuid`, n.ID) })
	}
	insertNode(t, root)
	insertNode(t, leaf)
	query(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,5)`, folder, trust.UserID.String())
	t.Cleanup(func() { query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid`, folder) })
	commit := func(t *testing.T, id string, revision uint64, field string, value string, want uint64) {
		t.Helper()
		next, edit, err := session.ReadNodeEdit(ctx, trust, uuid.MustParse(id), revision)
		if err != nil || edit == nil {
			t.Fatal("read signed fixture node", err)
		}
		trust = next
		metadata, err := edit.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "host":
			metadata.Host = &value
		case "name":
			metadata.Name = value
		default:
			t.Fatalf("unknown edit %s", field)
		}
		got, err := session.CommitNodeEdit(ctx, trust, edit, metadata, actor)
		if got != want || err != nil {
			t.Fatalf("folder %s: got revision %d, want %d (%v)", field, got, want, err)
		}
		r := query(`SELECT row_version,change_seq FROM wormhole_data.nodes,wormhole_data.workspace_meta WHERE id=$1::uuid AND singleton`, id)
		if want == 0 && (string(r.Rows[0][0]) != strconv.FormatUint(revision, 10) || string(r.Rows[0][1]) != strconv.FormatUint(edit.sequence, 10)) {
			t.Fatal("denied folder edit changed catalog")
		}
	}
	commit(t, folder, 1, "host", secondHost, 0)
	commit(t, folder, 1, "name", "Office group", 2)
	query(`UPDATE wormhole_data.grants SET permissions=15 WHERE node_id=$1::uuid`, folder)
	commit(t, folder, 2, "host", secondHost, 3)
	commit(t, child, 1, "host", "explicit.example", 2)
	query(`UPDATE wormhole_data.grants SET permissions=5 WHERE node_id=$1::uuid`, folder)
	commit(t, folder, 3, "host", firstHost, 4)
	t.Run("vnc-saved-credential", func(t *testing.T) {
		profile := sharedcatalog.CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: uuid.NewString(),
			Name: "VNC account", Protocol: "vnc", Kind: "password", Provider: "local"}, Fields: []vaultstore.CredentialField{}}
		seal, err := sharedcatalog.SignCredential(trust.WorkspaceID, boundary, profile, 1, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		query(`INSERT INTO wormhole_data.credential_profiles(id,name,protocol,kind,provider,fields,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
            VALUES($1::uuid,'VNC account','vnc','password','local','[]'::jsonb,$2::uuid,2,$3::uuid,$4::integer,decode($5,'hex'))`,
			profile.Metadata.ID, boundary.String(), signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
		t.Cleanup(func() { query(`DELETE FROM wormhole_data.credential_profiles WHERE id=$1::uuid`, profile.Metadata.ID) })
		vncProtocol := 6
		n := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "VNC session", Kind: 1, Protocol: &vncProtocol, Host: &firstHost, CredentialMode: &mode, CredentialID: &profile.Metadata.ID}
		insertNode(t, n)
		query(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,5)`, n.ID, trust.UserID.String())
		t.Cleanup(func() { query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid`, n.ID) })
		commit(t, n.ID, 1, "host", secondHost, 0)
		query(`UPDATE wormhole_data.grants SET permissions=15 WHERE node_id=$1::uuid`, n.ID)
		commit(t, n.ID, 1, "host", secondHost, 2)
	})
	t.Run("signed-move", func(t *testing.T) {
		supported, err := session.NodeMovingSupported(ctx)
		if err != nil || !supported {
			t.Fatal("missing move API", err)
		}
		other := root
		other.ID, other.Name, other.Host = uuid.NewString(), "Second folder", &secondHost
		insertNode(t, other)
		connection := leaf
		connection.ID = uuid.NewString()
		insertNode(t, connection)
		empty := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Nested folder", Kind: 0, ParentID: &folder}
		insertNode(t, empty)
		query(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,5)`, other.ID, trust.UserID.String())
		t.Cleanup(func() { query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid`, other.ID) })
		destination := uuid.MustParse(other.ID)
		nested := uuid.MustParse(empty.ID)
		source := uuid.MustParse(folder)
		move := func(t *testing.T, id string, revision uint64, parent *uuid.UUID, allowed bool) {
			t.Helper()
			next, edit, err := session.ReadNodeEdit(ctx, trust, uuid.MustParse(id), revision)
			if err != nil || edit == nil {
				t.Fatal("cannot select move source", err)
			}
			trust = next
			receipt, err := session.CommitNodeMove(ctx, trust, edit, parent, actor)
			if err != nil || (receipt != nil) != allowed {
				t.Fatalf("move at revision %d returned receipt=%t, expected %t (%v)", revision, receipt != nil, allowed, err)
			}
			r := query(`SELECT parent_id,row_version,change_seq FROM wormhole_data.nodes,wormhole_data.workspace_meta WHERE id=$1::uuid AND singleton`, id)
			if !allowed {
				if string(r.Rows[0][2]) != strconv.FormatUint(edit.sequence, 10) || string(r.Rows[0][1]) != strconv.FormatUint(revision, 10) {
					t.Fatal("denied move changed catalog")
				}
				return
			}
			if receipt.Revision() != revision+1 || (parent == nil && r.Rows[0][0] != nil) || (parent != nil && string(r.Rows[0][0]) != parent.String()) {
				t.Fatal("wrong move receipt")
			}
			trust, err = receipt.Advance(trust)
			if err != nil || trust.Catalog["node/"+id].Revision != revision+1 {
				t.Fatal("move floor", err)
			}
			if replay, err := session.CommitNodeMove(ctx, trust, edit, parent, actor); err != nil || replay != nil {
				t.Fatal("stale move accepted", err)
			}
		}
		// Equal grant sets permit a Write-only move when no connection changes.
		t.Run("workspace-move-lock", func(t *testing.T) {
			query("BEGIN")
			defer query("ROLLBACK")
			query(`SELECT pg_advisory_xact_lock(hashtextextended('wormhole/move/'||$1::text,0))`, trust.WorkspaceID.String())
			move(t, empty.ID, 1, &destination, false)
		})
		move(t, empty.ID, 1, &destination, true)
		move(t, empty.ID, 2, &source, true)
		move(t, folder, 4, &nested, false)
		move(t, connection.ID, 1, &destination, false)
		query(`UPDATE wormhole_data.grants SET permissions=15 WHERE node_id=$1::uuid`, other.ID)
		move(t, empty.ID, 3, &destination, false) // acquiring Reveal requires Manage on the source
		query(`UPDATE wormhole_data.grants SET permissions=15 WHERE node_id=$1::uuid`, folder)
		move(t, connection.ID, 1, &destination, true)
		t.Run("private-override", func(t *testing.T) {
			member := addPrivateEditAccount(t, ctx, db, trust, uuid.MustParse(connection.ID), key)
			move(t, connection.ID, 2, &source, false)
			query(`UPDATE wormhole_data.users SET disabled=true WHERE id=$1::uuid`, member.String())
			t.Cleanup(func() {
				query(`DELETE FROM wormhole_data.account_suspensions WHERE account_id=$1::uuid`, member.String())
			})
			query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid AND user_id=$2::uuid`, connection.ID, member.String())
			move(t, connection.ID, 2, &source, false)
		})
		query(`UPDATE wormhole_data.grants SET permissions=31 WHERE node_id=$1::uuid`, folder)
		move(t, empty.ID, 3, nil, true)
		if _, invisible, err := session.ReadNodeEdit(ctx, trust, nested, 4); err != nil || invisible != nil {
			t.Fatal("move to root retained inherited Write", err)
		}
	})
}

// Create signed public metadata for a second account's private override. No
// secret value is needed to exercise this metadata-only authorization decision.
func addPrivateEditAccount(t *testing.T, ctx context.Context, db *pgconn.PgConn, trust TrustState, node uuid.UUID, key ed25519.PrivateKey) uuid.UUID {
	t.Helper()
	member, boundary, account := uuid.New(), uuid.New(), uuid.New()
	signer := trust.Enrollment.Signing
	query := func(q string, args ...string) {
		t.Helper()
		params := make([][]byte, len(args))
		for i, a := range args {
			params[i] = []byte(a)
		}
		r := db.ExecParams(ctx, q, params, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal("private account fixture", r.Err)
		}
	}
	query(`INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,'edit-private-account')`, member.String())
	t.Cleanup(func() { query(`DELETE FROM wormhole_data.users WHERE id=$1::uuid`, member.String()) })
	query(`INSERT INTO wormhole_data.boundaries(id,owner_user_id) VALUES($1::uuid,$2::uuid)`, boundary.String(), member.String())
	t.Cleanup(func() { query(`DELETE FROM wormhole_data.boundaries WHERE id=$1::uuid`, boundary.String()) })
	query(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,3)`, node.String(), member.String())
	t.Cleanup(func() {
		query(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid AND user_id=$2::uuid`, node.String(), member.String())
	})
	value := sharedcatalog.CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: account.String(), OwnerUserID: member.String(), Name: "Personal edit fixture",
		Protocol: "ssh", Kind: "password", Provider: "local", Username: "personal-user"}, Fields: []vaultstore.CredentialField{}}
	seal, err := sharedcatalog.SignCredential(trust.WorkspaceID, boundary, value, 1, signer, key)
	if err != nil {
		t.Fatal(err)
	}
	query(`INSERT INTO wormhole_data.credential_profiles(id,owner_user_id,name,protocol,kind,provider,username,fields,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
        VALUES($1::uuid,$2::uuid,'Personal edit fixture','ssh','password','local','personal-user','[]'::jsonb,$3::uuid,2,$4::uuid,$5::integer,decode($6,'hex'))`,
		account.String(), member.String(), boundary.String(), signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
	t.Cleanup(func() { query(`DELETE FROM wormhole_data.credential_profiles WHERE id=$1::uuid`, account.String()) })
	override := sharedcatalog.OverrideRecord{UserID: member.String(), NodeID: node.String(), CredentialID: account.String()}
	seal, err = sharedcatalog.SignSelection(trust.WorkspaceID, boundary, override, 1, signer, key)
	if err != nil {
		t.Fatal(err)
	}
	query(`INSERT INTO wormhole_data.user_node_overrides(user_id,node_id,credential_id,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
        VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,2,$5::uuid,$6::integer,decode($7,'hex'))`, member.String(), node.String(), account.String(), boundary.String(),
		signer.ID.String(), strconv.FormatUint(uint64(signer.Version), 10), hex.EncodeToString(seal.Signature))
	t.Cleanup(func() {
		query(`DELETE FROM wormhole_data.user_node_overrides WHERE user_id=$1::uuid AND node_id=$2::uuid`, member.String(), node.String())
	})
	r := db.ExecParams(ctx, `SELECT wormhole_data.resolve_connection($1::uuid,$2::uuid,epoch,change_seq,'ssh')#>>'{credential,id}' FROM wormhole_data.workspace_meta WHERE singleton`,
		[][]byte{[]byte(node.String()), []byte(member.String())}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != account.String() {
		t.Fatal("second member did not resolve its own credential", r.Err)
	}
	return member
}

// Exercise the imported RDP gateway and the HTTPS connection with a stored
// browser session and a tunnel. Each attempted change is retried after Reveal
// is restored so a resolver failure cannot count as a permission denial.
func checkProtocolEditPermissions(t *testing.T, ctx context.Context, s *Session, trust TrustState, actor *vault.UserKeys, rdp, web uuid.UUID, boundaryGrant func(string)) {
	t.Helper()
	versions := map[uuid.UUID]uint64{rdp: 1, web: 1}
	for _, tc := range []struct {
		name string
		node uuid.UUID
		edit func(*vaultstore.NodeMetadata)
	}{
		{"rdp-server", rdp, func(n *vaultstore.NodeMetadata) { host := "new-desktop.example"; n.Host = &host }},
		{"rdp-gateway", rdp, func(n *vaultstore.NodeMetadata) { host := "new-gateway.example"; n.RDPGatewayHostname = &host }},
		{"https-host", web, func(n *vaultstore.NodeMetadata) { host := "new-web.example"; n.Host = &host }},
		{"https-tunnel", web, func(n *vaultstore.NodeMetadata) { enabled := false; n.TunnelEnabled = &enabled }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func() *NodeEdit {
				t.Helper()
				next, selected, err := s.ReadNodeEdit(ctx, trust, tc.node, versions[tc.node])
				if err != nil || selected == nil {
					t.Fatal("could not read the signed protocol fixture", err)
				}
				trust = next
				return selected
			}
			write := func(selected *NodeEdit, settings vaultstore.NodeMetadata, want uint64) {
				t.Helper()
				got, err := s.CommitNodeEdit(ctx, trust, selected, settings, actor)
				if err != nil || got != want {
					t.Fatalf("expected revision %d, got %d (%v)", want, got, err)
				}
				if got != 0 {
					versions[tc.node] = got
				}
			}
			boundaryGrant("7")
			t.Cleanup(func() { boundaryGrant("31") })
			before := read()
			changed, err := before.Metadata()
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&changed)
			write(before, changed, 0)
			if read().sequence != before.sequence {
				t.Fatal("denied protocol edit changed the catalog")
			}
			boundaryGrant("31")
			authorized := read()
			write(authorized, changed, versions[tc.node]+1)
			after := read()
			if !authorized.Matches(after, changed) {
				t.Fatal("signed readback differs from the authorized settings")
			}
			write(after, before.node.Metadata, versions[tc.node]+1)
		})
	}
}
