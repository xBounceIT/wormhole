package vaultstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func ptr[T any](v T) *T { return &v }
func node(s *SQLite) Node {
	return Node{NodeMetadata: NodeMetadata{ID: uuid.NewString(), Name: "Folder", Kind: 0}, CreatedAt: "2026-10-30T00:00:00Z", UpdatedAt: "2026-10-30T00:00:00Z", RowVersion: 1, Fields: []SecretField{}, SealSuite: NodeSealHMACSHA256, SealSignerKeyID: s.identity.Root.ID, SealSignerKeyVersion: s.identity.Root.Version, Seal: make([]byte, 32)}
}
func nodeSecret(s *SQLite, n *Node, field string) Secret {
	v := record(s)
	v.Ref = SecretRef{OwnerKind: "node", OwnerID: n.ID, Field: field}
	n.Fields = append(n.Fields, SecretField{Field: field, Version: 1, Present: true})
	return v
}

func TestNodeRoundTripNullableMetadata(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	n := node(s)
	if err := s.WriteNode(ctx, n, nil, 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadNode(ctx, n.ID)
	if err != nil || !reflect.DeepEqual(got, n) {
		t.Fatal("NULL roundtrip", err)
	}
	// Fill every nullable scalar so SQL column/target ordering cannot silently
	// drop or exchange fields. References are populated with real target records.
	parent := n
	n = node(s)
	n.Kind = 1
	n.ParentID = &parent.ID
	n.Protocol = ptr(1)
	n.OwnerUserID = ptr(uuid.NewString())
	n.CredentialMode = ptr(2)
	c := credential()
	c.Protocol = "rdp"
	if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	n.CredentialID = &c.ID
	n.RDPGatewayCredentialID = &c.ID
	tunnel, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, tunnel, &secret, 0); err != nil {
		t.Fatal(err)
	}
	n.TunnelConfigID = &tunnel.ID
	metadata := reflect.ValueOf(&n.NodeMetadata).Elem()
	typ := metadata.Type()
	for i := 0; i < metadata.NumField(); i++ {
		f := metadata.Field(i)
		if f.Kind() != reflect.Pointer || !f.IsNil() {
			continue
		}
		name := typ.Field(i).Name
		if name == "CredentialSlotID" {
			continue
		}
		switch f.Type().Elem().Kind() {
		case reflect.String:
			f.Set(reflect.ValueOf(ptr(name)))
		case reflect.Bool:
			f.Set(reflect.ValueOf(ptr(false)))
		case reflect.Int:
			f.Set(reflect.ValueOf(ptr(1)))
		}
	}
	n.RDPColorDepth = ptr(32)
	n.SshKnownHostFingerprint = ptr("SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	n.SerialDataBits = ptr(8)
	n.SerialBaudRate = ptr(115200)
	n.SerialStopBits = ptr(3)
	n.SerialFlowControl = ptr(3)
	if err := s.WriteNode(ctx, n, nil, 0); err != nil {
		t.Fatal("populated write", err)
	}
	got, err = s.ReadNode(ctx, n.ID)
	if err != nil || !reflect.DeepEqual(got, n) {
		t.Fatalf("populated roundtrip: %v\n%+v\n%+v", err, got, n)
	}
	n.RowVersion++
	n.SshAutoSudo = ptr(true)
	n.HTTPPath = ptr("")
	n.Port = ptr(0)
	n.RDPGatewayUseSameCreds = nil
	if err := s.WriteNode(ctx, n, nil, 1); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadNode(ctx, n.ID)
	if err != nil || !reflect.DeepEqual(got, n) {
		t.Fatal("false/NULL/empty drift", err)
	}
	if err := s.ValidateInitialization(ctx); err != ErrConflict {
		t.Fatal(err)
	}
}

func TestNodeAtomicFieldsAndDeletion(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	n := node(s)
	n.Kind = 1
	n.Protocol = ptr(0)
	n.UseInlinePassword = ptr(true)
	password := nodeSecret(s, &n, "inlinePassword")
	notes := nodeSecret(s, &n, "notes")
	if err := s.WriteNode(ctx, n, []Secret{password, notes}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteSecret(ctx, next(password), 1); err != ErrConflict {
		t.Fatal("primitive bypass", err)
	}
	n.RowVersion++
	n.Name = "renamed"
	if err := s.WriteNode(ctx, n, nil, 1); err != nil {
		t.Fatal(err)
	}
	n.RowVersion++
	n.Fields[0].Version++
	password = next(password)
	if err := s.WriteNode(ctx, n, []Secret{password}, 2); err != nil {
		t.Fatal(err)
	}
	n.RowVersion++
	n.Deleted = true
	for i := range n.Fields {
		n.Fields[i].Version++
		n.Fields[i].Present = false
	}
	password = next(password)
	notes = next(notes)
	password.Envelope.Ciphertext = make([]byte, 16)
	notes.Envelope.Ciphertext = make([]byte, 16)
	if err := s.WriteNode(ctx, n, []Secret{password, notes}, 3); err != nil {
		t.Fatal(err)
	}
	if page, err := s.ListNodes(ctx, "", 1); err != nil || len(page) != 0 {
		t.Fatal(err)
	}
	if got, err := s.ReadNode(ctx, n.ID); err != nil || !got.Deleted {
		t.Fatal(err)
	}
	n.RowVersion++
	n.Deleted = false
	n.UseInlinePassword = ptr(false)
	if err := s.WriteNode(ctx, n, nil, 4); err != ErrConflict {
		t.Fatal("resurrection", err)
	}
	count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 4)
}

func TestNodeReferenceChecksAndDeletionGuards(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	parent := node(s)
	if err := s.WriteNode(ctx, parent, nil, 0); err != nil {
		t.Fatal(err)
	}
	child := node(s)
	child.ParentID = &parent.ID
	child.Kind = 1
	child.Protocol = ptr(0)
	c := credential()
	if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	child.CredentialID = &c.ID
	tunnel, secret := tunnel(s)
	if err := s.WriteTunnel(ctx, tunnel, &secret, 0); err != nil {
		t.Fatal(err)
	}
	child.TunnelConfigID = &tunnel.ID
	if err := s.WriteNode(ctx, child, nil, 0); err != nil {
		t.Fatal(err)
	}
	parent.RowVersion++
	parent.Deleted = true
	if err := s.WriteNode(ctx, parent, nil, 1); err != ErrConflict {
		t.Fatal("nonempty folder deleted", err)
	}
	c.RowVersion++
	c.Deleted = true
	if err := s.WriteCredential(ctx, c, nil, 1); err != ErrConflict {
		t.Fatal("referenced credential deleted", err)
	}
	c.Deleted = false
	c.Protocol = "rdp"
	if err := s.WriteCredential(ctx, c, nil, 1); err != ErrConflict {
		t.Fatal("referenced credential changed protocol", err)
	}
	tunnel.RowVersion++
	tunnel.ConfigurationVersion++
	tunnel.Deleted = true
	secret = next(secret)
	secret.Envelope.Ciphertext = make([]byte, 16)
	if err := s.WriteTunnel(ctx, tunnel, &secret, 1); err != ErrConflict {
		t.Fatal("referenced tunnel deleted", err)
	}
	for name, mutate := range map[string]func(*Node){"parent missing": func(n *Node) { n.ParentID = ptr(uuid.NewString()) }, "parent leaf": func(n *Node) { n.ParentID = &child.ID }, "credential missing": func(n *Node) { n.CredentialID = ptr(uuid.NewString()) }, "tunnel missing": func(n *Node) { n.TunnelConfigID = ptr(uuid.NewString()) }, "gateway missing": func(n *Node) { n.RDPGatewayCredentialID = ptr(uuid.NewString()) }, "protocol mismatch": func(n *Node) { n.Protocol = ptr(6) }, "gateway mismatch": func(n *Node) { n.RDPGatewayCredentialID = &c.ID }, "slot": func(n *Node) {
		n.CredentialID = nil
		n.CredentialMode = ptr(3)
		n.CredentialSlotID = ptr(uuid.NewString())
	}} {
		t.Run(name, func(t *testing.T) {
			v := child
			v.ID = uuid.NewString()
			mutate(&v)
			if err := s.WriteNode(ctx, v, nil, 0); err == nil {
				t.Fatal("bad reference accepted")
			}
		})
	}
	child.RowVersion++
	child.Deleted = true
	if err := s.WriteNode(ctx, child, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteNode(ctx, parent, nil, 1); err != nil {
		t.Fatal(err)
	}
	c.Deleted = true
	if err := s.WriteCredential(ctx, c, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(ctx, tunnel, &secret, 1); err != nil {
		t.Fatal(err)
	}
}

func TestNodeCyclesDepthAndConcurrentMoves(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	a := node(s)
	b := node(s)
	for _, n := range []Node{a, b} {
		if err := s.WriteNode(ctx, n, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	a.RowVersion++
	b.RowVersion++
	a.ParentID = &b.ID
	b.ParentID = &a.ID
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, n := range []Node{a, b} {
		wg.Add(1)
		go func(n Node) { defer wg.Done(); results <- s.WriteNode(ctx, n, nil, 1) }(n)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if err != ErrConflict {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("concurrent cycle", successes)
	}
	chain := make([]Node, MaxNodeDepth)
	for i := range chain {
		chain[i] = node(s)
		if i > 0 {
			chain[i].ParentID = &chain[i-1].ID
		}
		if err := s.WriteNode(ctx, chain[i], nil, 0); err != nil {
			t.Fatal("depth", i, err)
		}
	}
	tooDeep := node(s)
	tooDeep.ParentID = &chain[len(chain)-1].ID
	if err := s.WriteNode(ctx, tooDeep, nil, 0); err != ErrConflict {
		t.Fatal("depth overflow", err)
	}
	fresh := node(s)
	if err := s.WriteNode(ctx, fresh, nil, 0); err != nil {
		t.Fatal(err)
	}
	moved := chain[0]
	moved.RowVersion++
	moved.ParentID = &fresh.ID
	if err := s.WriteNode(ctx, moved, nil, 1); err != ErrConflict {
		t.Fatal("subtree exceeded cap", err)
	}
	moved.ParentID = &chain[2].ID
	if err := s.WriteNode(ctx, moved, nil, 1); err != ErrConflict {
		t.Fatal("moved into descendant", err)
	}
}

func TestNodeWriteRollbackAndInvalidFields(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"Keys", "KeyCopies", "SecretValues", "Nodes", "WorkspaceMeta"} {
		for _, failure := range []string{"ABORT,'forced'", "IGNORE"} {
			t.Run(table+failure, func(t *testing.T) {
				s, _ := database(t)
				n := node(s)
				secret := nodeSecret(s, &n, "notes")
				action := "INSERT"
				if table == "WorkspaceMeta" {
					action = "UPDATE"
				}
				exec(t, s, "CREATE TRIGGER fail BEFORE "+action+" ON "+table+" BEGIN SELECT RAISE("+failure+"); END;")
				if err := s.WriteNode(ctx, n, []Secret{secret}, 0); err == nil {
					t.Fatal("partial aggregate")
				}
				count(t, s, "SELECT count(*) FROM Nodes", 0)
				count(t, s, "SELECT count(*) FROM SecretValues", 0)
				count(t, s, "SELECT count(*) FROM Keys", 1)
				count(t, s, "SELECT ChangeSeq FROM WorkspaceMeta", 0)
			})
		}
	}
	s, _ := database(t)
	n := node(s)
	secret := nodeSecret(s, &n, "notes")
	if err := s.WriteNode(ctx, n, []Secret{secret}, 0); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Node){func(n *Node) { n.Kind = 1 }, func(n *Node) { n.CreatedAt = "2026-10-29T00:00:00Z" }, func(n *Node) { n.Fields = nil }, func(n *Node) { n.Fields = append([]SecretField{}, n.Fields...); n.Fields[0].Version++ }, func(n *Node) { n.SealSignerKeyID = uuid.NewString() }} {
		v := n
		v.RowVersion++
		mutate(&v)
		if err := s.WriteNode(ctx, v, nil, 1); err == nil {
			t.Fatal("invalid update")
		}
	}
	n.RowVersion++
	secret = next(secret)
	n.Fields[0].Version++
	secret.Ref.OwnerKind = "credential"
	if err := s.WriteNode(ctx, n, []Secret{secret}, 1); err != ErrFormat {
		t.Fatal("cross-domain field", err)
	}
}

func TestNodeBoundsCorruptionAndSchemaMigration(t *testing.T) {
	ctx := context.Background()
	s, path := database(t)
	n := node(s)
	if err := s.WriteNode(ctx, n, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadNode(ctx, "bad"); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := s.ReadNode(ctx, uuid.NewString()); err != ErrMissing {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 129} {
		if _, err := s.ListNodes(ctx, "", limit); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := s.ListNodes(ctx, "bad", 1); err != ErrFormat {
		t.Fatal(err)
	}
	page, err := s.ListNodes(ctx, "", 1)
	if err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	page, err = s.ListNodes(ctx, n.ID, 1)
	if err != nil || len(page) != 0 {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE Nodes SET Notes=x'00'")
	if _, err := s.ReadNode(ctx, n.ID); err != ErrFormat {
		t.Fatal("plaintext notes allowed", err)
	}
	if _, err := s.ListNodes(ctx, "", 1); err != ErrFormat {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE Nodes SET Notes=NULL,SecretManifest='[{\"field\":\"notes\",\"version\":1,\"present\":false,\"extra\":0}]'")
	if _, err := s.ReadNode(ctx, n.ID); err != ErrFormat {
		t.Fatal(err)
	}
	exec(t, s, "DROP TABLE LocalState; DROP TABLE Nodes; ALTER TABLE CredentialProfiles DROP COLUMN CreatedAt; UPDATE WorkspaceMeta SET SchemaVersion=3")
	if _, err := s.ListNodes(ctx, "", 1); err != ErrStorage {
		t.Fatal(err)
	}
	s.Close()
	opened, err := OpenSQLite(ctx, path, s.identity, false)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	count(t, opened, "SELECT SchemaVersion FROM WorkspaceMeta", SchemaVersion)
	count(t, opened, "SELECT ChangeSeq FROM WorkspaceMeta", 1)
	if err := opened.WriteNode(ctx, n, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadNode(ctx, n.ID); err != ErrClosed {
		t.Fatal(err)
	}
	if _, err := s.ListNodes(ctx, "", 1); err != ErrClosed {
		t.Fatal(err)
	}
	if err := s.WriteNode(ctx, n, nil, 0); err != ErrClosed {
		t.Fatal(err)
	}
	for _, failure := range []string{"ABORT,'forced'", "IGNORE", "existing"} {
		t.Run(failure, func(t *testing.T) {
			s, path := database(t)
			if failure != "existing" {
				exec(t, s, "DROP TABLE Nodes")
			}
			exec(t, s, "DROP TABLE LocalState; UPDATE WorkspaceMeta SET SchemaVersion=3")
			if failure != "existing" {
				exec(t, s, "CREATE TRIGGER fail BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE("+failure+"); END;")
			}
			s.Close()
			if opened, err := OpenSQLite(ctx, path, s.identity, false); err == nil || opened != nil {
				t.Fatal("partial migration")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, count int
			if err := db.QueryRow("SELECT SchemaVersion FROM WorkspaceMeta").Scan(&version); err != nil || version != 3 {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='Nodes'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if failure == "existing" {
				want = 1
			}
			if count != want {
				t.Fatal("DDL escaped rollback")
			}
		})
	}
}

func TestNodeValidation(t *testing.T) {
	s, _ := database(t)
	n := node(s)
	for _, mutate := range []func(*Node){func(n *Node) { n.ParentID = &n.ID }, func(n *Node) { n.OwnerUserID = ptr("bad") }, func(n *Node) { n.Name = strings.Repeat("a", 257) }, func(n *Node) { n.Name = "bad\n" }, func(n *Node) { n.Protocol = ptr(2) }, func(n *Node) { n.Port = ptr(65536) }, func(n *Node) { n.CredentialMode = ptr(4) }, func(n *Node) { n.CredentialMode = ptr(2) }, func(n *Node) { n.CredentialMode = ptr(3) }, func(n *Node) { n.CredentialSlotID = ptr(uuid.NewString()) }, func(n *Node) { n.Host = ptr("\xff") }, func(n *Node) { n.Username = ptr("bad\r") }, func(n *Node) { n.SerialStopBits = ptr(0) }, func(n *Node) { n.SerialFlowControl = ptr(4) }, func(n *Node) { n.RDPColorDepth = ptr(17) }, func(n *Node) { n.RDPGatewayUsageMethod = ptr(4) }, func(n *Node) { n.SshKnownHostFingerprint = ptr("SHA256:bad") }, func(n *Node) { n.UseInlinePassword = ptr(true) }, func(n *Node) { n.RowVersion = math.MaxUint64 }, func(n *Node) { n.CreatedAt = "bad" }, func(n *Node) { n.UpdatedAt = "2026-10-30T00:00:00.000Z" }, func(n *Node) { n.SealSuite = 2 }, func(n *Node) { n.SealCapabilityID = ptr(uuid.NewString()) }, func(n *Node) { n.Fields = []SecretField{{Field: "password", Version: 1, Present: true}} }, func(n *Node) { n.Fields = []SecretField{{Field: "notes", Version: 2, Present: true}} }, func(n *Node) {
		n.Fields = []SecretField{{Field: "notes", Version: 1, Present: true}, {Field: "notes", Version: 1, Present: true}}
	}, func(n *Node) { n.Deleted = true; n.Fields = []SecretField{{Field: "notes", Version: 1, Present: true}} }, func(n *Node) { n.Kind = 1; n.Protocol = ptr(5); n.TunnelEnabled = ptr(true) }} {
		v := n
		mutate(&v)
		if v.Validate() != ErrFormat {
			t.Fatal("invalid node accepted")
		}
	}
	if !NodeSecretField("notes") || !NodeSecretField("inlinePassword") || NodeSecretField("password") {
		t.Fatal("field allowlist")
	}
}

func TestNodeInheritedProtocolCannotEnableUnsupportedSecretsOrRoutes(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	for _, protocol := range []int{0, 1, 3, 4, 5, 6, 7} {
		parent := node(s)
		parent.Protocol = ptr(protocol)
		if err := s.WriteNode(ctx, parent, nil, 0); err != nil {
			t.Fatal(err)
		}
		child := node(s)
		child.Kind, child.ParentID, child.UseInlinePassword = 1, &parent.ID, ptr(true)
		secret := nodeSecret(s, &child, "inlinePassword")
		err := s.WriteNode(ctx, child, []Secret{secret}, 0)
		if protocol == 0 || protocol == 1 || protocol == 7 {
			if err != nil {
				t.Fatal(protocol, err)
			}
		} else if err != ErrFormat {
			t.Fatal("inherited protocol accepted inline secret", protocol, err)
		}
		if protocol == 5 {
			routed := node(s)
			routed.Kind, routed.ParentID, routed.TunnelEnabled = 1, &parent.ID, ptr(true)
			if err := s.WriteNode(ctx, routed, nil, 0); err != ErrFormat {
				t.Fatal("inherited serial enabled VPN", err)
			}
		}
		// An explicit supported leaf protocol overrides its parent's context.
		child.ID, child.Protocol = uuid.NewString(), ptr(0)
		secret = record(s)
		secret.Ref = SecretRef{OwnerKind: "node", OwnerID: child.ID, Field: "inlinePassword"}
		if err := s.WriteNode(ctx, child, []Secret{secret}, 0); err != nil {
			t.Fatal("explicit protocol ignored", err)
		}
	}
}

func TestNodeOnlyWritePreventsInitializationMarkerReplay(t *testing.T) {
	s, _ := database(t)
	if err := s.WriteNode(context.Background(), node(s), nil, 0); err != nil {
		t.Fatal(err)
	}
	exec(t, s, "UPDATE WorkspaceMeta SET ChangeSeq=0")
	count(t, s, "SELECT count(*) FROM Keys", 1)
	count(t, s, "SELECT count(*) FROM SecretValues", 0)
	if err := s.ValidateInitialization(context.Background()); err != ErrConflict {
		t.Fatal("metadata-only node accepted old initialization marker", err)
	}
}

func TestNodeInsertAndCredentialDeleteCannotLeaveDanglingReference(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	c := credential()
	if err := s.WriteCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	n := node(s)
	n.Kind, n.Protocol, n.CredentialID = 1, ptr(0), &c.ID
	c.RowVersion, c.Deleted = 2, true
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- s.WriteNode(ctx, n, nil, 0) }()
	go func() { <-start; results <- s.WriteCredential(ctx, c, nil, 1) }()
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			winners++
		} else if err != ErrConflict {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("reference/deletion were both committed", winners)
	}
	current, err := s.ReadCredential(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, nodeErr := s.ReadNode(ctx, n.ID)
	if nodeErr != nil && nodeErr != ErrMissing {
		t.Fatal(nodeErr)
	}
	if (nodeErr == nil) == current.Deleted {
		t.Fatal("dangling reference or lost successful write")
	}
}
