package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func moveTestDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, CreatedAt, UpdatedAt) VALUES
 ('root',NULL,'Root',0,0,NULL,'old','old'),
 ('sub','root','Sub',0,0,NULL,'old','old'),
 ('deep','sub','Deep',0,0,NULL,'old','old'),
 ('source','sub','Source',1,1,0,'old','old'),
 ('other','sub','Other',1,2,0,'old','old'),
 ('leaf','deep','Leaf',1,0,0,'old','old'),
 ('outside',NULL,'Outside',1,1,0,'old','old');`)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func treeParents(t *testing.T, path string) map[string]string {
	t.Helper()
	workspace, err := loadWorkspace(path)
	if err != nil {
		t.Fatal(err)
	}
	parents := map[string]string{}
	var walk func([]*treeNode, string)
	walk = func(nodes []*treeNode, parent string) {
		for _, node := range nodes {
			parents[node.ID] = parent
			walk(node.Children, node.ID)
		}
	}
	walk(workspace.Tree, "")
	return parents
}

func TestMoveThenDuplicatePreservesNestedTree(t *testing.T) {
	path := moveTestDatabase(t)
	for _, id := range []string{"source", "other"} {
		if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{id}, "deep", "inside"}); err != nil {
			t.Fatal(err)
		}
	}
	before := treeParents(t, path)
	copy, err := duplicateWorkspaceNode(path, workspaceNodeRequest{NodeID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	after := treeParents(t, path)
	if after[copy.NodeID] != "deep" || after["source"] != "deep" || after["other"] != "deep" {
		t.Fatalf("nested nodes moved: %v", after)
	}
	delete(after, copy.NodeID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("unrelated nodes changed: %v -> %v", before, after)
	}
}

func TestMoveWorkspaceNodesOrderingAndFolderSubtree(t *testing.T) {
	for _, placement := range []string{"before", "after", "inside"} {
		t.Run(placement, func(t *testing.T) {
			path := moveTestDatabase(t)
			target := "outside"
			if placement == "inside" {
				target = "root"
			}
			if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"source", "deep"}, target, placement}); err != nil {
				t.Fatal(err)
			}
			parents := treeParents(t, path)
			want := ""
			if placement == "inside" {
				want = "root"
			}
			if parents["source"] != want || parents["deep"] != want || parents["leaf"] != "deep" || parents["other"] != "sub" {
				t.Fatal(parents)
			}
			db, err := openDatabase(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var deepOrder, sourceOrder, targetOrder int
			for id, dest := range map[string]*int{"deep": &deepOrder, "source": &sourceOrder, target: &targetOrder} {
				if err := db.QueryRow("SELECT SortOrder FROM Nodes WHERE Id = ?", id).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if deepOrder >= sourceOrder || (placement == "before" && sourceOrder >= targetOrder) || (placement == "after" && deepOrder <= targetOrder) {
				t.Fatalf("incorrect order: %d %d %d", deepOrder, sourceOrder, targetOrder)
			}
		})
	}
}

func TestMoveWorkspaceNodesRejectsInvalidMovesWithoutChanges(t *testing.T) {
	cases := []workspaceMoveNodesRequest{
		{nil, "deep", "inside"}, {make([]string, 1001), "deep", "inside"},
		{[]string{"source"}, "deep", "invalid"}, {[]string{""}, "deep", "inside"},
		{[]string{"source"}, "", "inside"}, {[]string{"source"}, "source", "before"},
		{[]string{"missing"}, "deep", "inside"}, {[]string{"source"}, "missing", "before"},
		{[]string{"source"}, "other", "inside"}, {[]string{"sub"}, "deep", "inside"},
		{[]string{"deep", "leaf"}, "outside", "before"},
	}
	for _, request := range cases {
		path := moveTestDatabase(t)
		before := treeParents(t, path)
		if err := moveWorkspaceNodes(path, request); err == nil {
			t.Fatalf("accepted invalid move: %v", request)
		}
		if after := treeParents(t, path); !reflect.DeepEqual(before, after) {
			t.Fatal("failed move changed tree")
		}
	}
}

func TestMoveWorkspaceNodesRollsBackWriteFailures(t *testing.T) {
	path := moveTestDatabase(t)
	before := treeParents(t, path)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TRIGGER reject_move BEFORE UPDATE ON Nodes WHEN OLD.Id = 'source' BEGIN SELECT RAISE(ABORT, 'write failed'); END;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"deep", "source"}, "outside", "before"}); err == nil {
		t.Fatal("expected write failure")
	}
	if after := treeParents(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("partial move survived rollback")
	}
}

func TestMoveWorkspaceNodesCLI(t *testing.T) {
	path := moveTestDatabase(t)
	var stdout, stderr bytes.Buffer
	code := runBackendCLI([]string{"-database", path, "-operation", "workspace-move-nodes"}, strings.NewReader(`{"nodeIds":["source"],"targetId":"deep","placement":"inside"}`), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"moved":true`) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	if treeParents(t, path)["source"] != "deep" {
		t.Fatal("CLI did not persist move")
	}
}

func TestMoveWorkspaceNodesPreservesSelectionTreeOrderAcrossFolders(t *testing.T) {
	path := moveTestDatabase(t)
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"outside", "source", "leaf"}, "root", "inside"}); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var leaf, source, outside int
	for id, dest := range map[string]*int{"leaf": &leaf, "source": &source, "outside": &outside} {
		if err := db.QueryRow("SELECT SortOrder FROM Nodes WHERE Id = ?", id).Scan(dest); err != nil {
			t.Fatal(err)
		}
	}
	if leaf >= source || source >= outside {
		t.Fatalf("lost visual tree order: %d %d %d", leaf, source, outside)
	}
}

func TestMoveWorkspaceNodesPreservesExactStoredIdentifiers(t *testing.T) {
	path := moveTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, CreatedAt, UpdatedAt) VALUES
 ('É-source', 'sub', 'Unicode source', 1, 3, 0, 'old', 'old'),
 ('UPPER-FOLDER', 'root', 'Upper folder', 0, 4, NULL, 'old', 'old');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"é-source"}, "upper-folder", "inside"}); err != nil {
		t.Fatal(err)
	}
	var parent string
	if err := db.QueryRow(`SELECT ParentId FROM Nodes WHERE Id = 'É-source'`).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != "UPPER-FOLDER" {
		t.Fatalf("move lost the exact parent identity: %q", parent)
	}
	// Case folding for lookup must not break SQLite's case-sensitive foreign key.
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("move introduced a dangling foreign key")
	}
}

func TestMoveWorkspaceNodesDoesNotRewriteUnchangedSiblings(t *testing.T) {
	path := moveTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TRIGGER protect_leaf BEFORE UPDATE ON Nodes WHEN OLD.Id = 'leaf'
 BEGIN SELECT RAISE(ABORT, 'unrelated sibling rewritten'); END;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"source"}, "deep", "inside"}); err != nil {
		t.Fatal(err)
	}
}

func TestMoveWorkspaceNodesRejectsInvalidStoredIDs(t *testing.T) {
	for _, id := range []string{"", " ", "a\nb", strings.Repeat("x", 129)} {
		t.Run("invalid-id", func(t *testing.T) {
			path := moveTestDatabase(t)
			db, err := openDatabase(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			_, err = db.Exec(`INSERT INTO Nodes (Id, Name, Kind, SortOrder, CreatedAt, UpdatedAt) VALUES (?, 'Invalid', 0, 0, 'old', 'old')`, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"source"}, "deep", "inside"}); err == nil {
				t.Fatal("accepted invalid stored identifier")
			}
			var parent string
			if err := db.QueryRow(`SELECT ParentId FROM Nodes WHERE Id = 'source'`).Scan(&parent); err != nil {
				t.Fatal(err)
			}
			if parent != "sub" {
				t.Fatal("invalid tree was modified")
			}
		})
	}
}

func TestMoveWorkspaceNodesRejectsIgnoredWrites(t *testing.T) {
	path := moveTestDatabase(t)
	before := treeParents(t, path)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TRIGGER ignore_move BEFORE UPDATE ON Nodes WHEN OLD.Id = 'source' BEGIN SELECT RAISE(IGNORE); END;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"deep", "source"}, "outside", "before"}); err == nil {
		t.Fatal("reported success with an ignored update")
	}
	if after := treeParents(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("partial move survived ignored update")
	}
}

func TestMoveWorkspaceNodesRejectsCorruptAncestryAndAmbiguousIDs(t *testing.T) {
	for _, setup := range []string{
		`UPDATE Nodes SET ParentId = 'deep' WHERE Id = 'sub'`,
		`UPDATE Nodes SET ParentId = 'missing' WHERE Id = 'sub'`,
		`UPDATE Nodes SET ParentId = 'other' WHERE Id = 'sub'`,
		`UPDATE Nodes SET Id = 'SOURCE' WHERE Id = 'other'`,
	} {
		t.Run("corrupt-tree", func(t *testing.T) {
			path := moveTestDatabase(t)
			db, err := openDatabase(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(setup); err != nil {
				t.Fatal(err)
			}
			if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{[]string{"source"}, "root", "inside"}); err == nil {
				t.Fatal("accepted corrupt ancestry")
			}
			var parent string
			if err := db.QueryRow(`SELECT ParentId FROM Nodes WHERE Id = 'source'`).Scan(&parent); err != nil {
				t.Fatal(err)
			}
			if parent != "sub" {
				t.Fatal("changed source despite invalid tree")
			}
		})
	}
}

func TestMoveWorkspaceNodesHandlesMaximumBatchWithSharedDeepAncestry(t *testing.T) {
	path := moveTestDatabase(t)
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	insert, err := tx.Prepare(`INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, CreatedAt, UpdatedAt) VALUES (?, ?, ?, ?, ?, 0, 'old', 'old')`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	parent := "root"
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("folder-%04d", i)
		if _, err := insert.Exec(id, parent, id, 0, 0); err != nil {
			t.Fatal(err)
		}
		parent = id
	}
	ids := make([]string, 1000)
	for i := range ids {
		ids[i] = fmt.Sprintf("connection-%04d", i)
		if _, err := insert.Exec(ids[i], parent, ids[i], 1, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := moveWorkspaceNodes(path, workspaceMoveNodesRequest{ids, "deep", "inside"}); err != nil {
		t.Fatal(err)
	}
	var moved int
	if err := db.QueryRow(`SELECT count(*) FROM Nodes WHERE ParentId = 'deep' AND Id LIKE 'connection-%'`).Scan(&moved); err != nil {
		t.Fatal(err)
	}
	if moved != len(ids) {
		t.Fatalf("moved %d of %d connections", moved, len(ids))
	}
}
