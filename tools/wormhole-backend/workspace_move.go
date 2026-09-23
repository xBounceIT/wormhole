package main

import (
	"database/sql"
	"errors"
)

type workspaceMoveNodesRequest struct {
	NodeIDs   []string `json:"nodeIds"`
	TargetID  string   `json:"targetId"`
	Placement string   `json:"placement"`
}

// Move only the selected roots; descendants keep their existing parent and settings.
func moveWorkspaceNodes(databasePath string, request workspaceMoveNodesRequest) error {
	if len(request.NodeIDs) == 0 || len(request.NodeIDs) > 1000 {
		return errors.New("invalid number of workspace nodes")
	}
	if request.Placement != "inside" && request.Placement != "before" && request.Placement != "after" {
		return errors.New("invalid workspace drop placement")
	}
	targetID, err := normalizeWorkspaceNodeID(request.TargetID)
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, rawID := range request.NodeIDs {
		id, err := normalizeWorkspaceNodeID(rawID)
		if err != nil {
			return err
		}
		selected[id] = true
	}
	if selected[targetID] {
		return errors.New("cannot move a node onto itself")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type entry struct {
		id, parent, rawID string
		rawParent         sql.NullString
		kind              int
		sortOrder         int64
	}
	entries := map[string]entry{}
	ordered := []entry{}
	rows, err := tx.Query(`SELECT Id, ParentId, Kind, SortOrder FROM Nodes ORDER BY SortOrder, Name, Id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var node entry
		if err := rows.Scan(&node.rawID, &node.rawParent, &node.kind, &node.sortOrder); err != nil {
			rows.Close()
			return err
		}
		node.id, err = normalizeWorkspaceNodeID(node.rawID)
		if err != nil {
			rows.Close()
			return err
		}
		node.parent = normalizeID(node.rawParent.String)
		if _, exists := entries[node.id]; exists {
			rows.Close()
			return errors.New("workspace node identifiers are ambiguous")
		}
		entries[node.id] = node
		ordered = append(ordered, node)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	target, exists := entries[targetID]
	if !exists {
		return errors.New("workspace target was not found")
	}
	parentID := target.parent
	if request.Placement == "inside" {
		if target.kind != 0 {
			return errors.New("workspace target must be a folder")
		}
		parentID = targetID
	}
	// Validate shared ancestry once, before any writes. Selected ancestors are never cached.
	validated := map[string]bool{}
	validateAncestors := func(start string) error {
		seen := map[string]bool{}
		for current := start; current != "" && !validated[current]; {
			if seen[current] || selected[current] {
				return errors.New("invalid workspace move ancestry")
			}
			seen[current] = true
			ancestor, exists := entries[current]
			if !exists || ancestor.kind != 0 {
				return errors.New("workspace parent folder was not found")
			}
			current = ancestor.parent
		}
		for id := range seen {
			validated[id] = true
		}
		return nil
	}
	if err := validateAncestors(parentID); err != nil {
		return err
	}
	for id := range selected {
		node, exists := entries[id]
		if !exists {
			return errors.New("workspace source was not found")
		}
		if err := validateAncestors(node.parent); err != nil {
			return err
		}
	}
	moved, siblings := []string{}, []string{}
	children := map[string][]string{}
	for _, node := range ordered {
		children[node.parent] = append(children[node.parent], node.id)
		if !selected[node.id] && node.parent == parentID {
			siblings = append(siblings, node.id)
		}
	}
	// Match the visible tree order even when selections span different folders.
	stack := []string{}
	pushChildren := func(ids []string) {
		for i := len(ids) - 1; i >= 0; i-- {
			stack = append(stack, ids[i])
		}
	}
	pushChildren(children[""])
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if selected[id] {
			moved = append(moved, id)
		} else {
			pushChildren(children[id])
		}
	}
	index := len(siblings)
	if request.Placement != "inside" {
		for i, id := range siblings {
			if id == targetID {
				index = i
				if request.Placement == "after" {
					index++
				}
				break
			}
		}
	}
	result := append(append(append([]string{}, siblings[:index]...), moved...), siblings[index:]...)
	for i, id := range result {
		node := entries[id]
		parent := node.rawParent
		if selected[id] {
			parent = sql.NullString{}
			if parentID != "" {
				parent = sql.NullString{String: entries[parentID].rawID, Valid: true}
			}
		}
		if node.rawParent == parent && node.sortOrder == int64(i) {
			continue
		}
		// Use the exact primary key: SQLite lower() only folds ASCII and prevents an index lookup.
		updated, err := tx.Exec(`UPDATE Nodes SET ParentId = ?, SortOrder = ? WHERE Id = ?`, parent, i, node.rawID)
		if err != nil {
			return err
		}
		affected, err := updated.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return errors.New("workspace node was not updated")
		}
	}
	return tx.Commit()
}
