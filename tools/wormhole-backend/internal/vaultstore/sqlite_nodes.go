package vaultstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
)

var _ NodeStore = (*SQLite)(nil)

func (s *SQLite) migrateNodes(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, nodeSchema); err != nil {
		return storeError(err)
	}
	if err := requireOne(tx.ExecContext(ctx, `UPDATE WorkspaceMeta SET SchemaVersion=4 WHERE Singleton=1 AND SchemaVersion=3;`)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return storeError(err)
	}
	return nil
}

func scanNode(row scanner) (Node, error) {
	var n Node
	var manifest []byte
	var plain bool
	targets := append(nodeMetadataTargets(&n), &n.CreatedAt, &n.UpdatedAt, &n.RowVersion, &n.Deleted, &manifest, &n.SealSuite, &n.SealSignerKeyID, &n.SealSignerKeyVersion, &n.SealCapabilityID, &n.Seal, &plain)
	err := row.Scan(targets...)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrMissing
	}
	if err != nil {
		return Node{}, storeError(err)
	}
	if !plain || len(manifest) > 2048 || json.Unmarshal(manifest, &n.Fields) != nil {
		return Node{}, ErrFormat
	}
	canonical, _ := json.Marshal(n.Fields)
	if !bytes.Equal(manifest, canonical) || n.Validate() != nil {
		return Node{}, ErrFormat
	}
	return n, nil
}

func (s *SQLite) ReadNode(ctx context.Context, id string) (Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Node{}, ErrClosed
	}
	if !validID(id) {
		return Node{}, ErrFormat
	}
	return scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Id=?;`, id))
}

func (s *SQLite) ListNodes(ctx context.Context, after string, limit int) ([]Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if (after != "" && !validID(after)) || limit < 1 || limit > 128 {
		return nil, ErrFormat
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Deleted=0 AND Id>? ORDER BY Id LIMIT ?;`, after, limit)
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	values := make([]Node, 0, limit)
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, n)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(err)
	}
	return values, nil
}

func (s *SQLite) WriteNode(ctx context.Context, value Node, secrets []Secret, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeError(err)
	}
	defer tx.Rollback()
	if err := s.writeNode(ctx, tx, value, secrets, expected); err != nil {
		return err
	}
	return commitChange(ctx, tx)
}

func (s *SQLite) writeNode(ctx context.Context, tx *sql.Tx, value Node, secrets []Secret, expected uint64) error {
	if value.Validate() != nil || expected >= math.MaxInt64 || value.RowVersion != expected+1 || len(secrets) > 3 || value.SealSignerKeyID != s.identity.Root.ID || value.SealSignerKeyVersion != s.identity.Root.Version {
		return ErrFormat
	}
	previous, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Id=?;`, value.ID))
	if errors.Is(err, ErrMissing) {
		if expected != 0 || value.Deleted {
			return ErrConflict
		}
	} else if err != nil {
		return err
	} else if previous.RowVersion != expected || previous.Deleted || previous.Kind != value.Kind || previous.CreatedAt != value.CreatedAt {
		return ErrConflict
	}
	if err := validateNodeReferences(ctx, tx, value, previous); err != nil {
		return err
	}
	if err := s.writeAggregateFields(ctx, tx, "node", value.ID, previous.Fields, value.Fields, secrets); err != nil {
		return err
	}
	manifest, _ := json.Marshal(value.Fields)
	args := append(nodeMetadataTargets(&value), value.CreatedAt, value.UpdatedAt, value.RowVersion, value.Deleted, manifest, value.SealSuite, value.SealSignerKeyID, value.SealSignerKeyVersion, value.SealCapabilityID, value.Seal)
	if err := requireOne(tx.ExecContext(ctx, writeNodeSQL, args...)); err != nil {
		return err
	}
	return nil
}

func sameOptionalID(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func validateNodeReferences(ctx context.Context, tx *sql.Tx, n, previous Node) error {
	if n.Deleted {
		var children bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM Nodes WHERE ParentId=? AND Deleted=0);`, n.ID).Scan(&children); err != nil {
			return storeError(err)
		}
		if children {
			return ErrConflict
		}
		return nil
	}
	// Slot-shaped metadata is reserved; it cannot become active without a slot
	// catalog and the shared resolver/permission implementation.
	if n.CredentialMode != nil && *n.CredentialMode == 3 {
		return ErrFormat
	}
	depth := 1
	parent := n.ParentID
	seen := map[string]bool{n.ID: true}
	protocol := n.Protocol
	for parent != nil {
		if seen[*parent] || depth >= MaxNodeDepth {
			return ErrConflict
		}
		seen[*parent] = true
		depth++
		ancestor, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Id=?;`, *parent))
		if err != nil {
			return err
		}
		if ancestor.Deleted || ancestor.Kind != 0 {
			return ErrConflict
		}
		if protocol == nil {
			protocol = ancestor.Protocol
		}
		parent = ancestor.ParentID
	}
	resolvedProtocol := 0
	if protocol != nil {
		resolvedProtocol = *protocol
	}
	if n.Kind == 1 {
		if nodeInline(n.NodeMetadata) && resolvedProtocol != 0 && resolvedProtocol != 1 && resolvedProtocol != 7 {
			return ErrFormat
		}
		if resolvedProtocol == 5 && (n.CredentialID != nil || n.CredentialSlotID != nil || n.TunnelConfigID != nil || (n.TunnelEnabled != nil && *n.TunnelEnabled)) {
			return ErrFormat
		}
	}
	if previous.RowVersion != 0 && !sameOptionalID(n.ParentID, previous.ParentID) {
		// Moving a folder must not push any descendant past the resolver depth cap.
		// Work stays in SQLite, uses the parent index and observes the request context.
		var height int
		err := tx.QueryRowContext(ctx, `WITH RECURSIVE subtree(Id,Depth) AS (SELECT Id,0 FROM Nodes WHERE Id=? AND Deleted=0 UNION ALL SELECT child.Id,subtree.Depth+1 FROM Nodes child JOIN subtree ON child.ParentId=subtree.Id WHERE child.Deleted=0 AND subtree.Depth<?) SELECT COALESCE(MAX(Depth),0) FROM subtree;`, n.ID, MaxNodeDepth).Scan(&height)
		if err != nil {
			return storeError(err)
		}
		if depth+height > MaxNodeDepth {
			return ErrConflict
		}
	}
	if n.TunnelConfigID != nil {
		t, err := scanTunnel(tx.QueryRowContext(ctx, `SELECT `+tunnelColumns+` FROM TunnelConfigs WHERE Id=?;`, *n.TunnelConfigID))
		if err != nil {
			return err
		}
		if t.Deleted {
			return ErrConflict
		}
	}
	for _, reference := range []struct {
		id      *string
		gateway bool
	}{{n.CredentialID, false}, {n.RDPGatewayCredentialID, true}} {
		if reference.id == nil {
			continue
		}
		c, err := scanCredential(tx.QueryRowContext(ctx, `SELECT `+credentialColumns+` FROM CredentialProfiles WHERE Id=?;`, *reference.id))
		if err != nil {
			return err
		}
		if c.Deleted {
			return ErrConflict
		}
		if reference.gateway {
			if c.Protocol != "rdp" {
				return ErrConflict
			}
		} else if n.Kind == 1 {
			want := ""
			switch resolvedProtocol {
			case 0, 7:
				want = "ssh"
			case 1:
				want = "rdp"
			case 6:
				want = "vnc"
			}
			if want == "" || c.Protocol != want {
				return ErrConflict
			}
		}
	}
	return nil
}
