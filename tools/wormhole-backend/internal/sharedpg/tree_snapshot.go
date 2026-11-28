package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxTreePage = 32
const treePageSQL = `SELECT workspace_id::text,user_id::text,epoch::text,change_seq::text,resolver_version::text,
has_more::text,node::text,permissions::text,boundary_id::text,row_version::text,seal_suite::text,
seal_signer_key_id::text,seal_signer_key_version::text,seal_capability_id::text,pg_catalog.encode(seal,'hex')
FROM wormhole_api_v1.get_tree(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::integer)`

type TreeCursor struct {
	After            uuid.UUID
	Epoch, ChangeSeq uint64
}
type UnverifiedTreeNode struct {
	Metadata    vaultstore.NodeMetadata
	Permissions permissions.Mask
	Boundary    uuid.UUID
	Seal        vault.RecordSeal
}

// Signatures, writer authority, key boundaries and persistent revision floors
// are NOT checked by this transport projection. Never release a secret from it.
type UnverifiedTreePage struct {
	Epoch, ChangeSeq uint64
	Nodes            []UnverifiedTreeNode
	Next             *TreeCursor
}

func validTreeCursor(cursor TreeCursor, limit int) bool {
	if limit < 1 || limit > MaxTreePage || cursor.Epoch > math.MaxInt64 || cursor.ChangeSeq > math.MaxInt64 {
		return false
	}
	if cursor.After == uuid.Nil {
		return cursor.Epoch == 0 && cursor.ChangeSeq == 0
	}
	return cursor.Epoch > 0
}

func (s *Session) TreePage(ctx context.Context, cursor TreeCursor, limit int) (*UnverifiedTreePage, error) {
	if ctx == nil || !validTreeCursor(cursor, limit) {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return nil, err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return nil, ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return nil, ErrQuery
	}
	params := make([][]byte, 5)
	params[4] = []byte(strconv.Itoa(limit))
	if cursor.After != uuid.Nil {
		params[1] = []byte(cursor.After.String())
		params[2] = []byte(strconv.FormatUint(cursor.Epoch, 10))
		params[3] = []byte(strconv.FormatUint(cursor.ChangeSeq, 10))
	}
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		params[0] = hex.AppendEncode(nil, capability)
		defer vault.Wipe(params[0])
		var e error
		rows, e = s.queryLeased(opCtx, conn, treePageSQL, params)
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	page, err := parseTreePage(rows, s.admission, cursor, limit)
	if err != nil {
		s.discardConnection(conn)
	}
	return page, err
}

func treeNumber(raw []byte, minimum, maximum uint64) (uint64, bool) {
	value, err := strconv.ParseUint(string(raw), 10, 64)
	return value, err == nil && value >= minimum && value <= maximum && strconv.FormatUint(value, 10) == string(raw)
}
func treeID(raw []byte) (uuid.UUID, bool) {
	id, err := uuid.Parse(string(raw))
	return id, err == nil && id != uuid.Nil && id.String() == string(raw)
}

func parseTreePage(rows [][][]byte, request AdmissionRequest, cursor TreeCursor, limit int) (*UnverifiedTreePage, error) {
	if !validTreeCursor(cursor, limit) || len(rows) == 0 || len(rows) > limit {
		return nil, ErrAdmissionResponse
	}
	page := &UnverifiedTreePage{}
	previous := cursor.After
	var more bool
	for index, row := range rows {
		if len(row) != 15 || string(row[0]) != request.WorkspaceID.String() || string(row[1]) != request.UserID.String() || string(row[4]) != "1" {
			return nil, ErrAdmissionResponse
		}
		epoch, ok := treeNumber(row[2], 1, math.MaxInt64)
		if !ok {
			return nil, ErrAdmissionResponse
		}
		sequence, ok := treeNumber(row[3], 0, math.MaxInt64)
		if !ok {
			return nil, ErrAdmissionResponse
		}
		if string(row[5]) != "true" && string(row[5]) != "false" {
			return nil, ErrAdmissionResponse
		}
		rowMore := string(row[5]) == "true"
		if index == 0 {
			page.Epoch = epoch
			page.ChangeSeq = sequence
			more = rowMore
		}
		if epoch != page.Epoch || sequence != page.ChangeSeq || more != rowMore || (cursor.After != uuid.Nil && (epoch != cursor.Epoch || sequence != cursor.ChangeSeq)) {
			return nil, ErrAdmissionResponse
		}
		if row[6] == nil {
			if len(rows) != 1 || more {
				return nil, ErrAdmissionResponse
			}
			for _, value := range row[7:] {
				if value != nil {
					return nil, ErrAdmissionResponse
				}
			}
			return page, nil
		}
		metadata, err := parseTreeMetadata(row[6])
		if err != nil {
			return nil, err
		}
		id := uuid.MustParse(metadata.ID)
		if bytes.Compare(id[:], previous[:]) <= 0 {
			return nil, ErrAdmissionResponse
		}
		previous = id
		mask, err := parseNodePermissions([][][]byte{{row[7]}})
		if err != nil || mask&permissions.View == 0 {
			return nil, ErrAdmissionResponse
		}
		boundary, ok := treeID(row[8])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		revision, ok := treeNumber(row[9], 1, math.MaxInt64)
		if !ok || string(row[10]) != "2" {
			return nil, ErrAdmissionResponse
		}
		signer, ok := treeID(row[11])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		keyVersion, ok := treeNumber(row[12], 1, math.MaxInt32)
		if !ok {
			return nil, ErrAdmissionResponse
		}
		var capability *string
		if row[13] != nil {
			v, ok := treeID(row[13])
			if !ok {
				return nil, ErrAdmissionResponse
			}
			text := v.String()
			capability = &text
		}
		if len(row[14]) != 128 {
			return nil, ErrAdmissionResponse
		}
		signature, err := hex.DecodeString(string(row[14]))
		if err != nil {
			return nil, ErrAdmissionResponse
		}
		page.Nodes = append(page.Nodes, UnverifiedTreeNode{metadata, mask, boundary, vault.RecordSeal{FormatVersion: vault.FormatVersion, SignerKeyID: signer.String(), SignerKeyVersion: uint32(keyVersion), CapabilityID: capability, Revision: revision, Signature: signature}})
	}
	if more {
		if len(page.Nodes) != limit {
			return nil, ErrAdmissionResponse
		}
		page.Next = &TreeCursor{previous, page.Epoch, page.ChangeSeq}
	}
	return page, nil
}

// NodeMetadata is a flat, fully populated JSON object: explicit NULL represents
// inheritance. Reject missing fields, duplicate keys and case-insensitive aliases
// before Go's ordinary decoder can assign them different interpretations.
func parseTreeMetadata(raw []byte) (vaultstore.NodeMetadata, error) {
	var node vaultstore.NodeMetadata
	if len(raw) == 0 || len(raw) > 512*1024 || !utf8.Valid(raw) {
		return node, ErrAdmissionResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return node, ErrAdmissionResponse
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(fields) >= 64 {
			return node, ErrAdmissionResponse
		}
		if _, exists := fields[key]; exists {
			return node, ErrAdmissionResponse
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return node, ErrAdmissionResponse
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return node, ErrAdmissionResponse
	}
	canonical, _ := json.Marshal(node)
	var expected map[string]json.RawMessage
	json.Unmarshal(canonical, &expected)
	if imported, present := fields["imported"]; present {
		var reference vaultstore.NodeImportReference
		if json.Unmarshal(imported, &reference) != nil {
			return node, ErrAdmissionResponse
		}
		if _, err := strictCatalogObject(imported, reference); err != nil {
			return node, ErrAdmissionResponse
		}
		expected["imported"] = json.RawMessage(`{}`)
	}
	if len(fields) != len(expected) {
		return node, ErrAdmissionResponse
	}
	for key, value := range expected {
		actual, ok := fields[key]
		if !ok || (string(value) != "null" && string(actual) == "null") {
			return node, ErrAdmissionResponse
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&node) != nil || node.Validate() != nil {
		return vaultstore.NodeMetadata{}, ErrAdmissionResponse
	}
	return node, nil
}
