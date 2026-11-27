package sharedpg

import (
	"context"
	"encoding/hex"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const beginUseSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,expires_at::text
 FROM wormhole_api_v1.begin_use(pg_catalog.decode($1,'hex'),$2::uuid,$3)`

const beginUsePathSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,expires_at::text,protocol_path
 FROM wormhole_api_v1.begin_use_path(pg_catalog.decode($1,'hex'),$2::uuid,$3,$4::text)`

const beginTunnelUseSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,expires_at::text,protocol_path
 FROM wormhole_api_v1.begin_tunnel_use(pg_catalog.decode($1,'hex'),$2::uuid,$3)`

const connectionPathsAvailableSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.connection_plan_path(bytea,uuid,text)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.begin_use_path(bytea,uuid,text,text)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.fetch_secret_path(bytea,uuid,uuid,text)') IS NOT NULL)::text`

// DefaultConnectionPath requests the default account path of the authenticated
// node protocol. The receipt always identifies the actual path.
const DefaultConnectionPath = "default"

func (s *Session) ConnectionPathsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, connectionPathsAvailableSQL)
}

func (s *Session) TunnelUseSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.begin_tunnel_use(bytea,uuid,text)') IS NOT NULL)::text`)
}

// UseIntent is native-only and is not authorization to decrypt or release a secret.
// Fetch must independently require committed audit, current permissions and a
// matching single-use ticket; the vault must verify the signed resolution chain.
type UseIntent struct {
	Ticket, Node     uuid.UUID
	Epoch, ChangeSeq uint64
	ExpiresAt        int64
	Path             string
}

// BeginUse returns only after the standalone audit transaction has completed.
// Never retry automatically: a lost response can still mean an audit was committed.
func (s *Session) BeginUse(ctx context.Context, node uuid.UUID, source string) (*UseIntent, error) {
	return s.beginUse(ctx, node, source, "", false)
}

// BeginUsePath commits the explicit protocol path in the audit and use ticket.
func (s *Session) BeginUsePath(ctx context.Context, node uuid.UUID, source, path string) (*UseIntent, error) {
	if path != DefaultConnectionPath && !credentialReleasePath(path) {
		return nil, ErrConfiguration
	}
	return s.beginUse(ctx, node, source, path, false)
}

// BeginTunnelUse authorizes a web tunnel graph without borrowing a Reveal
// account. The receipt identifies the actual path of the current node.
func (s *Session) BeginTunnelUse(ctx context.Context, node uuid.UUID, source string) (*UseIntent, error) {
	return s.beginUse(ctx, node, source, DefaultConnectionPath, true)
}

func credentialReleasePath(path string) bool {
	return path == "ssh" || path == "sftp" || path == "vnc" || path == "rdp"
}

// DefaultAuditedPath returns the explicit path for a protocol supported by the
// path-bound release. Other protocols still have their original audited API.
func DefaultAuditedPath(protocol int) string {
	path := resolver.DefaultPath(protocol)
	if credentialReleasePath(path) {
		return path
	}
	return ""
}

func (s *Session) beginUse(ctx context.Context, node uuid.UUID, source, path string, tunnel bool) (*UseIntent, error) {
	if ctx == nil || node == uuid.Nil || (source != "ui" && source != "mcp") {
		return nil, ErrConfiguration
	}
	statement := beginUseSQL
	args := [][]byte{nil, []byte(node.String()), []byte(source)}
	if tunnel {
		statement = beginTunnelUseSQL
	} else if path != "" {
		statement, args = beginUsePathSQL, append(args, []byte(path))
	}
	var result *UseIntent
	err := s.beginUseOperation(ctx, statement, args, func(rows [][][]byte) error {
		actual := ""
		if path != "" {
			if len(rows) != 1 || len(rows[0]) != 9 {
				return ErrAdmissionResponse
			}
			actual = string(rows[0][8])
			if path == DefaultConnectionPath {
				if rows[0][8] != nil && !credentialReleasePath(actual) && !(tunnel && actual == WebConnectionPlanPath) {
					return ErrAdmissionResponse
				}
			} else if actual != path {
				return ErrAdmissionResponse
			}
			rows = [][][]byte{rows[0][:8]}
		}
		var err error
		result, err = parseUseIntent(rows, s.admission, node)
		if err == nil {
			result.Path = actual
		}
		return err
	})
	return result, err
}

// Both purposes require a standalone committed audit transaction on the original
// admitted connection. Decode while holding the lease so malformed receipts
// discard that connection before another operation can reuse it.
func (s *Session) beginUseOperation(ctx context.Context, query string, params [][]byte, decode func([][][]byte) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 {
		return ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrQuery
	}
	if conn.TxStatus() != 'I' {
		return ErrConfiguration
	}
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		params[0] = hex.AppendEncode(nil, capability)
		defer vault.Wipe(params[0])
		var e error
		rows, e = s.queryLeased(opCtx, conn, query, params)
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		s.discardConnection(conn)
		return err
	}
	if conn.TxStatus() != 'I' {
		s.discardConnection(conn)
		return ErrAdmissionResponse
	}
	err = decode(rows)
	if err != nil {
		s.discardConnection(conn)
	}
	return err
}

func parseUseIntent(rows [][][]byte, request AdmissionRequest, node uuid.UUID) (*UseIntent, error) {
	if len(rows) != 1 || len(rows[0]) != 8 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	if string(row[0]) != request.WorkspaceID.String() || string(row[1]) != request.UserID.String() || string(row[2]) != request.DeviceID.String() || string(row[3]) != node.String() {
		return nil, ErrAdmissionResponse
	}
	ticket, ok := treeID(row[4])
	epoch, ok2 := treeNumber(row[5], 1, math.MaxInt64)
	seq, ok3 := treeNumber(row[6], 0, math.MaxInt64)
	expiry, ok4 := treeNumber(row[7], 1, math.MaxInt64)
	if !ok || !ok2 || !ok3 || !ok4 {
		return nil, ErrAdmissionResponse
	}
	return &UseIntent{Ticket: ticket, Node: node, Epoch: epoch, ChangeSeq: seq, ExpiresAt: int64(expiry)}, nil
}
