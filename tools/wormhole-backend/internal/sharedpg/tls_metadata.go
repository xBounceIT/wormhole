package sharedpg

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const tlsTrustBundleSQL = `SELECT workspace_id::text,tls_sequence::text,pg_catalog.encode(signed_bundle,'hex') FROM wormhole_api_v1.tls_trust_bundle(pg_catalog.decode($1,'hex'))`

// TLSTrustBundle reads public signed metadata using this session's native
// capability. The returned document is UNVERIFIED: callers must authenticate its
// organisation signature and durable sequence/digest floor before using it.
func (s *Session) TLSTrustBundle(ctx context.Context) (*TLSTrustBundle, error) {
	if ctx == nil {
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
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		var e error
		rows, e = s.queryLeased(opCtx, conn, tlsTrustBundleSQL, [][]byte{encoded})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	bundle, err := parseTLSTrustMetadata(rows, s.admission)
	if err != nil {
		s.discardConnection(conn)
	}
	return bundle, err
}

func parseTLSTrustMetadata(rows [][][]byte, request AdmissionRequest) (*TLSTrustBundle, error) {
	if len(rows) != 1 || len(rows[0]) != 3 || len(rows[0][2]) == 0 || len(rows[0][2]) > 2*MaxTLSTrustBundleBytes {
		return nil, ErrAdmissionResponse
	}
	raw, err := hex.DecodeString(string(rows[0][2]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	bundle, err := DecodeTLSTrustBundle(raw)
	if err != nil || bundle.WorkspaceID != request.WorkspaceID || bundle.WorkspaceID.String() != string(rows[0][0]) || strconv.FormatUint(bundle.Sequence, 10) != string(rows[0][1]) {
		return nil, ErrAdmissionResponse
	}
	return &bundle, nil
}
