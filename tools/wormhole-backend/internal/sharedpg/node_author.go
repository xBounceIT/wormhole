package sharedpg

import (
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const nodeAuthorSQL = `SELECT workspace_id::text,node_id::text,author_id::text,epoch::text,change_seq::text,
signing_key_id::text,signing_key_version::text,state_sequence::text,pg_catalog.encode(signed_state,'hex'),
suite::text,pg_catalog.encode(public_key,'hex'),cert_signer_key_id::text,cert_signer_key_version::text,
cert_revision::text,pg_catalog.encode(cert_signature,'hex'),
pg_catalog.encode((pg_catalog.to_jsonb(a)->>'enrollment_certificate')::pg_catalog.bytea,'hex')
FROM wormhole_api_v1.node_author(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint) a`

type UnverifiedNodeAuthor struct {
	Key   vault.KeyRef
	State *vault.UserKeyState
	// May be absent so an authentic revocation can still be observed.
	Certificate           *vault.UserKeyCertificate
	EnrollmentCertificate *vault.UserEnrollmentCertificate
}

// NodeAuthor retrieves only public verification material bound to a tree page.
// It does not authenticate the returned state or certificate.
func (s *Session) NodeAuthor(ctx context.Context, node uuid.UUID, epoch, sequence uint64) (*UnverifiedNodeAuthor, error) {
	if ctx == nil || !validTreeCursor(TreeCursor{node, epoch, sequence}, 1) || node == uuid.Nil {
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
		rows, e = s.queryLeased(opCtx, conn, nodeAuthorSQL, [][]byte{encoded, []byte(node.String()), []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(sequence, 10))})
		return e
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	result, err := parseNodeAuthor(rows, s.admission, node, epoch, sequence)
	if err != nil {
		s.discardConnection(conn)
	}
	return result, err
}

func parseNodeAuthor(rows [][][]byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedNodeAuthor, error) {
	if len(rows) != 1 || (len(rows[0]) != 15 && len(rows[0]) != 16) {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != node.String() || string(r[3]) != strconv.FormatUint(epoch, 10) || string(r[4]) != strconv.FormatUint(sequence, 10) {
		return nil, ErrAdmissionResponse
	}
	author, ok := treeID(r[2])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	key, ok := treeID(r[5])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	version, ok := treeNumber(r[6], 1, math.MaxInt32)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	request.UserID = author
	state, err := parseAccountKeyState([][][]byte{{r[8], r[7]}}, request)
	if err != nil {
		return nil, err
	}
	result := &UnverifiedNodeAuthor{Key: vault.KeyRef{ID: key, Version: uint32(version)}, State: state}
	if len(r) == 16 && r[15] != nil {
		for _, v := range r[9:15] {
			if v != nil {
				return nil, ErrAdmissionResponse
			}
		}
		if len(r[15]) == 0 || len(r[15]) > vault.MaxUserEnrollmentCertificateBytes*2 {
			return nil, ErrAdmissionResponse
		}
		raw, err := hex.DecodeString(string(r[15]))
		if err != nil {
			return nil, ErrAdmissionResponse
		}
		c, err := vault.DecodeUserEnrollmentCertificate(raw)
		if err != nil || c.Manifest.Context.WorkspaceID != request.WorkspaceID || c.Manifest.Context.UserID != author || result.Key != (vault.KeyRef{ID: c.Rekey.SigningKeyID, Version: c.Rekey.KeyVersion}) {
			return nil, ErrAdmissionResponse
		}
		result.EnrollmentCertificate = &c
		return result, nil
	}
	if r[9] == nil {
		for _, value := range r[10:] {
			if value != nil {
				return nil, ErrAdmissionResponse
			}
		}
		return result, nil
	}
	if string(r[9]) != "1" || len(r[10]) != 64 || len(r[14]) != 128 {
		return nil, ErrAdmissionResponse
	}
	public, e := hex.DecodeString(string(r[10]))
	signature, e2 := hex.DecodeString(string(r[14]))
	if e != nil || e2 != nil {
		return nil, ErrAdmissionResponse
	}
	signer, ok := treeID(r[11])
	if !ok || signer == key {
		return nil, ErrAdmissionResponse
	}
	signerVersion, ok := treeNumber(r[12], 1, math.MaxInt32)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	revision, ok := treeNumber(r[13], 1, math.MaxInt64)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	result.Certificate = &vault.UserKeyCertificate{FormatVersion: vault.FormatVersion, WorkspaceID: request.WorkspaceID, UserID: author, Key: result.Key, Kind: "user-sign", Suite: 1, PublicKey: public, Signer: vault.KeyRef{ID: signer, Version: uint32(signerVersion)}, Revision: revision, Signature: signature}
	return result, nil
}

// Called only after the author chain and copy signature have been verified.
func (a *UnverifiedNodeAuthor) signingPublic() []byte {
	if a.EnrollmentCertificate != nil {
		return a.EnrollmentCertificate.Rekey.Public.Signing
	}
	if a.Certificate != nil {
		return a.Certificate.PublicKey
	}
	return nil
}
