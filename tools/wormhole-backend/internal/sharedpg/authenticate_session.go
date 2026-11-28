package sharedpg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const sessionChallengeSQL = `SELECT workspace_id::text,user_id::text,device_id::text,auth_epoch::text,
backend_pid::text,expires_at::text,pg_catalog.encode(server_nonce,'hex'),pg_catalog.encode(salt,'hex'),iterations::text,
pg_catalog.pg_backend_pid()::text FROM wormhole_api_v1.session_challenge(pg_catalog.decode($1,'hex'),pg_catalog.decode($2,'hex'))`
const sessionProveSQL = `SELECT pg_catalog.encode(wormhole_api_v1.session_prove(pg_catalog.decode($1,'hex')),'hex')`
const authenticatedSessionStartSQL = `SELECT session_id::text,workspace_id::text,user_id::text,device_id::text,
is_admin::text,min_api::text,max_api::text,epoch::text,change_seq::text,
pg_catalog.encode(signed_profile,'hex') FROM wormhole_api_v1.session_start($1::integer,$2::text,$3::text,pg_catalog.decode($4,'hex'))`

func wipeQueryRows(rows [][][]byte) {
	for _, row := range rows {
		for _, value := range row {
			vault.Wipe(value)
		}
	}
}

// AuthenticateSession proves the current derived login credential and performs
// audited admission in one short, pinned transaction. The retained capability is
// native memory (mandatory page locking at Hardened+), never the password/derived
// login input. There is no legacy
// fallback or retry. SignedProfile still requires the caller's independent trust
// verification. On failure the owner is invalidated; Close must confirm cleanup.
func (s *Session) AuthenticateSession(ctx context.Context, request AdmissionRequest, derived []byte) (result *UnverifiedAdmission, err error) {
	if ctx == nil || request.Validate() != nil || len(derived) != 32 {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = take(ctx, s.control); err != nil {
		return nil, err
	}
	defer give(s.control)
	if s.capability != nil {
		return nil, ErrSessionStarted
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
	defer func() {
		if err != nil {
			s.discardConnection(conn) // Closing the backend also rolls back an uncertain transaction.
			if result != nil {
				vault.Wipe(result.SignedProfile)
				result = nil
			}
			if s.capability != nil {
				if s.capability.Close() != nil {
					err = ErrSessionCleanup
				} else {
					s.capability = nil
				}
			}
		}
	}()
	if conn.TxStatus() != 'I' {
		return nil, ErrConfiguration
	}
	command := func(sql string) error {
		rows, e := s.queryLeased(opCtx, conn, sql, nil)
		defer wipeQueryRows(rows)
		if e != nil {
			return e
		}
		if len(rows) != 0 {
			return ErrAdmissionResponse
		}
		return nil
	}
	s.capability, err = securemem.New(32, s.requireLocked)
	if err != nil {
		return nil, err
	}
	var commitment [32]byte
	err = s.capability.With(func(capability []byte) error {
		rand.Read(capability)
		commitment = sha256.Sum256(capability)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = command("BEGIN"); err != nil {
		return nil, err
	}
	if conn.TxStatus() != 'T' {
		return nil, ErrAdmissionResponse
	}
	nonce := NewSessionProofNonce()
	rows, err := s.queryLeased(opCtx, conn, sessionChallengeSQL, [][]byte{hex.AppendEncode(nil, nonce), hex.AppendEncode(nil, commitment[:])})
	if err != nil {
		return nil, err
	}
	challenge, err := parseSessionChallenge(rows, request, nonce, commitment)
	wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	proof, err := ProveSession(derived, challenge.Binding, nonce, challenge)
	if err != nil {
		return nil, err
	}
	defer proof.Wipe()
	encodedProof := hex.AppendEncode(nil, proof.Client)
	defer vault.Wipe(encodedProof)
	rows, err = s.queryLeased(opCtx, conn, sessionProveSQL, [][]byte{encodedProof})
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || len(rows[0]) != 1 || len(rows[0][0]) != 64 {
		wipeQueryRows(rows)
		return nil, ErrAdmissionResponse
	}
	server := make([]byte, 32)
	_, decodeErr := hex.Decode(server, rows[0][0])
	wipeQueryRows(rows)
	err = proof.VerifyServer(server)
	vault.Wipe(server)
	if decodeErr != nil || err != nil {
		return nil, ErrAuthentication
	}
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		var e error
		rows, e = s.queryLeased(opCtx, conn, authenticatedSessionStartSQL, [][]byte{[]byte(strconv.FormatInt(int64(request.API), 10)), []byte(request.AppVersion), []byte(request.Source), encoded})
		return e
	})
	if err != nil {
		return nil, err
	}
	result, err = parseAdmission(rows, request)
	wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	if err = command("COMMIT"); err != nil {
		return result, err
	}
	if conn.TxStatus() != 'I' {
		return result, ErrAdmissionResponse
	}
	result.MemoryLockWarning = !s.capability.Locked()
	s.admission = request
	s.authEpoch = challenge.Binding.Epoch
	s.administrator = result.IsAdmin
	return result, nil
}

func parseSessionChallenge(rows [][][]byte, request AdmissionRequest, nonce []byte, commitment [32]byte) (SessionProofChallenge, error) {
	var c SessionProofChallenge
	if len(rows) != 1 || len(rows[0]) != 10 {
		return c, ErrAdmissionResponse
	}
	r := rows[0]
	for i, expected := range []uuid.UUID{request.WorkspaceID, request.UserID, request.DeviceID} {
		if string(r[i]) != expected.String() {
			return c, ErrAdmissionResponse
		}
	}
	numbers := [4]int64{}
	for i, index := range []int{3, 4, 5, 8} {
		n, e := strconv.ParseInt(string(r[index]), 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != string(r[index]) {
			return c, ErrAdmissionResponse
		}
		numbers[i] = n
	}
	if numbers[1] > 2147483647 || string(r[4]) != string(r[9]) || numbers[3] < SCRAMIterations || numbers[3] > 1000000 || len(r[6]) != 64 || len(r[7]) < 32 || len(r[7]) > 128 || len(r[7])%2 != 0 {
		return c, ErrAdmissionResponse
	}
	c.Binding = SessionProofBinding{WorkspaceID: request.WorkspaceID, UserID: request.UserID, DeviceID: request.DeviceID, Epoch: uint64(numbers[0]), BackendPID: int32(numbers[1]), ExpiresAt: numbers[2], CapabilityHash: commitment}
	c.ClientNonce = append([]byte(nil), nonce...)
	c.ServerNonce = make([]byte, 32)
	c.Salt = make([]byte, len(r[7])/2)
	c.Iterations = int(numbers[3])
	if _, err := hex.Decode(c.ServerNonce, r[6]); err != nil {
		return SessionProofChallenge{}, ErrAdmissionResponse
	}
	if _, err := hex.Decode(c.Salt, r[7]); err != nil {
		return SessionProofChallenge{}, ErrAdmissionResponse
	}
	if _, err := c.authMessage(c.Binding, nonce); err != nil {
		return SessionProofChallenge{}, ErrAdmissionResponse
	}
	return c, nil
}
