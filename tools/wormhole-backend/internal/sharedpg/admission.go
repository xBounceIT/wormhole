package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"

	"github.com/google/uuid"
)

var (
	ErrIdentityUnavailable   = errors.New("workspace account or device is unavailable")
	ErrProvisioning          = errors.New("workspace provisioning is incomplete")
	ErrTLSRequired           = errors.New("workspace requires TLS")
	ErrAPIVersion            = errors.New("workspace API version is unsupported")
	ErrAuditUnavailable      = errors.New("workspace audit is unavailable")
	ErrTransactionIsolation  = errors.New("workspace transaction isolation is unsupported")
	ErrAdmissionResponse     = errors.New("invalid workspace admission response")
	ErrPasswordChangePayload = errors.New("invalid workspace password change payload")
	ErrDeviceCredentials     = errors.New("workspace device credentials could not be updated")
	ErrAccountRevision       = errors.New("workspace account revision changed")
	ErrTLSMetadata           = errors.New("workspace TLS metadata unavailable")
)

var appVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$`)

type AdmissionRequest struct {
	API        int32
	AppVersion string
	Source     string
	// Expected identities must come from the caller's authenticated configuration.
	WorkspaceID uuid.UUID
	UserID      uuid.UUID
	DeviceID    uuid.UUID
}

// UnverifiedAdmission is a structurally checked server response, not authority to
// unlock data or enable operations. The native caller must verify SignedProfile
// against its pinned trust and check epoch/API policy before accepting it. Never
// send this structure or profile bytes to the renderer as trusted policy.
type UnverifiedAdmission struct {
	SessionID         uuid.UUID
	WorkspaceID       uuid.UUID
	UserID            uuid.UUID
	DeviceID          uuid.UUID
	IsAdmin           bool
	MinAPI            int32
	MaxAPI            int32
	Epoch             int64
	ChangeSeq         int64
	SignedProfile     []byte
	MemoryLockWarning bool // Native allocation status, never read from SQL metadata.
}

const sessionStartSQL = `SELECT session_id::text,workspace_id::text,user_id::text,device_id::text,
is_admin::text,min_api::text,max_api::text,epoch::text,change_seq::text,
pg_catalog.encode(signed_profile,'hex') FROM wormhole_api_v1.session_start($1::integer,$2::text,$3::text)`

// StartSession performs one audited admission request without automatic retry.
// A revoked identity or malformed response invalidates the owner; the caller
// must still Close it to confirm cleanup of both connections.
func (s *Session) StartSession(ctx context.Context, request AdmissionRequest) (*UnverifiedAdmission, error) {
	if ctx == nil || request.Validate() != nil {
		return nil, ErrConfiguration
	}
	rows, err := s.Query(ctx, sessionStartSQL, [][]byte{[]byte(strconv.FormatInt(int64(request.API), 10)), []byte(request.AppVersion), []byte(request.Source)})
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, row := range rows {
			for _, value := range row {
				clear(value)
			}
		}
	}()
	result, err := parseAdmission(rows, request)
	if err != nil {
		s.ready.Store(false)
		s.cancel()
		return nil, err
	}
	return result, nil
}

// Validate rejects malformed admission metadata before a login proof is sent.
func (r AdmissionRequest) Validate() error {
	if r.API < 1 || len(r.AppVersion) > 64 || !appVersionPattern.MatchString(r.AppVersion) ||
		(r.Source != "ui" && r.Source != "mcp") || r.WorkspaceID == uuid.Nil || r.UserID == uuid.Nil || r.DeviceID == uuid.Nil {
		return ErrConfiguration
	}
	return nil
}

func parseAdmission(rows [][][]byte, request AdmissionRequest) (*UnverifiedAdmission, error) {
	if len(rows) != 1 || len(rows[0]) != 10 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	result := &UnverifiedAdmission{}
	for i, target := range []*uuid.UUID{&result.SessionID, &result.WorkspaceID, &result.UserID, &result.DeviceID} {
		id, err := uuid.Parse(string(row[i]))
		if err != nil || id == uuid.Nil || id.String() != string(row[i]) {
			return nil, ErrAdmissionResponse
		}
		*target = id
	}
	if result.WorkspaceID != request.WorkspaceID || result.UserID != request.UserID || result.DeviceID != request.DeviceID {
		return nil, ErrAdmissionResponse
	}
	switch string(row[4]) {
	case "true":
		result.IsAdmin = true
	case "false":
	default:
		return nil, ErrAdmissionResponse
	}
	numbers := [4]int64{}
	for i := range numbers {
		value, err := strconv.ParseInt(string(row[5+i]), 10, 64)
		if err != nil || value < 0 || strconv.FormatInt(value, 10) != string(row[5+i]) {
			return nil, ErrAdmissionResponse
		}
		numbers[i] = value
	}
	if numbers[0] < 1 || numbers[1] < numbers[0] || numbers[1] > 2147483647 || int64(request.API) < numbers[0] || int64(request.API) > numbers[1] || numbers[2] < 1 {
		return nil, ErrAdmissionResponse
	}
	result.MinAPI = int32(numbers[0])
	result.MaxAPI = int32(numbers[1])
	result.Epoch = numbers[2]
	result.ChangeSeq = numbers[3]
	if len(row[9]) < 2 || len(row[9]) > 2*65536 || len(row[9])%2 != 0 {
		return nil, ErrAdmissionResponse
	}
	profile, err := hex.DecodeString(string(row[9]))
	if err != nil {
		clear(profile)
		return nil, ErrAdmissionResponse
	}
	result.SignedProfile = profile
	return result, nil
}

func workspaceQueryError(err error) error {
	for _, entry := range []struct {
		code string
		err  error
	}{
		{"WH001", ErrIdentityUnavailable}, {"WH002", ErrProvisioning}, {"WH003", ErrTLSRequired},
		{"WH004", ErrAPIVersion}, {"WH005", ErrAuditUnavailable}, {"WH006", ErrTransactionIsolation},
		{"WH007", ErrAuthentication},
		{"WH008", ErrPasswordChangePayload}, {"WH009", ErrDeviceCredentials}, {"WH010", ErrAccountRevision},
		{"WH011", ErrTLSMetadata},
		{"WH012", ErrInvitation},
		{"WH013", ErrTreeSnapshotChanged}, {"WH014", ErrTreeMetadata}, {"WH015", ErrUseTicket},
		{"WH020", ErrServerCertificateAuthority}, {"WH021", ErrWorkspaceCARotation},
		{"WH022", ErrResultLimit},
		{"WH023", ErrAccountRecovery},
		{"WH024", ErrAccountResetLogging},
		{"WH025", ErrWorkspaceImport},
		{"WH028", ErrSetupImportConflict},
		{"WH026", ErrImportedConnectionPins},
		{"55P03", ErrChangeInProgress}, {"53300", ErrConnectionLimit},
	} {
		if hasSQLState(err, entry.code, 0) {
			return entry.err
		}
	}
	return ErrQuery
}
