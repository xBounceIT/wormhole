package sharedpg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The two signed documents are public verification material, never a capsule,
// key copy, secret value or release capability.
const MaxRuntimeStateBytes = 256 * 1024

type runtimeStateWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Profile       string          `json:"profile"`
	Account       json.RawMessage `json:"account"`
}

type UnverifiedRuntimeState struct {
	profile           []byte
	account           vault.UserKeyState
	administrator     bool
	privateStatements bool
}

// WasAdmittedAsAdministrator is a UI hint from the audited session admission.
// Mutation and export endpoints still check current authority in PostgreSQL.
func (s *UnverifiedRuntimeState) WasAdmittedAsAdministrator() bool { return s.administrator }

// StatementsPrivate reports the active device role's connection setting.
func (s *UnverifiedRuntimeState) StatementsPrivate() bool { return s.privateStatements }

func parseRuntimeMaterial(profile string, account []byte, request AdmissionRequest) (*UnverifiedRuntimeState, error) {
	if len(profile) == 0 || len(profile) > 2*65536 {
		return nil, ErrAdmissionResponse
	}
	raw, err := hex.DecodeString(profile)
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	row, err := snapshotOptionalRow(account, 2)
	if err != nil || row == nil {
		return nil, ErrAdmissionResponse
	}
	state, err := parseAccountKeyState([][][]byte{{row[1], row[0]}}, request)
	if err != nil {
		return nil, err
	}
	return &UnverifiedRuntimeState{profile: raw, account: *state}, nil
}

func DecodeRuntimeState(raw []byte, request AdmissionRequest) (*UnverifiedRuntimeState, error) {
	if len(raw) == 0 || len(raw) > MaxRuntimeStateBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	var wire runtimeStateWire
	if _, err := strictCatalogObject(raw, wire); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &wire) != nil {
		return nil, ErrAdmissionResponse
	}
	if wire.FormatVersion > 1 {
		return nil, vault.ErrNewerFormat
	}
	if wire.FormatVersion != 1 {
		return nil, ErrAdmissionResponse
	}
	return parseRuntimeMaterial(wire.Profile, wire.Account, request)
}

// VerifyRuntimeState authenticates current policy and own account state. Persist
// any nonzero observations even on error, before exposing a policy projection.
// A higher authentic policy always requires fresh admission of the old owner.
func (s TrustState) VerifyRuntimeState(ctx context.Context, input *UnverifiedRuntimeState) (TrustState, error) {
	if input == nil {
		return TrustState{}, ErrConfiguration
	}
	return s.verifyRuntimeMaterial(ctx, input.profile, input.account)
}

func (s TrustState) verifyRuntimeMaterial(ctx context.Context, profile []byte, account vault.UserKeyState) (observed TrustState, err error) {
	if ctx == nil {
		return TrustState{}, ErrConfiguration
	}
	if !s.valid() || s.Account == nil || !s.Account.Active {
		return TrustState{}, ErrTrustState
	}
	observed = cloneTrustState(s)
	changed := false
	defer func() {
		if changed {
			observed.Revision = s.Revision + 1
		}
	}()
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
	}
	if err := ctx.Err(); err != nil {
		return observed, err
	}
	next, err := observed.advanceReleasePolicy(profile)
	absorb(next)
	if err != nil {
		return observed, err
	}
	next, err = observed.AdvanceAccount(account, s.WrappingRevision)
	absorb(next)
	if err != nil {
		return observed, err
	}
	if !observed.Account.Active {
		return observed, vault.ErrPolicy
	}
	if observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		return observed, vault.ErrAuthentication
	}
	return observed, nil
}

const runtimeStateSQL = `SELECT workspace_id::text,user_id::text,device_id::text,
 epoch::text,change_seq::text,payload::text,(pg_catalog.current_setting('log_statement')='none')::text
 FROM wormhole_api_v1.runtime_state(pg_catalog.decode($1,'hex'))`

func (s *Session) RuntimeState(ctx context.Context) (result *UnverifiedRuntimeState, err error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	err = s.queryAuthenticated(ctx, runtimeStateSQL, nil, MaxRuntimeStateBytes, 7, func(rows [][][]byte, r AdmissionRequest) error {
		if len(rows) != 1 || len(rows[0]) != 7 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		if string(row[0]) != r.WorkspaceID.String() || string(row[1]) != r.UserID.String() || string(row[2]) != r.DeviceID.String() {
			return ErrAdmissionResponse
		}
		_, epochOK := treeNumber(row[3], 1, math.MaxInt64)
		_, sequenceOK := treeNumber(row[4], 0, math.MaxInt64)
		private := string(row[6]) == "true"
		if !epochOK || !sequenceOK || (!private && string(row[6]) != "false") {
			return ErrAdmissionResponse
		}
		if !private && s.requirePrivateStatements {
			return ErrProfileChanged
		}
		var e error
		result, e = DecodeRuntimeState(row[5], r)
		if e == nil {
			result.administrator = s.administrator
			result.privateStatements = private
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
