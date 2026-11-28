package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountResetLifetime = 12 * time.Hour
const MaxAccountResetOfferBytes = 2*MaxTLSTrustBundleBytes + 8192

type accountResetSubject struct {
	UserID            uuid.UUID       `json:"userId"`
	LoginName         string          `json:"loginName"`
	Encryption        vault.KeyRef    `json:"encryption"`
	Signing           vault.KeyRef    `json:"signing"`
	WrapRevision      uint64          `json:"wrapRevision"`
	MinimumKDF        vault.KDFPreset `json:"minimumKdf"`
	CertificateDigest []byte          `json:"certificateDigest"`
	StateDigest       []byte          `json:"stateDigest"`
	Suspension        uint64          `json:"suspension,omitempty"`
	AccountSequence   uint64          `json:"accountSequence,omitempty"`
}

func (s accountResetSubject) binding(workspace uuid.UUID) vault.UserKeyBinding {
	return vault.UserKeyBinding{WorkspaceID: workspace, UserID: s.UserID,
		Encryption: s.Encryption, Signing: s.Signing, Revision: s.WrapRevision + 1}
}

// An account reset handover contains public connection and certification
// material. The code and ASK are delivered separately from this document.
type accountResetOffer struct {
	Version      uint16                        `json:"version"`
	WorkspaceID  uuid.UUID                     `json:"workspaceId"`
	ID           uuid.UUID                     `json:"id"`
	Subject      accountResetSubject           `json:"subject"`
	UserPublic   vault.UserPublicKeys          `json:"userPublic"`
	RoleTag      string                        `json:"roleTag"`
	Database     string                        `json:"database"`
	Endpoints    []Endpoint                    `json:"endpoints"`
	Organisation []byte                        `json:"organisation"`
	Signer       vault.KeyRef                  `json:"signer"`
	TLSBundle    json.RawMessage               `json:"tlsBundle"`
	SignedPolicy json.RawMessage               `json:"signedPolicy"`
	ExpiresAt    int64                         `json:"expiresAt"`
	Replacement  *accountReplacementEnrollment `json:"replacement,omitempty"`
	Signature    []byte                        `json:"signature"`
}

func (o accountResetOffer) capsuleBinding() vault.UserKeyBinding {
	binding := o.Subject.binding(o.WorkspaceID)
	if o.Replacement != nil {
		binding.Encryption = o.Replacement.Encryption.Key
		binding.Signing = o.Replacement.Signing.Key
	}
	return binding
}

func (o accountResetOffer) codeContext() vault.InviteContext {
	binding := o.capsuleBinding()
	return vault.InviteContext{WorkspaceID: o.WorkspaceID, UserID: o.Subject.UserID,
		InviteID: o.ID, KeyID: binding.Encryption.ID, KeyVersion: binding.Encryption.Version,
		LoginName: o.Subject.LoginName}
}

func (o accountResetOffer) role() string { return "wh_" + o.RoleTag + "_r_" + o.ID.String() }

func (o accountResetOffer) signingBytes() ([]byte, error) {
	o.Signature = nil
	body, err := json.Marshal(o)
	if err != nil || len(body) > MaxAccountResetOfferBytes {
		return nil, ErrAccountRecovery
	}
	return append([]byte("wormhole/v1/account-reset-offer\x00"), body...), nil
}

func (o accountResetOffer) transport(now time.Time) (Settings, vault.Policy, error) {
	if (o.Version != 1 && o.Version != 2) || o.ID == uuid.Nil || o.Subject.UserID == uuid.Nil || o.Subject.Encryption.ID == uuid.Nil ||
		o.Subject.Signing.ID == uuid.Nil || o.Subject.Signing.ID == o.Subject.Encryption.ID ||
		o.Subject.Encryption.Version == 0 || o.Subject.Encryption.Version > math.MaxInt32 ||
		o.Subject.Signing.Version == 0 || o.Subject.Signing.Version > math.MaxInt32 ||
		o.Subject.WrapRevision == 0 || o.Subject.WrapRevision >= math.MaxInt64 ||
		len(o.Subject.StateDigest) != sha256.Size || len(o.Subject.CertificateDigest) != sha256.Size ||
		len(o.UserPublic.Encryption) != 32 || len(o.UserPublic.Signing) != ed25519.PublicKeySize ||
		len(o.Organisation) != ed25519.PublicKeySize || o.ExpiresAt <= now.Unix() ||
		o.ExpiresAt > now.Add(24*time.Hour).Unix() || deploy.ValidateIdentity(o.RoleTag, o.WorkspaceID.String()) != nil {
		return Settings{}, vault.Policy{}, ErrAccountRecovery
	}
	if _, err := vault.SharedSalt(o.WorkspaceID.String(), o.Subject.LoginName); err != nil {
		return Settings{}, vault.Policy{}, err
	}
	if _, err := vault.Parameters(o.Subject.MinimumKDF); err != nil {
		return Settings{}, vault.Policy{}, err
	}
	body, err := o.signingBytes()
	if err != nil || !ed25519.Verify(o.Organisation, body, o.Signature) {
		return Settings{}, vault.Policy{}, vault.ErrAuthentication
	}
	if o.Version == 2 {
		if err := o.verifyReplacement(now); err != nil {
			return Settings{}, vault.Policy{}, err
		}
	} else if o.Replacement != nil || o.Subject.Suspension != 0 || o.Subject.AccountSequence != 0 {
		return Settings{}, vault.Policy{}, ErrAccountRecovery
	}
	policy, err := vault.DecodeSignedPolicy(o.SignedPolicy)
	if err != nil {
		return Settings{}, vault.Policy{}, err
	}
	if err := vault.VerifyPolicy(policy, o.WorkspaceID.String(), o.Signer.ID.String(), o.Signer.Version, o.Organisation, 1); err != nil {
		return Settings{}, vault.Policy{}, err
	}
	if !policy.Policy.OrgEscrow || (policy.Policy.Profile != vault.Default && policy.Policy.Profile != vault.Standard) {
		return Settings{}, vault.Policy{}, vault.ErrPolicy
	}
	document, err := DecodeTLSTrustBundle(o.TLSBundle)
	if err != nil {
		return Settings{}, vault.Policy{}, err
	}
	tls, err := VerifyTLSTrustBundle(document, TLSTrustPin{WorkspaceID: o.WorkspaceID,
		Signer: o.Signer, Organisation: o.Organisation, MinimumSequence: 1})
	if err != nil {
		return Settings{}, vault.Policy{}, err
	}
	settings := Settings{Endpoints: o.Endpoints, Database: o.Database, DeviceRole: o.role(),
		Profile: policy.Policy.Profile, TLS: TLSVerified, TLSBundle: tls}
	transport, err := invitationTransportSettings(settings)
	if err != nil {
		return Settings{}, vault.Policy{}, err
	}
	if _, err := validateTransportSettings(transport); err != nil {
		return Settings{}, vault.Policy{}, err
	}
	return settings, policy.Policy, nil
}

func accountResetKey(code, ask []byte, digest [32]byte, label string) ([]byte, error) {
	if len(code) != vault.InviteCodeBytes || len(ask) != 32 {
		return nil, ErrConfiguration
	}
	var both [vault.InviteCodeBytes + 32]byte
	copy(both[:], code)
	copy(both[vault.InviteCodeBytes:], ask)
	defer vault.Wipe(both[:])
	return hkdf.Key(sha256.New, both[:], digest[:], label, 32)
}

const fetchAccountResetSQL = `SELECT pg_catalog.encode(wormhole_api_v1.account_reset_capsule($1::uuid,pg_catalog.decode($2,'hex')),'hex')`

// OpenAccountReset authenticates a delivered offer and opens its sealed
// original account keys. It borrows both factors. The caller owns the temporary
// keys and must wipe them. Opening alone makes no account or device mutation.
func OpenAccountReset(ctx context.Context, document, code, ask []byte) (*vault.UserKeys, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	offer, settings, _, err := decodeAccountReset(document, time.Now())
	if err != nil {
		return nil, err
	}
	return openAccountReset(ctx, offer, settings, sha256.Sum256(document), code, ask)
}

func decodeAccountReset(document []byte, now time.Time) (accountResetOffer, Settings, vault.Policy, error) {
	offer, err := parseAccountResetOffer(document)
	if err != nil {
		return accountResetOffer{}, Settings{}, vault.Policy{}, err
	}
	settings, policy, err := offer.transport(now)
	return offer, settings, policy, err
}

func parseAccountResetOffer(document []byte) (accountResetOffer, error) {
	offer, err := parseAccountOffer(document)
	if err != nil {
		return accountResetOffer{}, err
	}
	if offer.Version != 1 || offer.Replacement != nil || offer.Subject.Suspension != 0 || offer.Subject.AccountSequence != 0 {
		return accountResetOffer{}, ErrAccountRecovery
	}
	return offer, nil
}

func parseAccountOffer(document []byte) (accountResetOffer, error) {
	if len(document) == 0 || len(document) > MaxAccountResetOfferBytes {
		return accountResetOffer{}, ErrConfiguration
	}
	var offer accountResetOffer
	if err := json.Unmarshal(document, &offer); err != nil {
		return accountResetOffer{}, ErrAccountRecovery
	}
	canonical, err := json.Marshal(offer)
	if err != nil || !bytes.Equal(canonical, document) {
		return accountResetOffer{}, ErrAccountRecovery
	}
	return offer, nil
}

func openAccountReset(ctx context.Context, offer accountResetOffer, settings Settings, digest [32]byte, code, ask []byte) (*vault.UserKeys, error) {
	master, err := accountResetKey(code, ask, digest, "wormhole/v1/account-reset-capsule")
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(master)
	login, err := resetEnrollmentLogin(offer, code)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(login)
	conn, err := Connect(ctx, settings, login)
	if err != nil {
		return nil, err
	}
	defer closeDeploymentConnection(conn)
	statement := fetchAccountResetSQL
	if offer.Version == 2 {
		statement = fetchAccountReenrollmentSQL
	}
	row, err := readAccountResetRow(ctx, conn, statement, [][]byte{[]byte(offer.ID.String()),
		hex.AppendEncode(nil, digest[:])}, 1, 1024)
	if err != nil {
		return nil, err
	}
	defer wipeQueryRows([][][]byte{row})
	raw, err := hex.AppendDecode(nil, row[0])
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	var capsule vault.Envelope
	if err := json.Unmarshal(raw, &capsule); err != nil {
		return nil, ErrAdmissionResponse
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := vault.OpenUserKeys(master, offer.capsuleBinding(), capsule, offer.UserPublic)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		keys.Wipe()
		return nil, err
	}
	return keys, nil
}

func resetEnrollmentLogin(offer accountResetOffer, code []byte) ([]byte, error) {
	derived, err := vault.DeriveInviteLogin(code, offer.codeContext())
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(derived)
	return EncodeLoginSecret(derived)
}

// Each reset statement has exactly one bounded result. Its connection is
// retired by the caller on malformed or ambiguous replies.
func readAccountResetRow(ctx context.Context, conn *pgconn.PgConn, statement string, args [][]byte, columns, maxField int) ([][]byte, error) {
	conn.Frontend().SetMaxBodyLen(columns*(maxField+4) + 1024)
	reader := conn.ExecParams(ctx, statement, args, nil, nil, nil)
	if !reader.NextRow() {
		if _, err := reader.Close(); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, workspaceQueryError(err)
		}
		return nil, ErrAdmissionResponse
	}
	values := reader.Values()
	if len(values) != columns || len(reader.FieldDescriptions()) != columns {
		return nil, ErrAdmissionResponse
	}
	row := make([][]byte, len(values))
	for i, value := range values {
		if len(value) > maxField {
			return nil, ErrAdmissionResponse
		}
		row[i] = bytes.Clone(value)
	}
	if reader.NextRow() {
		return nil, ErrAdmissionResponse
	}
	if _, err := reader.Close(); err != nil {
		return nil, workspaceQueryError(err)
	}
	return row, ctx.Err()
}
