package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxBootstrapEnvelopeBytes = 65536
const invitationBootstrapSQL = `SELECT workspace_id::text,user_id::text,login_name,invite_id::text,bootstrap_key_id::text,bootstrap_key_version::text,expires_at::text,pg_catalog.encode(bootstrap_envelope,'hex'),pg_catalog.encode(manifest,'hex'),manifest_revision::text FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)`

// UnverifiedInvitationBootstrap contains only encrypted/public data. Structural
// decoding does not authenticate a database-supplied document; use Authenticate.
type UnverifiedInvitationBootstrap struct {
	Envelope vault.Envelope       `json:"-"`
	Manifest vault.InviteManifest `json:"-"`
}

// OpenInvitation opens one query connection with the temporary enrollment login.
// As with Open, callers own this Session and must Close it on every exit path.
func (s *Session) OpenInvitation(ctx context.Context, i Invitation, code []byte) error {
	if ctx == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	settings, login, err := i.EnrollmentLogin(code, time.Now())
	if err != nil {
		return err
	}
	defer vault.Wipe(login)
	return s.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true})
}

// InvitationBootstrap fetches only this invitation's bootstrap on the native
// enrollment connection. Malformed responses invalidate the owner; Close still
// belongs to the caller. Expiry is checked again when authenticating the result.
func (s *Session) InvitationBootstrap(ctx context.Context, i Invitation) (*UnverifiedInvitationBootstrap, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if _, err := i.EnrollmentRole(time.Now()); err != nil {
		return nil, err
	}
	rows, err := s.Query(ctx, invitationBootstrapSQL, [][]byte{[]byte(i.Enrollment.Context.InviteID.String())})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	result, err := parseInvitationBootstrap(rows, i, time.Now())
	if err != nil {
		s.cancel()
	}
	return result, err
}

// EncodeInvitationBootstrapEnvelope defines the canonical bytea representation
// used by provisioning. This validates shape/binding, not ciphertext authenticity.
func EncodeInvitationBootstrapEnvelope(i Invitation, envelope vault.Envelope, now time.Time) ([]byte, error) {
	if _, err := i.EnrollmentRole(now); err != nil {
		return nil, err
	}
	c := i.Enrollment.Context
	const ciphertextBytes = 1 + 32 + ed25519.SeedSize + ed25519.PublicKeySize + 16
	if envelope.FormatVersion != vault.FormatVersion || envelope.SuiteID != vault.SuiteAES256GCM || envelope.KeyID != c.KeyID.String() || envelope.KeyVersion != c.KeyVersion || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) != ciphertextBytes {
		return nil, ErrInvitation
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > maxBootstrapEnvelopeBytes {
		return nil, ErrInvitation
	}
	return raw, nil
}

func parseInvitationBootstrap(rows [][][]byte, i Invitation, now time.Time) (*UnverifiedInvitationBootstrap, error) {
	if i.Validate(now) != nil || (i.FormatVersion != 2 && i.FormatVersion != 3) || len(rows) != 1 || len(rows[0]) != 10 {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	c := i.Enrollment.Context
	expected := []string{i.WorkspaceID.String(), c.UserID.String(), i.LoginName, c.InviteID.String(), c.KeyID.String(), strconv.FormatUint(uint64(c.KeyVersion), 10), strconv.FormatInt(i.ExpiresAt, 10)}
	for n, value := range expected {
		if string(r[n]) != value {
			return nil, ErrAdmissionResponse
		}
	}
	if len(r[7]) == 0 || len(r[7]) > 2*maxBootstrapEnvelopeBytes || len(r[8]) == 0 || len(r[8]) > 2*vault.MaxInviteManifestBytes {
		return nil, ErrAdmissionResponse
	}
	raw, err := hex.DecodeString(string(r[7]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, ErrAdmissionResponse
	}
	canonical, err := EncodeInvitationBootstrapEnvelope(i, envelope, now)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrAdmissionResponse
	}
	raw, err = hex.DecodeString(string(r[8]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	manifest, err := vault.DecodeInviteManifest(raw)
	if err != nil || manifest.Context != c || manifest.ExpiresAt != i.ExpiresAt || strconv.FormatUint(manifest.Revision, 10) != string(r[9]) {
		return nil, ErrAdmissionResponse
	}
	return &UnverifiedInvitationBootstrap{Envelope: envelope, Manifest: manifest}, nil
}

// Authenticate uses the separately delivered code to authenticate the organisation
// key, then verifies the manifest and bootstrap public-key pair. Caller must wipe
// the returned native plaintext keys; failure never returns them.
func (b *UnverifiedInvitationBootstrap) Authenticate(i Invitation, code []byte, minimumRevision uint64, now time.Time) (*vault.InviteBootstrap, error) {
	if b == nil || (i.FormatVersion != 2 && i.FormatVersion != 3) {
		return nil, ErrInvitation
	}
	opened, err := i.OpenBootstrap(code, b.Manifest.Context, b.Envelope, now)
	if err != nil {
		return nil, err
	}
	if err := vault.VerifyInviteBootstrap(opened, b.Manifest, i.Enrollment.Context, minimumRevision, i.ExpiresAt, now); err != nil {
		opened.Wipe()
		return nil, err
	}
	return opened, nil
}
