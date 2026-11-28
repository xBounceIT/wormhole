package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxInvitationBytes = MaxTLSTrustBundleBytes + 384*1024
const invitationPrefix = "WHINV1-"
const enrollmentInvitationPrefix = "WHINV2-"
const tlsEnrollmentInvitationPrefix = "WHINV3-"
const maxInvitationTokenBytes = len(invitationPrefix) + (MaxInvitationBytes*8+5)/6 + 1 + sha256.Size*2

var ErrInvitation = errors.New("invalid or expired shared workspace invitation")

// Invitation contains public enrollment coordinates only, never the separately
// delivered one-time code. Its checksum detects transcription errors, not forgery.
// Authenticate bootstrap material with the code before trusting its organisation
// key; matching a key supplied by an unauthenticated server is not authentication.
type Invitation struct {
	FormatVersion           uint16                 `json:"formatVersion"`
	WorkspaceID             uuid.UUID              `json:"workspaceId"`
	LoginName               string                 `json:"loginName"`
	Endpoints               []Endpoint             `json:"endpoints"`
	Database                string                 `json:"database"`
	TLS                     TLSMode                `json:"tls"`
	CAPEM                   []byte                 `json:"caPem"`
	OrganisationFingerprint []byte                 `json:"organisationFingerprint"`
	ExpiresAt               int64                  `json:"expiresAt"`
	Enrollment              *InvitationEnrollment  `json:"enrollment,omitempty"`
	TLSIdentity             *InvitationTLSIdentity `json:"tlsIdentity,omitempty"`
}

func (i Invitation) Validate(now time.Time) error {
	if (i.FormatVersion != 1 && i.FormatVersion != 2 && i.FormatVersion != 3) || i.WorkspaceID == uuid.Nil || len(i.OrganisationFingerprint) != sha256.Size || i.ExpiresAt <= 0 || i.ExpiresAt <= now.Unix() {
		return ErrInvitation
	}
	if (i.FormatVersion == 1 && i.Enrollment != nil) || (i.FormatVersion >= 2 && !i.validEnrollment()) || (i.FormatVersion < 3 && i.TLSIdentity != nil) {
		return ErrInvitation
	}
	if _, err := vault.SharedSalt(i.WorkspaceID.String(), i.LoginName); err != nil {
		return ErrInvitation
	}
	settings := Settings{Endpoints: i.Endpoints, Database: i.Database, DeviceRole: "invitation", TLS: i.TLS, Profile: vault.Default, CAPEM: i.CAPEM}
	if i.FormatVersion == 3 {
		var err error
		settings.TLSBundle, err = i.invitationTLSHint()
		if err != nil {
			return ErrInvitation
		}
		settings, err = invitationTransportSettings(settings)
		if err != nil {
			return ErrInvitation
		}
	}
	if _, err := validateTransportSettings(settings); err != nil {
		return ErrInvitation
	}
	return nil
}

// EncodeInvitation returns the same bounded token for clipboard and invite files.
func EncodeInvitation(i Invitation, now time.Time) (string, error) {
	if err := i.Validate(now); err != nil {
		return "", err
	}
	raw, err := json.Marshal(i)
	if err != nil || len(raw) > MaxInvitationBytes {
		return "", ErrInvitation
	}
	prefix := invitationPrefix
	if i.FormatVersion == 2 {
		prefix = enrollmentInvitationPrefix
	}
	if i.FormatVersion == 3 {
		prefix = tlsEnrollmentInvitationPrefix
	}
	payload := prefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(payload))
	return payload + "." + hex.EncodeToString(sum[:]), nil
}

// DecodeInvitation accepts canonical WHINV1/WHINV2 tokens, with optional outer
// ASCII whitespace. It performs no network or file access and authenticates no key.
func DecodeInvitation(token string, now time.Time) (Invitation, error) {
	if len(token) > maxInvitationTokenBytes+2 {
		return Invitation{}, ErrInvitation
	}
	token = strings.Trim(token, " \t\r\n")
	prefix := invitationPrefix
	if strings.HasPrefix(token, tlsEnrollmentInvitationPrefix) {
		prefix = tlsEnrollmentInvitationPrefix
	} else if strings.HasPrefix(token, enrollmentInvitationPrefix) {
		prefix = enrollmentInvitationPrefix
	}
	if !strings.HasPrefix(token, prefix) || len(token) > maxInvitationTokenBytes {
		return Invitation{}, ErrInvitation
	}
	payload, checksum, ok := strings.Cut(token, ".")
	if !ok {
		return Invitation{}, ErrInvitation
	}
	sum := sha256.Sum256([]byte(payload))
	if checksum != hex.EncodeToString(sum[:]) {
		return Invitation{}, ErrInvitation
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload[len(prefix):])
	if err != nil || len(raw) == 0 || len(raw) > MaxInvitationBytes || base64.RawURLEncoding.EncodeToString(raw) != payload[len(prefix):] {
		return Invitation{}, ErrInvitation
	}
	var i Invitation
	if json.Unmarshal(raw, &i) != nil || i.Validate(now) != nil {
		return Invitation{}, ErrInvitation
	}
	if (i.FormatVersion == 2) != (prefix == enrollmentInvitationPrefix) || (i.FormatVersion == 3) != (prefix == tlsEnrollmentInvitationPrefix) {
		return Invitation{}, ErrInvitation
	}
	canonical, err := json.Marshal(i)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Invitation{}, ErrInvitation
	}
	return i, nil
}

// CheckOrganisationKey is used only after the code authenticates the bootstrap
// material. Rechecking expiry prevents reuse of a previously parsed stale invite.
func (i Invitation) CheckOrganisationKey(key ed25519.PublicKey, now time.Time) error {
	if i.Validate(now) != nil || len(key) != ed25519.PublicKeySize {
		return ErrInvitation
	}
	fingerprint := sha256.Sum256(key)
	if subtle.ConstantTimeCompare(fingerprint[:], i.OrganisationFingerprint) != 1 {
		return ErrInvitation
	}
	return nil
}

// OpenBootstrap is the native enrollment boundary: enforce invite coordinates
// and expiry, then authenticate the bootstrap using the separately supplied code.
// The caller must wipe the returned temporary keys on every exit path.
func (i Invitation) OpenBootstrap(code []byte, c vault.InviteContext, envelope vault.Envelope, now time.Time) (*vault.InviteBootstrap, error) {
	if i.Validate(now) != nil || c.WorkspaceID != i.WorkspaceID || c.LoginName != i.LoginName {
		return nil, ErrInvitation
	}
	if i.Enrollment != nil && c != i.Enrollment.Context {
		return nil, ErrInvitation
	}
	var b *vault.InviteBootstrap
	var err error
	if i.FormatVersion == 3 {
		digest, e := i.tlsBootstrapDigest()
		if e != nil {
			return nil, ErrInvitation
		}
		b, err = vault.OpenTLSInviteBootstrap(code, c, envelope, i.OrganisationFingerprint, digest)
	} else {
		b, err = vault.OpenInviteBootstrap(code, c, envelope, i.OrganisationFingerprint)
	}
	if err != nil {
		return nil, ErrInvitation
	}
	return b, nil
}

// PrepareRewrap authenticates the code, organisation and complete graph before
// generating final user keys. Bootstrap plaintext is retired on every exit.
// Publication and one-time redemption remain a separate server transaction.
func (i Invitation) PrepareRewrap(ctx context.Context, code []byte, envelope vault.Envelope, manifest vault.InviteManifest, copies []vault.SignedKeyCopy, minimumRevision uint64, now time.Time) (*vault.InviteRewrapPlan, error) {
	if ctx == nil {
		return nil, ErrInvitation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := i.OpenBootstrap(code, manifest.Context, envelope, now)
	if err != nil {
		return nil, err
	}
	defer b.Wipe()
	return vault.PrepareCertifiedInviteRewrap(ctx, manifest.Context, b, manifest, copies, minimumRevision, i.ExpiresAt, now)
}
