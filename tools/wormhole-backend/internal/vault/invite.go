package vault

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"

	"github.com/google/uuid"
)

const InviteCodeBytes = 16
const inviteBootstrapBytes = 1 + 32 + ed25519.SeedSize + ed25519.PublicKeySize

// InviteContext identifies one issuance, including resets. Reissuing a code must
// allocate a fresh InviteID. Values are expected coordinates, not envelope fields.
type InviteContext struct {
	WorkspaceID uuid.UUID `json:"workspaceId"`
	UserID      uuid.UUID `json:"userId"`
	InviteID    uuid.UUID `json:"inviteId"`
	KeyID       uuid.UUID `json:"keyId"`
	KeyVersion  uint32    `json:"keyVersion"`
	LoginName   string    `json:"loginName"`
}

func (c InviteContext) binding() (Binding, []byte, error) {
	if c.WorkspaceID == uuid.Nil || c.UserID == uuid.Nil || c.InviteID == uuid.Nil || c.KeyID == uuid.Nil || c.KeyVersion == 0 {
		return Binding{}, nil, ErrFormat
	}
	if _, err := SharedSalt(c.WorkspaceID.String(), c.LoginName); err != nil {
		return Binding{}, nil, err
	}
	context := canonical("wormhole/v1/invite-context", c.WorkspaceID[:], c.UserID[:], c.InviteID[:], c.KeyID[:], binary.BigEndian.AppendUint32(nil, c.KeyVersion), []byte(c.LoginName))
	salt := sha256.Sum256(context)
	return Binding{WorkspaceID: c.WorkspaceID.String(), Table: "Invites", OwnerID: c.InviteID.String(), Field: hex.EncodeToString(salt[:]), KeyID: c.KeyID.String(), KeyVersion: c.KeyVersion}, salt[:], nil
}

func deriveInviteKey(code, salt []byte, label string) ([]byte, error) {
	if len(code) != InviteCodeBytes {
		return nil, ErrFormat
	}
	return hkdf.Key(sha256.New, code, salt, label, 32)
}

// DeriveInviteLogin returns the enrollment login material. The caller owns and
// must wipe it. Never use it as the unlock key or transmit the original code.
func DeriveInviteLogin(code []byte, c InviteContext) ([]byte, error) {
	_, salt, err := c.binding()
	if err != nil {
		return nil, err
	}
	return deriveInviteKey(code, salt, "wormhole/v1/invite-login")
}

// InviteBootstrap is a temporary native-only secret. Its owner must call Wipe
// after re-keying or cancellation; persistent ownership belongs in securemem.
// JSON serialization deliberately excludes all fields.
type InviteBootstrap struct {
	EncryptionPrivate  []byte `json:"-"`
	SigningSeed        []byte `json:"-"`
	OrganisationPublic []byte `json:"-"`
}

func NewInviteBootstrap(organisation ed25519.PublicKey) (*InviteBootstrap, error) {
	if len(organisation) != ed25519.PublicKeySize {
		return nil, ErrFormat
	}
	b := &InviteBootstrap{EncryptionPrivate: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize), OrganisationPublic: append([]byte(nil), organisation...)}
	rand.Read(b.EncryptionPrivate)
	rand.Read(b.SigningSeed)
	return b, nil
}

func (b *InviteBootstrap) Wipe() {
	if b == nil {
		return
	}
	Wipe(b.EncryptionPrivate)
	Wipe(b.SigningSeed)
	Wipe(b.OrganisationPublic)
	b.EncryptionPrivate, b.SigningSeed, b.OrganisationPublic = nil, nil, nil
}

func SealInviteBootstrap(code []byte, c InviteContext, b *InviteBootstrap) (Envelope, error) {
	return sealInviteBootstrap(code, c, b, nil)
}

// SealTLSInviteBootstrap binds a new issuance to its canonical signed TLS
// identity digest. Never reuse an InviteID/code from a legacy issuance.
func SealTLSInviteBootstrap(code []byte, c InviteContext, b *InviteBootstrap, digest []byte) (Envelope, error) {
	if len(digest) != sha256.Size {
		return Envelope{}, ErrFormat
	}
	return sealInviteBootstrap(code, c, b, digest)
}

func sealInviteBootstrap(code []byte, c InviteContext, b *InviteBootstrap, digest []byte) (Envelope, error) {
	if b == nil || len(b.EncryptionPrivate) != 32 || len(b.SigningSeed) != ed25519.SeedSize || len(b.OrganisationPublic) != ed25519.PublicKeySize {
		return Envelope{}, ErrFormat
	}
	binding, salt, err := c.binding()
	if err != nil {
		return Envelope{}, err
	}
	if len(digest) != 0 {
		binding.Field += "/tls-v1/" + hex.EncodeToString(digest)
	}
	key, err := deriveInviteKey(code, salt, "wormhole/v1/invite-unlock")
	if err != nil {
		return Envelope{}, err
	}
	defer Wipe(key)
	plain := make([]byte, inviteBootstrapBytes)
	defer Wipe(plain)
	plain[0] = 1
	copy(plain[1:33], b.EncryptionPrivate)
	copy(plain[33:65], b.SigningSeed)
	copy(plain[65:], b.OrganisationPublic)
	return Seal(key, binding, plain)
}

// OpenInviteBootstrap authenticates with the code before checking the organisation
// fingerprint from the separately received invitation. No secret is returned on
// either failure. This does not consume the code: redemption is a server transaction.
func OpenInviteBootstrap(code []byte, c InviteContext, envelope Envelope, fingerprint []byte) (*InviteBootstrap, error) {
	return openInviteBootstrap(code, c, envelope, fingerprint, nil)
}

// OpenTLSInviteBootstrap requires the expected digest from the validated v3
// invitation. A legacy open or a replaced/stripped proof cannot open its AEAD.
func OpenTLSInviteBootstrap(code []byte, c InviteContext, envelope Envelope, fingerprint, digest []byte) (*InviteBootstrap, error) {
	if len(digest) != sha256.Size {
		return nil, ErrFormat
	}
	return openInviteBootstrap(code, c, envelope, fingerprint, digest)
}

func openInviteBootstrap(code []byte, c InviteContext, envelope Envelope, fingerprint, digest []byte) (*InviteBootstrap, error) {
	if len(fingerprint) != sha256.Size || len(envelope.Ciphertext) != inviteBootstrapBytes+16 {
		return nil, ErrFormat
	}
	binding, salt, err := c.binding()
	if err != nil {
		return nil, err
	}
	if len(digest) != 0 {
		binding.Field += "/tls-v1/" + hex.EncodeToString(digest)
	}
	key, err := deriveInviteKey(code, salt, "wormhole/v1/invite-unlock")
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	plain, err := Open(key, binding, envelope)
	if err != nil {
		return nil, err
	}
	defer Wipe(plain)
	if len(plain) != inviteBootstrapBytes || plain[0] != 1 {
		return nil, ErrFormat
	}
	actual := sha256.Sum256(plain[65:])
	if subtle.ConstantTimeCompare(actual[:], fingerprint) != 1 {
		return nil, ErrAuthentication
	}
	return &InviteBootstrap{EncryptionPrivate: append([]byte(nil), plain[1:33]...), SigningSeed: append([]byte(nil), plain[33:65]...), OrganisationPublic: append([]byte(nil), plain[65:]...)}, nil
}
