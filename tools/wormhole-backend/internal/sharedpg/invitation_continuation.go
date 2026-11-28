package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxInvitationContinuationBytes = vault.MaxSecretBytes

// The compact record keeps each certificate/copy only once. In particular it
// stores neither SCRAM verifier, code, factors, master nor plaintext private keys.
type invitationContinuationRecord struct {
	FormatVersion uint16               `json:"formatVersion"`
	Invitation    string               `json:"invitation"`
	Pending       PendingEnrollment    `json:"pending"`
	Name          string               `json:"name"`
	Nonce         []byte               `json:"nonce"`
	Ciphertext    []byte               `json:"ciphertext"`
	Copies        []invitationCopyWire `json:"copies"`
}

// InvitationContinuation is authenticated local preparation, never permission to
// submit SQL. Only a fresh code-authenticated server revalidation can produce a
// prepared mutation. The borrowed master stays caller-owned. Serialize all use.
type InvitationContinuation struct {
	record  invitationContinuationRecord
	binding TrustBinding
	master  *AccountMaster
}

func (c *InvitationContinuation) Wipe() {
	if c == nil {
		return
	}
	vault.Wipe(c.record.Nonce)
	vault.Wipe(c.record.Ciphertext)
	*c = InvitationContinuation{}
}

// Invitation returns independent public coordinates for a protected native flow.
func (c *InvitationContinuation) Invitation() (Invitation, error) {
	if c == nil || c.master == nil {
		return Invitation{}, ErrConfiguration
	}
	return DecodeInvitation(c.record.Invitation, time.Now())
}

func invitationContinuationBinding(b TrustBinding) (vault.Binding, error) {
	result, err := b.binding()
	result.Table = "SharedInvitationContinuation"
	result.Field += "/v1"
	return result, err
}

func (p *PreparedInvitationCommit) SealContinuation(root []byte, b TrustBinding, i Invitation) ([]byte, error) {
	if p == nil || i.Enrollment == nil || p.ValidateAccountMaster(p.master) != nil || p.device != b.DeviceID || p.role != "wh_"+i.Enrollment.RoleTag+"_d_"+b.DeviceID.String() || p.expires != i.ExpiresAt {
		return nil, ErrConfiguration
	}
	// Preserve the live owner's buffers; no verifier enters the record.
	pending, err := p.PendingEnrollment(b)
	if err != nil || pending.Observed != nil {
		return nil, ErrTrustState
	}
	token, err := EncodeInvitation(i, time.Now())
	if err != nil {
		return nil, err
	}
	r := invitationContinuationRecord{FormatVersion: 1, Invitation: token, Pending: pending, Name: string(p.params[4])}
	r.Nonce, err = hex.DecodeString(string(p.params[8]))
	if err != nil {
		return nil, ErrTrustState
	}
	r.Ciphertext, err = hex.DecodeString(string(p.params[9]))
	if err != nil || json.Unmarshal(p.params[11], &r.Copies) != nil {
		return nil, ErrTrustState
	}
	c := &InvitationContinuation{record: r, binding: b, master: p.master}
	if _, err := c.validate(); err != nil {
		return nil, err
	}
	params, err := c.parameters(nil)
	if err != nil {
		return nil, err
	}
	for n := range params {
		if n != 5 && !bytes.Equal(params[n], p.params[n]) {
			return nil, ErrTrustState
		}
	}
	plain, err := json.Marshal(r)
	defer vault.Wipe(plain)
	if err != nil || len(plain) > MaxInvitationContinuationBytes {
		return nil, ErrConfiguration
	}
	binding, err := invitationContinuationBinding(b)
	if err != nil {
		return nil, err
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	envelope, err := vault.Seal(key, binding, plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func OpenInvitationContinuation(root []byte, b TrustBinding, master *AccountMaster, sealed []byte) (result *InvitationContinuation, err error) {
	binding, err := invitationContinuationBinding(b)
	if err != nil || master == nil || len(sealed) == 0 || len(sealed) > 2*MaxInvitationContinuationBytes {
		return nil, ErrConfiguration
	}
	var envelope vault.Envelope
	if json.Unmarshal(sealed, &envelope) != nil {
		return nil, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, sealed) {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(plain)
	c := &InvitationContinuation{binding: b, master: master}
	defer func() {
		if err != nil {
			c.Wipe()
		}
	}()
	if json.Unmarshal(plain, &c.record) != nil {
		return nil, ErrTrustState
	}
	canonical, err = json.Marshal(c.record)
	defer vault.Wipe(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return nil, ErrTrustState
	}
	if _, err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *InvitationContinuation) validate() (Invitation, error) {
	if c == nil || c.master == nil || c.record.FormatVersion != 1 || !c.record.Pending.valid(c.binding) || c.record.Pending.Observed != nil {
		return Invitation{}, ErrTrustState
	}
	r, p := c.record, c.record.Pending
	i, err := c.Invitation()
	if err != nil {
		return Invitation{}, err
	}
	if i.Enrollment == nil || i.Enrollment.Context != p.Certificate.Manifest.Context || i.WorkspaceID != c.binding.WorkspaceID || i.LoginName != c.master.LoginName() || i.WorkspaceID != c.master.WorkspaceID() || i.Enrollment.RoleTag != p.RoleTag || i.ExpiresAt != p.Certificate.Manifest.ExpiresAt || len(r.Name) == 0 || len(r.Name) > 4096 || !utf8.ValidString(r.Name) || strings.ContainsRune(r.Name, 0) || len(r.Nonce) != 12 || len(r.Ciphertext) != 81 || r.Copies == nil || len(r.Copies) != len(p.Certificate.Manifest.Copies) {
		return Invitation{}, ErrTrustState
	}
	fingerprint := sha256.Sum256(p.Trust.PublicKey)
	if !bytes.Equal(fingerprint[:], i.OrganisationFingerprint) {
		return Invitation{}, ErrTrustState
	}
	b := vault.UserKeyBinding{WorkspaceID: i.WorkspaceID, UserID: c.binding.UserID,
		Encryption: vault.KeyRef{ID: p.Certificate.Rekey.EncryptionKeyID, Version: 1},
		Signing:    vault.KeyRef{ID: p.Certificate.Rekey.SigningKeyID, Version: 1}, Revision: 1}
	err = c.master.Use(func(secret []byte, preset vault.KDFPreset, ask bool) error {
		if preset != p.KDF || ask != p.ASKRequired {
			return ErrAccountRevision
		}
		envelope := vault.Envelope{FormatVersion: 1, SuiteID: vault.SuiteAES256GCM, KeyID: b.Encryption.ID.String(), KeyVersion: 1, Nonce: r.Nonce, Ciphertext: r.Ciphertext}
		if !bytes.Equal(enrollmentCapsuleDigest(envelope), p.CapsuleDigest) {
			return ErrTrustState
		}
		keys, err := vault.OpenUserKeys(secret, b, envelope, p.Certificate.Rekey.Public)
		if err != nil {
			return err
		}
		defer keys.Wipe()
		return c.validateCopies(keys, b)
	})
	return i, err
}

func (c *InvitationContinuation) validateCopies(keys *vault.UserKeys, b vault.UserKeyBinding) error {
	for n, wire := range c.record.Copies {
		binding := c.record.Pending.Certificate.Manifest.Copies[n]
		binding.Holder, binding.Issuer = b.Encryption, b.Signing
		if wire.KeyID != binding.Key.ID.String() || wire.KeyVersion != binding.Key.Version {
			return ErrTrustState
		}
		enc, e1 := hex.DecodeString(wire.Enc)
		cipher, e2 := hex.DecodeString(wire.Ciphertext)
		signature, e3 := hex.DecodeString(wire.Signature)
		if e1 != nil || e2 != nil || e3 != nil || hex.EncodeToString(enc) != wire.Enc || hex.EncodeToString(cipher) != wire.Ciphertext || hex.EncodeToString(signature) != wire.Signature {
			return ErrTrustState
		}
		copy := vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: 1, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: enc, Ciphertext: cipher}, Signature: signature}
		plain, err := vault.OpenKeyCopy(keys.EncryptionPrivate, binding, copy, c.record.Pending.Certificate.Rekey.Public.Signing)
		vault.Wipe(plain)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *InvitationContinuation) parameters(verifier []byte) ([][]byte, error) {
	r := c.record
	manifest, err := vault.EncodeInviteManifest(r.Pending.Certificate.Manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(manifest)
	certificate, err := vault.EncodeUserEnrollmentCertificate(r.Pending.Certificate)
	if err != nil {
		return nil, err
	}
	copies, err := json.Marshal(r.Copies)
	if err != nil || len(copies) > 1024*1024 {
		return nil, ErrConfiguration
	}
	return [][]byte{[]byte(r.Pending.Certificate.Manifest.Context.InviteID.String()), []byte(strconv.FormatUint(r.Pending.Certificate.Manifest.Revision, 10)), hex.AppendEncode(nil, digest[:]), []byte(c.binding.DeviceID.String()), []byte(r.Name), verifier, []byte(r.Pending.KDF), []byte(strconv.FormatBool(r.Pending.ASKRequired)), hex.AppendEncode(nil, r.Nonce), hex.AppendEncode(nil, r.Ciphertext), hex.AppendEncode(nil, certificate), copies}, nil
}
