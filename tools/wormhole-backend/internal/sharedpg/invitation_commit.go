package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrInvitationCommitUncertain = errors.New("invitation commit outcome is uncertain; reconcile the prepared device before continuing")

// PreparedInvitationCommit owns a verifier and encrypted payload, never plaintext
// keys. It is native-only. The caller must durably protect its pending enrollment
// before dispatch and Wipe this request on every terminal path. Do not use/Wipe
// concurrently. A receipt does not replace device proof or local trust persistence.
type PreparedInvitationCommit struct {
	master  *AccountMaster // borrowed preparation identity; Wipe releases reference
	params  [][]byte
	pending []byte
	device  uuid.UUID
	role    string
	expires int64
}

type invitationCopyWire struct {
	KeyID      string `json:"keyId"`
	KeyVersion uint32 `json:"keyVersion"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// PrepareInvitationCommit is for first enrollment (explicit rollback floors of
// one). The organisation key must come from the code-authenticated bootstrap.
// Plan must come from authenticated complete-copy rewrap, and master from the
// signed policy's account derivation. This snapshots payloads without consuming
// either owner. Existing enrollment/recovery must preserve their higher floors.
func PrepareInvitationCommit(i Invitation, certification *UnverifiedInvitationCertification, organisation ed25519.PublicKey, manifest vault.InviteManifest, plan *vault.InviteRewrapPlan, master *AccountMaster, device uuid.UUID, name string, now time.Time) (*PreparedInvitationCommit, error) {
	if plan == nil || plan.Keys == nil || master == nil || master.WorkspaceID() != i.WorkspaceID || master.loginName != i.LoginName || device == uuid.Nil || len(name) == 0 || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return nil, ErrConfiguration
	}
	policy, trust, err := certification.Verify(i, organisation, manifest, 1, 1, 1, now)
	if err != nil {
		return nil, err
	}
	certificate, err := vault.PrepareUserEnrollmentCertificate(vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest, BootstrapEncryption: certification.Encryption, BootstrapSigning: certification.Signing, Rekey: plan.Proof}, i.Enrollment.Context, certification.State, trust, 1, now)
	if err != nil {
		return nil, err
	}
	rawManifest, err := vault.EncodeInviteManifest(manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(rawManifest)
	if plan.SourceManifestRevision != manifest.Revision || !bytes.Equal(plan.SourceManifestDigest, digest[:]) || len(plan.Copies) != len(manifest.Copies) {
		return nil, ErrInvitation
	}
	public, err := plan.Keys.Public()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public.Encryption, certificate.Rekey.Public.Encryption) || !bytes.Equal(public.Signing, certificate.Rekey.Public.Signing) {
		return nil, vault.ErrAuthentication
	}
	binding := vault.UserKeyBinding{WorkspaceID: i.WorkspaceID, UserID: trust.UserID, Encryption: vault.KeyRef{ID: plan.Proof.EncryptionKeyID, Version: 1}, Signing: vault.KeyRef{ID: plan.Proof.SigningKeyID, Version: 1}, Revision: 1}
	copies := make([]invitationCopyWire, len(plan.Copies))
	for n, copy := range plan.Copies {
		expected := manifest.Copies[n]
		expected.Holder, expected.Issuer = binding.Encryption, binding.Signing
		if copy.Binding != expected {
			return nil, ErrInvitation
		}
		plain, e := vault.OpenKeyCopy(plan.Keys.EncryptionPrivate, expected, copy.Copy, public.Signing)
		vault.Wipe(plain)
		if e != nil {
			return nil, e
		}
		copies[n] = invitationCopyWire{expected.Key.ID.String(), expected.Key.Version, hex.EncodeToString(copy.Copy.Envelope.Enc), hex.EncodeToString(copy.Copy.Envelope.Ciphertext), hex.EncodeToString(copy.Copy.Signature)}
	}
	copyJSON, err := json.Marshal(copies)
	if err != nil || len(copyJSON) > 1024*1024 {
		return nil, ErrConfiguration
	}
	certRaw, err := vault.EncodeUserEnrollmentCertificate(certificate)
	if err != nil {
		return nil, err
	}
	p := &PreparedInvitationCommit{master: master, device: device, role: "wh_" + i.Enrollment.RoleTag + "_d_" + device.String(), expires: i.ExpiresAt}
	err = master.Use(func(secret []byte, preset vault.KDFPreset, ask bool) error {
		actual := policy
		actual.KDF, actual.ASKRequired = preset, ask
		if e := actual.Validate(); e != nil {
			return e
		}
		floor, _ := vault.Parameters(policy.KDF)
		selected, _ := vault.Parameters(preset)
		if selected.MemoryKiB < floor.MemoryKiB || selected.Iterations < floor.Iterations || (policy.ASKRequired && !ask) {
			return vault.ErrPolicy
		}
		envelope, e := vault.SealUserKeys(secret, binding, plan.Keys)
		if e != nil {
			return e
		}
		login, e := vault.DeriveKey(secret, nil, vault.PurposeLogin)
		if e != nil {
			return e
		}
		defer vault.Wipe(login)
		verifier, e := NewSCRAMVerifier(login)
		if e != nil {
			return e
		}
		p.params = [][]byte{[]byte(manifest.Context.InviteID.String()), []byte(strconv.FormatUint(manifest.Revision, 10)), hex.AppendEncode(nil, digest[:]), []byte(device.String()), []byte(name), verifier, []byte(preset), []byte(strconv.FormatBool(ask)), hex.AppendEncode(nil, envelope.Nonce), hex.AppendEncode(nil, envelope.Ciphertext), hex.AppendEncode(nil, certRaw), copyJSON}
		profileDigest := sha256.Sum256(certification.SignedProfile)
		pending := PendingEnrollment{FormatVersion: 1, RoleTag: i.Enrollment.RoleTag, KDF: preset, ASKRequired: ask, Certificate: certificate, CapsuleDigest: enrollmentCapsuleDigest(envelope),
			Trust: TrustState{FormatVersion: 3, Revision: 1, WorkspaceID: i.WorkspaceID, UserID: trust.UserID, DeviceID: device, SignerKeyID: trust.Signer.ID.String(), SignerKeyVersion: trust.Signer.Version, PublicKey: organisation, PolicySequence: policy.Sequence, PolicyDigest: profileDigest[:], SignedProfile: certification.SignedProfile, Account: &certification.State, WrappingRevision: 1}}
		p.pending, e = json.Marshal(pending)
		return e
	})
	if err != nil {
		p.Wipe()
		return nil, err
	}
	return p, nil
}

func (p *PreparedInvitationCommit) Wipe() {
	if p == nil {
		return
	}
	for _, value := range p.params {
		vault.Wipe(value)
	}
	vault.Wipe(p.pending)
	*p = PreparedInvitationCommit{}
}

// ValidateAccountMaster prevents a prepared verifier/capsule being submitted
// with a different native account derivation. The master remains caller-owned.
// Expired requests are rejected before the coordinator creates local intent.
func (p *PreparedInvitationCommit) ValidateAccountMaster(master *AccountMaster) error {
	if p == nil || master == nil || p.master != master || len(p.pending) == 0 || len(p.params) != 12 || p.expires <= time.Now().Unix() {
		return ErrConfiguration
	}
	return master.Use(func([]byte, vault.KDFPreset, bool) error { return nil })
}

const commitInvitationSQL = `SELECT device_id::text,role_name,wrap_revision::text,auth_epoch::text FROM wormhole_api_v1.commit_invitation($1::uuid,$2::bigint,pg_catalog.decode($3,'hex'),$4::uuid,$5,$6,$7,$8::boolean,pg_catalog.decode($9,'hex'),pg_catalog.decode($10,'hex'),pg_catalog.decode($11,'hex'),$12::jsonb)`

// CommitInvitation sends once in autocommit. Its fixed, prevalidated payload has
// a separate 4 MiB ceiling (certificate hex plus up to 1024 encrypted copies).
// It deliberately does not raise the arbitrary Query parameter limit. Unknown
// post-dispatch outcomes retire the session; NEVER blindly resubmit this request.
func (s *Session) CommitInvitation(ctx context.Context, p *PreparedInvitationCommit) error {
	if ctx == nil || p == nil || len(p.params) != 12 || p.device == uuid.Nil || p.expires <= time.Now().Unix() {
		return ErrConfiguration
	}
	total := 0
	for _, value := range p.params {
		if len(value) > 4*1024*1024-total {
			return ErrConfiguration
		}
		total += len(value)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	if s.capability != nil || s.authEpoch != 0 {
		return ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrQuery
	}
	if conn.TxStatus() != 'I' {
		return ErrConfiguration
	}
	rows, err := s.queryLeased(opCtx, conn, commitInvitationSQL, p.params)
	defer wipeQueryRows(rows)
	if err != nil && knownInvitationCommitRejection(err) {
		return err
	}
	valid := conn.TxStatus() == 'I' && validInvitationCommitReceipt(rows, p)
	s.discardConnection(conn)
	if err != nil || !valid {
		return ErrInvitationCommitUncertain
	}
	return nil
}

func validInvitationCommitReceipt(rows [][][]byte, p *PreparedInvitationCommit) bool {
	return len(rows) == 1 && len(rows[0]) == 4 && string(rows[0][0]) == p.device.String() && string(rows[0][1]) == p.role && string(rows[0][2]) == "1" && string(rows[0][3]) == "1"
}

func knownInvitationCommitRejection(err error) bool {
	return err == ErrInvitation || err == ErrAccountRevision || err == ErrAuditUnavailable || err == ErrChangeInProgress || err == ErrIdentityUnavailable || err == ErrAuthentication || err == ErrTransactionIsolation || err == ErrAPIVersion || err == ErrTLSRequired
}
