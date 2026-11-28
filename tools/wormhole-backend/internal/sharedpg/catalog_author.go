package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// A final key's revision is its manifest revision, not the bootstrap certificate
// revision. Keep both namespaces distinct while retaining current signed account
// state for revocation. All fields here remain untrusted until catalog verification.
type catalogAuthorMaterial struct {
	certificate           vault.UserKeyCertificate
	enrollment            []vault.UserEnrollmentCertificate
	keyKey, enrollmentKey string
	keyValue              any
	selection             catalogEnrollmentSelection
	minimum               uint64
}

type catalogEnrollmentSelection struct {
	User                uuid.UUID    `json:"userId"`
	BootstrapEncryption vault.KeyRef `json:"bootstrapEncryption"`
	BootstrapSigning    vault.KeyRef `json:"bootstrapSigning"`
	Encryption          vault.KeyRef `json:"encryption"`
	Signing             vault.KeyRef `json:"signing"`
	PublicDigest        [32]byte     `json:"publicDigest"`
}

func catalogKeyName(prefix string, ref vault.KeyRef) string {
	return prefix + "/" + ref.ID.String() + "/" + strconv.FormatUint(uint64(ref.Version), 10)
}

// Either bootstrap reference can be replaced by a signed reset. Pin the final
// selection to the complete pair so changing only encryption is not mistaken
// for equivocation under the still-current bootstrap signing key.
func catalogEnrollmentName(state vault.UserKeyState) string {
	return catalogKeyName("enrollment", state.Signing) + "/" + state.Encryption.ID.String() + "/" + strconv.FormatUint(uint64(state.Encryption.Version), 10)
}

func (s TrustState) catalogAuthorMaterial(a UnverifiedNodeAuthor) catalogAuthorMaterial {
	m := catalogAuthorMaterial{keyKey: catalogKeyName("key", a.State.Signing)}
	if a.Certificate != nil {
		m.certificate = *a.Certificate
	}
	m.keyValue = m.certificate
	if c := a.EnrollmentCertificate; c != nil {
		m.enrollment = []vault.UserEnrollmentCertificate{*c}
		m.selection = catalogEnrollmentSelection{User: a.State.UserID, BootstrapEncryption: a.State.Encryption, BootstrapSigning: a.State.Signing, Encryption: vault.KeyRef{ID: c.Rekey.EncryptionKeyID, Version: c.Rekey.KeyVersion}, Signing: vault.KeyRef{ID: c.Rekey.SigningKeyID, Version: c.Rekey.KeyVersion}}
		m.selection.PublicDigest = enrollmentPublicDigest(c.Rekey.Public)
		m.keyKey = catalogKeyName("key", m.selection.Signing)
		m.enrollmentKey = catalogEnrollmentName(*a.State)
		// Stronger bootstrap certificates can be renewed without changing this
		// final delegation. Their current minimums are verified independently.
		m.keyValue = struct {
			Manifest vault.InviteManifest   `json:"manifest"`
			Rekey    vault.InviteRekeyProof `json:"rekey"`
		}{c.Manifest, c.Rekey}
	}
	m.minimum = max(1, s.Catalog[m.keyKey].Revision, s.Catalog[m.enrollmentKey].Revision)
	if len(m.enrollment) > 0 && s.Enrollment != nil && a.State.UserID == s.UserID && s.Account != nil && s.Account.Encryption == a.State.Encryption && s.Account.Signing == a.State.Signing {
		m.minimum = max(m.minimum, s.Enrollment.ManifestRevision)
	}
	return m
}

func enrollmentPublicDigest(keys vault.UserPublicKeys) (digest [32]byte) {
	h := sha256.New()
	h.Write([]byte("wormhole/v1/enrollment-public"))
	h.Write(keys.Encryption)
	h.Write(keys.Signing)
	copy(digest[:], h.Sum(nil))
	return digest
}

func (s TrustState) mergeCatalogAuthor(a UnverifiedNodeAuthor, m catalogAuthorMaterial, floor CatalogFloor, sequence, revision uint64, verifyErr error, records ...catalogFloorObservation) (TrustState, error) {
	author := catalogFloorObservation{"author/" + a.State.UserID.String(), sequence, *a.State}
	entries := []catalogFloorObservation{author}
	if sequence > 0 && a.State.Active && a.EnrollmentCertificate != nil {
		bootstrap, err := s.enrollmentBootstrapObservations(*a.EnrollmentCertificate, *a.State)
		entries = append(entries, bootstrap...)
		if err != nil {
			return s.mergeCatalogObservations(*a.State, floor, sequence, err, entries...)
		}
	}
	if revision > 0 {
		if err := s.checkCatalogAuthorSelection(a, m); err != nil {
			return s.mergeCatalogObservations(*a.State, floor, sequence, err, entries...)
		}
	}
	entries = append(entries, catalogFloorObservation{m.keyKey, revision, m.keyValue})
	if m.enrollmentKey != "" {
		entries = append(entries, catalogFloorObservation{m.enrollmentKey, revision, m.selection})
	}
	entries = append(entries, records...)
	return s.mergeCatalogObservations(*a.State, floor, sequence, verifyErr, entries...)
}

// Only call after the current signed state and selected author proof verify.
// A known final selection constrains both catalog reads and local enrollment;
// neither can re-enable bootstrap signing or select another pair at a new revision.
func (s TrustState) checkCatalogAuthorSelection(a UnverifiedNodeAuthor, m catalogAuthorMaterial) error {
	owned := s.Enrollment != nil && a.State.UserID == s.UserID && s.Account != nil && s.Account.Signing == a.State.Signing && s.Account.Encryption == a.State.Encryption
	if m.enrollmentKey == "" {
		if owned || s.Catalog[catalogEnrollmentName(*a.State)].Revision > 0 {
			return vault.ErrAuthentication
		}
		return nil
	}
	if old := s.Catalog[m.enrollmentKey]; old.Revision > 0 {
		raw, _ := json.Marshal(m.selection)
		digest := sha256.Sum256(raw)
		if !bytes.Equal(old.Digest, digest[:]) {
			return ErrCatalogEquivocation
		}
	}
	if owned {
		p := s.Enrollment
		if p.Encryption != m.selection.Encryption || p.Signing != m.selection.Signing || !bytes.Equal(p.PublicDigest, m.selection.PublicDigest[:]) {
			return ErrAccountEquivocation
		}
	}
	return nil
}

// Bootstrap certificates have their own independent revision/digest floors.
// Authenticate them even when the later manifest/rekey/record fails, so a bad
// delegation cannot hide a valid newer organisation certificate observation.
func (s TrustState) enrollmentBootstrapObservations(c vault.UserEnrollmentCertificate, state vault.UserKeyState) ([]catalogFloorObservation, error) {
	if !state.Active {
		return nil, vault.ErrPolicy
	}
	trust, err := s.accountTrust()
	if err != nil {
		return nil, err
	}
	var entries []catalogFloorObservation
	var first error
	for _, item := range []struct {
		certificate vault.UserKeyCertificate
		key         vault.KeyRef
		kind        string
		minimum     uint64
	}{
		{c.BootstrapEncryption, state.Encryption, "user-enc", state.MinimumEncryptionCertificate},
		{c.BootstrapSigning, state.Signing, "user-sign", state.MinimumSigningCertificate},
	} {
		key := catalogKeyName("key", item.key)
		err := vault.VerifyUserKeyCertificate(item.certificate, s.WorkspaceID, state.UserID, item.key, item.kind, trust.Signer, trust.Organisation, max(item.minimum, s.Catalog[key].Revision))
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		entries = append(entries, catalogFloorObservation{key, item.certificate.Revision, item.certificate})
	}
	return entries, first
}
