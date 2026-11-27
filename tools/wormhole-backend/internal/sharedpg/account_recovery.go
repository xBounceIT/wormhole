package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrAccountRecovery = errors.New("shared account recovery custody is unavailable")

const accountRecoveryAvailableSQL = `SELECT
	(pg_catalog.to_regprocedure('wormhole_api_v1.account_recovery_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)') IS NOT NULL)::text`
const accountRecoveryMaterialSQL = `SELECT wormhole_api_v1.account_recovery_material(` + serverCAArguments + `)::text`
const storeAccountRecoverySQL = `SELECT wormhole_api_v1.store_account_recovery(` + serverCAArguments +
	`,$10::uuid,$11::integer,pg_catalog.decode($12,'hex'),$13::jsonb)`

type accountRecoveryMaterial struct {
	Recipient          vault.KeyRef                 `json:"recipient"`
	Signer             vault.KeyRef                 `json:"signer"`
	PublicKey          []byte                       `json:"publicKey"`
	Certificate        []byte                       `json:"certificate"`
	OrganisationCopies []workspaceAdminRecoveryCopy `json:"organisationCopies"`
	AccountCopies      []workspaceAdminRecoveryCopy `json:"accountCopies"`
}

// EnsureAccountRecovery deposits the unlocked account's current private keys
// under signed workspace escrow policy. The caller owns keys and borrows them
// only for this call. False means custody has not been confirmed.
func (s *Session) EnsureAccountRecovery(ctx context.Context, trust TrustState, keys *vault.UserKeys) (bool, error) {
	if ctx == nil || keys == nil {
		return false, ErrConfiguration
	}
	policy, err := trust.Policy()
	if err != nil {
		return false, err
	}
	if !policy.OrgEscrow || (policy.Profile != vault.Default && policy.Profile != vault.Standard) ||
		trust.TLSSequence == 0 || trust.Enrollment == nil {
		return false, nil
	}
	account, err := trust.AccountTrust()
	if err != nil || !trust.Account.Active {
		return false, vault.ErrAuthentication
	}
	public, err := keys.Public()
	if err != nil {
		return false, err
	}
	digest := enrollmentPublicDigest(public)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return false, vault.ErrAuthentication
	}
	supported, err := s.accountRecoverySupported(ctx)
	if err != nil || !supported {
		return false, err
	}
	var material *accountRecoveryMaterial
	err = s.queryServerCA(ctx, trust, accountRecoveryMaterialSQL, nil, 4096, 1, 1, func(rows [][][]byte) error {
		var err error
		material, err = parseAccountRecoveryMaterial(rows)
		return err
	})
	if err != nil || material == nil {
		return false, err
	}
	recipient := vault.OrganisationRecoveryRecipient{
		WorkspaceID: trust.WorkspaceID, Encryption: material.Recipient, Signer: material.Signer, PublicKey: material.PublicKey,
	}
	certificate, err := material.authenticateRecipient(recipient, trust, account, keys)
	if err != nil {
		return false, errors.Join(ErrAccountRecovery, err)
	}
	if certificate == nil {
		return false, nil
	}
	encryption := accountRecoveryBinding(trust, trust.Enrollment.Encryption, material.Recipient)
	signing := accountRecoveryBinding(trust, trust.Enrollment.Signing, material.Recipient)
	if len(material.Certificate) != 0 &&
		validAccountRecoveryCopy(material.AccountCopies, encryption, public.Signing) &&
		validAccountRecoveryCopy(material.AccountCopies, signing, public.Signing) {
		return true, nil
	}
	rows := make([]workspaceAdminRecoveryCopy, 0, 2)
	for _, item := range []struct {
		binding vault.KeyCopyBinding
		key     []byte
	}{{encryption, keys.EncryptionPrivate}, {signing, keys.SigningSeed}} {
		copy, err := vault.SealKeyCopy(item.key, item.binding, recipient.PublicKey, keys.SigningSeed)
		if err != nil {
			return false, err
		}
		rows = append(rows, workspaceAdminRecoveryCopy{
			KeyRef: item.binding.Key, Enc: copy.Envelope.Enc, Ciphertext: copy.Envelope.Ciphertext, Signature: copy.Signature,
		})
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return false, err
	}
	args := [][]byte{[]byte(material.Recipient.ID.String()), strconv.AppendUint(nil, uint64(material.Recipient.Version), 10),
		hex.AppendEncode(nil, certificate), payload}
	err = s.queryServerCA(ctx, trust, storeAccountRecoverySQL, args, 32, 1, 1, checkAccountRecoveryReceipt)
	return err == nil, err
}

func checkAccountRecoveryReceipt(rows [][][]byte) error {
	if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != "stored" {
		return ErrAdmissionResponse
	}
	return nil
}

// Older deployed workspaces can still unlock. Probe the fixed function name
// before using the newer custody API.
func (s *Session) accountRecoverySupported(ctx context.Context) (bool, error) {
	rows, err := s.Query(ctx, accountRecoveryAvailableSQL, nil)
	if err != nil {
		return false, err
	}
	defer wipeQueryRows(rows)
	if len(rows) != 1 || len(rows[0]) != 1 {
		return false, ErrAdmissionResponse
	}
	switch string(rows[0][0]) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, ErrAdmissionResponse
	}
}

func parseAccountRecoveryMaterial(rows [][][]byte) (*accountRecoveryMaterial, error) {
	if len(rows) != 1 || len(rows[0]) != 1 || len(rows[0][0]) > 4096 {
		return nil, ErrAdmissionResponse
	}
	var material *accountRecoveryMaterial
	if err := json.Unmarshal(rows[0][0], &material); err != nil {
		return nil, ErrAdmissionResponse
	}
	if material != nil && (len(material.PublicKey) != 32 ||
		(len(material.Certificate) != 0 && len(material.Certificate) != ed25519.SignatureSize) ||
		(len(material.OrganisationCopies) != 0 && (len(material.OrganisationCopies) != 2 || len(material.Certificate) != 0)) ||
		len(material.AccountCopies) > 2) {
		return nil, ErrAdmissionResponse
	}
	return material, nil
}

func (m *accountRecoveryMaterial) authenticateRecipient(recipient vault.OrganisationRecoveryRecipient, trust TrustState, account vault.UserKeyTrust, keys *vault.UserKeys) ([]byte, error) {
	if recipient.Signer != account.Signer {
		return nil, vault.ErrAuthentication
	}
	certificate := m.Certificate
	if len(certificate) == 0 {
		if len(m.OrganisationCopies) == 0 {
			return nil, nil
		}
		custody, err := openEscrowKeyPair(m.OrganisationCopies, recipient.Encryption, recipient.Signer, func(row workspaceAdminRecoveryCopy) ([]byte, error) {
			return openServerCAOrgCopy(trust, row.KeyRef, accountRecoverySignedCopy(row), keys.EncryptionPrivate, keys.SigningSeed)
		})
		if err != nil {
			return nil, err
		}
		defer custody.Wipe()
		if err := verifyEscrowKeyPair(custody, vault.UserPublicKeys{Encryption: recipient.PublicKey, Signing: account.Organisation}); err != nil {
			return nil, err
		}
		certificate, err = vault.SignOrganisationRecoveryRecipient(recipient, custody.SigningSeed)
		if err != nil {
			return nil, err
		}
	}
	if err := vault.VerifyOrganisationRecoveryRecipient(recipient, certificate, trust.WorkspaceID, account.Signer, account.Organisation); err != nil {
		return nil, err
	}
	return certificate, nil
}

func accountRecoveryBinding(trust TrustState, key, recipient vault.KeyRef) vault.KeyCopyBinding {
	return vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: key, Holder: recipient, Issuer: trust.Enrollment.Signing}
}

func validAccountRecoveryCopy(rows []workspaceAdminRecoveryCopy, binding vault.KeyCopyBinding, public ed25519.PublicKey) bool {
	for _, row := range rows {
		if row.KeyRef == binding.Key {
			return vault.VerifyKeyCopy(binding, accountRecoverySignedCopy(row), public) == nil
		}
	}
	return false
}

func accountRecoverySignedCopy(row workspaceAdminRecoveryCopy) vault.SignedKeyCopy {
	return vault.SignedKeyCopy{
		Envelope: vault.SealedBundle{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM,
			Enc: row.Enc, Ciphertext: row.Ciphertext},
		Signature: row.Signature,
	}
}
