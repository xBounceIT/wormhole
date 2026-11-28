package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrWorkspaceRecoveryKit = errors.New("shared_workspace_recovery_kit_mismatch")

const workspaceRecoveryKitRefreshSQL = `SELECT ` + serverCAKeyColumns + `,ca::text,
	pg_catalog.encode(bootstrap_recovery,'hex')
	FROM wormhole_api_v1.workspace_recovery_kit_refresh(` + serverCAArguments + `)`

// RefreshWorkspaceRecoveryKit retains the existing recovery envelope and replaces
// its CA record with the current verified authority. The caller enforces the
// effective profile before borrowing the current device's account keys.
func (s *Session) RefreshWorkspaceRecoveryKit(ctx context.Context, trust TrustState, current *VerifiedTLSBundle, source, userPrivate, userSigningSeed []byte) ([]byte, error) {
	if ctx == nil || len(userPrivate) != 32 || len(userSigningSeed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	account, err := authenticatedServerCAContext(trust, current)
	if err != nil {
		return nil, err
	}
	if len(current.bundle.CAs) != 1 {
		return nil, ErrServerCertificateAuthority
	}
	existing, err := decodeWorkspaceRecoveryKit(trust.WorkspaceID, source)
	if err != nil || existing.Signing != account.Signer || !bytes.Equal(existing.Public.Signing, account.Organisation) {
		return nil, ErrWorkspaceRecoveryKit
	}
	var material *serverCertificateRenewalMaterial
	var bootstrap []byte
	err = s.queryServerCA(ctx, trust, workspaceRecoveryKitRefreshSQL, nil, 4096, 1, 7, func(rows [][][]byte) error {
		var err error
		material, bootstrap, err = parseWorkspaceRecoveryKitRefresh(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	organisationPrivate, err := openServerCAOrgCopy(trust, material.organisation, material.copy, userPrivate, userSigningSeed)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(organisationPrivate)
	return refreshWorkspaceRecoveryKit(existing, current, material, bootstrap, organisationPrivate)
}

func parseWorkspaceRecoveryKitRefresh(rows [][][]byte) (*serverCertificateRenewalMaterial, []byte, error) {
	if len(rows) != 1 || len(rows[0]) != 7 || len(rows[0][6]) == 0 || len(rows[0][6]) > 2*maxBootstrapRecoveryBytes {
		return nil, nil, ErrAdmissionResponse
	}
	bootstrap, err := hex.DecodeString(string(rows[0][6]))
	if err != nil {
		return nil, nil, ErrAdmissionResponse
	}
	material, err := parseServerCertificateRenewal([][][]byte{rows[0][:6]})
	if err != nil {
		return nil, nil, err
	}
	return material, bootstrap, nil
}

func refreshWorkspaceRecoveryKit(existing workspaceRecoveryKit, current *VerifiedTLSBundle, material *serverCertificateRenewalMaterial, bootstrap, encryptionPrivate []byte) ([]byte, error) {
	pin := current.pin
	if existing.Encryption != material.organisation {
		return nil, ErrWorkspaceRecoveryKit
	}
	encryption, err := ecdh.X25519().NewPrivateKey(encryptionPrivate)
	if err != nil || !bytes.Equal(encryption.PublicKey().Bytes(), existing.Public.Encryption) {
		return nil, ErrWorkspaceRecoveryKit
	}
	// Compare with the original server capsule, then retain the user's exact
	// envelope. Neither the recovery code nor the org signing seed is needed.
	capsule, _, err := decodeBootstrapRecoveryCapsule(workspaceBootstrapWire{
		Recovery: bootstrap, WorkspaceID: pin.WorkspaceID,
		OrganisationEncryption: material.organisation, OrganisationSigning: pin.Signer,
		Organisation: existing.Public,
	})
	if err != nil {
		return nil, vault.ErrAuthentication
	}
	organisation := vault.OrganisationRecoveryBinding{WorkspaceID: pin.WorkspaceID, Encryption: material.organisation, Signing: pin.Signer}
	if !reflect.DeepEqual(capsule, existing.Capsule) ||
		(existing.CA != nil && !existing.CA.matches(encryptionPrivate, organisation, pin.Organisation)) {
		return nil, ErrWorkspaceRecoveryKit
	}
	ca := &workspaceRecoveryCA{Certificate: current.bundle.workspaceIssuer(), Key: material.ca}
	if (current.bundle.WorkspaceCA != nil && material.ca.Key != current.bundle.WorkspaceCA.Key) ||
		!ca.matches(encryptionPrivate, organisation, pin.Organisation) {
		return nil, vault.ErrAuthentication
	}
	existing.Version, existing.CA = 2, ca
	return encodeWorkspaceRecoveryKit(existing)
}
