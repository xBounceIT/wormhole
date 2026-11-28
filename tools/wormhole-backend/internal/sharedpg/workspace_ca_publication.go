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

const serverCARotationMaterialSQL = `SELECT kind,` + serverCAKeyColumns + `,ca::text
	FROM wormhole_api_v1.server_ca_rotation_material(` + serverCAArguments + `) ORDER BY kind`

const publishServerCARotationSQL = `SELECT wormhole_api_v1.publish_server_ca_rotation(` + serverCAArguments +
	`,pg_catalog.decode($10,'hex'),$11::jsonb)::text`

// PublishWorkspaceCAOverlap signs and atomically publishes the new wrapped CA
// and the bundle containing both roots. The returned public leaf can be
// recovered from the signed overlap after a lost acknowledgement or restart.
// The controller must enforce the fresh effective profile and persist trust
// observations before using the new bundle as a transport anchor.
func (s *Session) PublishWorkspaceCAOverlap(ctx context.Context, trust TrustState, current *VerifiedTLSBundle, userPrivate, userSigningSeed, csr []byte, now time.Time) (*VerifiedTLSBundle, error) {
	if ctx == nil || len(userPrivate) != 32 || len(userSigningSeed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, current); err != nil {
		return nil, err
	}
	if len(current.bundle.CAs) != 1 {
		return nil, ErrWorkspaceCARotation
	}
	dns, ips, err := serverCertificateNames(current.bundle.Hosts)
	if err != nil {
		return nil, err
	}
	if _, err := approvedServerCSR(csr, dns, ips); err != nil {
		return nil, err
	}
	before, org, keys, err := s.openWorkspaceCAOrganisation(ctx, trust, current, userPrivate, userSigningSeed)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe()
	rotation, err := prepareWorkspaceCARotation(current, before, org, keys, csr, now)
	if err != nil {
		return nil, err
	}
	keyCopy, err := json.Marshal(rotation.key)
	if err != nil {
		return nil, err
	}
	if err := s.publishWorkspaceCAUpdate(ctx, trust, rotation.overlap, keyCopy); err != nil {
		return nil, err
	}
	return rotation.overlap, nil
}

// PublishWorkspaceCARetirement checks every authenticated configured endpoint
// and atomically publishes a higher-sequence bundle containing the new root.
func (s *Session) PublishWorkspaceCARetirement(ctx context.Context, trust TrustState, current *VerifiedTLSBundle, settings Settings, userPrivate, userSigningSeed []byte) (*VerifiedTLSBundle, error) {
	if ctx == nil || len(userPrivate) != 32 || len(userSigningSeed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, current); err != nil {
		return nil, err
	}
	if len(current.PendingServerCertificate()) == 0 {
		return nil, ErrWorkspaceCARotation
	}
	_, _, keys, err := s.openWorkspaceCAOrganisation(ctx, trust, current, userPrivate, userSigningSeed)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe()
	final, err := current.retirePreviousWorkspaceCA(ctx, settings, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	if err := s.publishWorkspaceCAUpdate(ctx, trust, final, nil); err != nil {
		return nil, err
	}
	return final, nil
}

func (s *Session) openWorkspaceCAOrganisation(ctx context.Context, trust TrustState, current *VerifiedTLSBundle, userPrivate, userSigningSeed []byte) (workspaceCAKeyCopy, vault.OrganisationRecoveryBinding, *vault.UserKeys, error) {
	var material *serverCertificateRenewalMaterial
	var signKey vault.KeyRef
	var signCopy vault.SignedKeyCopy
	err := s.queryServerCA(ctx, trust, serverCARotationMaterialSQL, nil, 4096, 2, 7, func(rows [][][]byte) error {
		var err error
		material, signKey, signCopy, err = parseWorkspaceCAOrganisation(rows)
		return err
	})
	if err != nil {
		return workspaceCAKeyCopy{}, vault.OrganisationRecoveryBinding{}, nil, err
	}
	pin := current.pin
	if signKey != pin.Signer || (current.bundle.WorkspaceCA != nil && material.ca.Key != current.bundle.WorkspaceCA.Key) {
		return workspaceCAKeyCopy{}, vault.OrganisationRecoveryBinding{}, nil, vault.ErrAuthentication
	}
	private, err := openServerCAOrgCopy(trust, material.organisation, material.copy, userPrivate, userSigningSeed)
	if err != nil {
		return workspaceCAKeyCopy{}, vault.OrganisationRecoveryBinding{}, nil, err
	}
	seed, err := openServerCAOrgCopy(trust, signKey, signCopy, userPrivate, userSigningSeed)
	keys := &vault.UserKeys{EncryptionPrivate: private, SigningSeed: seed}
	// Even a syntactically valid organisation copy is untrusted until both
	// its signer and its ability to open the signed issuing CA match.
	organisation := vault.OrganisationRecoveryBinding{WorkspaceID: trust.WorkspaceID, Encryption: material.organisation, Signing: pin.Signer}
	ca := workspaceRecoveryCA{Certificate: current.bundle.workspaceIssuer(), Key: material.ca}
	public, publicErr := keys.Public()
	if err != nil || publicErr != nil || !bytes.Equal(public.Signing, pin.Organisation) || !ca.matches(keys.EncryptionPrivate, organisation, pin.Organisation) {
		keys.Wipe()
		return workspaceCAKeyCopy{}, vault.OrganisationRecoveryBinding{}, nil, vault.ErrAuthentication
	}
	return material.ca, organisation, keys, nil
}

func parseWorkspaceCAOrganisation(rows [][][]byte) (*serverCertificateRenewalMaterial, vault.KeyRef, vault.SignedKeyCopy, error) {
	if len(rows) != 2 || len(rows[0]) != 7 || len(rows[1]) != 7 || string(rows[0][0]) != "org-enc" || string(rows[1][0]) != "org-sign" || rows[1][6] != nil {
		return nil, vault.KeyRef{}, vault.SignedKeyCopy{}, ErrAdmissionResponse
	}
	encryption, err := parseServerCertificateRenewal([][][]byte{rows[0][1:]})
	if err != nil {
		return nil, vault.KeyRef{}, vault.SignedKeyCopy{}, err
	}
	key, copy, err := parseServerCAOrgCopy(rows[1][1:6])
	return encryption, key, copy, err
}

func (s *Session) publishWorkspaceCAUpdate(ctx context.Context, trust TrustState, next *VerifiedTLSBundle, keyCopy []byte) error {
	return s.queryServerCA(ctx, trust, publishServerCARotationSQL,
		[][]byte{hex.AppendEncode(nil, next.raw), keyCopy}, 20, 1, 1, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != strconv.FormatUint(next.bundle.Sequence, 10) {
				return ErrAdmissionResponse
			}
			return nil
		})
}
