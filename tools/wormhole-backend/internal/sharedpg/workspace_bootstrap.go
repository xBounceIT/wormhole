package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// workspaceBootstrap holds the signed and encrypted records for an empty
// workspace. The first administrator takes the same certified Join path as
// subsequent accounts. The DBA never receives a private key or enrollment code.
type workspaceBootstrap struct {
	invitation    Invitation
	certification UnverifiedInvitationCertification
	manifest      vault.InviteManifest
	envelope      []byte
	organisation  vault.UserPublicKeys
	recovery      vault.OrganisationRecoveryBinding
	recoveryKeys  vault.Envelope
	caKey         *workspaceCAKeyCopy
	boundary      vault.BoundaryManifest
	copies        []workspaceBootstrapCopy
}

type workspaceBootstrapCopy struct {
	binding vault.KeyCopyBinding
	copy    vault.SignedKeyCopy
}

// Only the protected setup owner may retain these factors. The separate
// recovery key opens the offline capsule, while the invite code is single-use.
type workspaceBootstrapSecrets struct {
	invitationCode [vault.InviteCodeBytes]byte
	recoveryKey    [32]byte
}

func (s *workspaceBootstrapSecrets) wipe() {
	vault.Wipe(s.invitationCode[:])
	vault.Wipe(s.recoveryKey[:])
}

// caRoots are the roots of the Verified TLS connection, selected by the
// calling setup flow from its approved trust data. They are DER certificates.
// The caller must durably protect the setup checkpoint and arrange offline
// recovery custody before publishing these records to the server.
func prepareWorkspaceBootstrap(workspace uuid.UUID, roleTag string, settings Settings, caRoots [][]byte, login string, requireASK bool, now time.Time, org *bootstrapOrganisation) (*workspaceBootstrap, *workspaceBootstrapSecrets, error) {
	if deploy.ValidateIdentity(roleTag, workspace.String()) != nil || !identifier(settings.Database) || len(settings.Endpoints) != 1 || settings.Endpoints[0].Port == 0 || now.IsZero() || now.Year() >= 9999 || len(caRoots) > 8 {
		return nil, nil, ErrConfiguration
	}
	if _, err := vault.SharedSalt(workspace.String(), login); err != nil {
		return nil, nil, ErrConfiguration
	}
	if settings.Profile != vault.Default && settings.Profile != vault.Standard {
		return nil, nil, vault.ErrPolicy
	}
	endpoint := settings.Endpoints[0]
	dns, ips, err := serverCertificateNames([]string{endpoint.Host})
	if err != nil {
		return nil, nil, err
	}
	if len(dns) == 1 {
		endpoint.Host = dns[0]
	} else {
		endpoint.Host = ips[0].String()
	}
	if org == nil {
		generated := newBootstrapOrganisation(workspace)
		defer generated.keys.Wipe()
		org = &generated
	} else if org.binding.WorkspaceID != workspace || len(caRoots) != 1 || !bytes.Equal(caRoots[0], org.caDER) {
		return nil, nil, ErrServerCertificate
	}
	result := &workspaceBootstrap{recovery: org.binding, caKey: org.caKey}
	keys := org.keys
	result.organisation, err = keys.Public()
	if err != nil {
		return nil, nil, err
	}
	signer := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(signer)

	// Sign an owned, canonical snapshot without sorting or retaining the input.
	cas := slices.Clone(caRoots)
	slices.SortFunc(cas, bytes.Compare)
	cas = slices.CompactFunc(cas, bytes.Equal)
	tlsHosts := []string{endpoint.Host}
	if org.caKey != nil {
		issued, err := x509.ParseCertificate(org.serverDER)
		if err != nil {
			return nil, nil, ErrServerCertificate
		}
		tlsHosts = slices.Clone(issued.DNSNames)
		for _, ip := range issued.IPAddresses {
			tlsHosts = append(tlsHosts, ip.String())
		}
		slices.Sort(tlsHosts)
	}
	bundle, err := SignTLSTrustBundle(TLSTrustBundle{FormatVersion: 1, WorkspaceID: workspace, Signer: result.recovery.Signing,
		Sequence: 1, CAs: cas, Hosts: tlsHosts, Revoked: []TLSRevocation{}}, signer)
	if err != nil {
		return nil, nil, err
	}
	tls, err := EncodeTLSTrustBundle(bundle)
	if err != nil {
		return nil, nil, err
	}
	invite := vault.InviteContext{WorkspaceID: workspace, UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: login}
	result.invitation = verifiedEnrollmentInvitation(invite, roleTag, settings.Database, []Endpoint{endpoint},
		result.organisation.Signing, tls, now.Add(72*time.Hour).Unix())
	if err := result.invitation.Validate(now); err != nil {
		return nil, nil, err
	}
	bootstrap, err := vault.NewInviteBootstrap(result.organisation.Signing)
	if err != nil {
		return nil, nil, err
	}
	defer bootstrap.Wipe()
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		return nil, nil, err
	}
	if err := result.certify(public, settings, requireASK, signer); err != nil {
		return nil, nil, err
	}
	if err := result.prepareBoundary(keys, public.Encryption, signer); err != nil {
		return nil, nil, err
	}
	var secrets workspaceBootstrapSecrets
	rand.Read(secrets.invitationCode[:])
	rand.Read(secrets.recoveryKey[:])
	if err := result.seal(bootstrap, keys, &secrets, now); err != nil {
		secrets.wipe()
		return nil, nil, err
	}
	return result, &secrets, nil
}

func (p *workspaceBootstrap) certify(public vault.UserPublicKeys, settings Settings, requireASK bool, signer ed25519.PrivateKey) error {
	i := p.invitation.Enrollment.Context
	org := p.recovery.Signing
	certification, err := certifyInvitationBootstrap(i, org, public, signer)
	if err != nil {
		return err
	}
	policy := vault.Policy{FormatVersion: 1, WorkspaceID: i.WorkspaceID.String(), Sequence: 1, Profile: settings.Profile, KDF: vault.KDFV1,
		ASKRequired: requireASK, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	devices := settings.Changes.ConcurrentDevices
	if settings.Changes.TransactionPooler {
		devices = 0
	}
	policy.DirectConnectionDevices = &devices
	signed, err := vault.SignPolicy(policy, org.ID.String(), org.Version, signer)
	if err != nil {
		return err
	}
	certification.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		return err
	}
	p.certification = certification
	p.manifest = vault.InviteManifest{FormatVersion: 1, Context: i, Revision: 1, ExpiresAt: p.invitation.ExpiresAt, Bootstrap: public,
		Issuers: []vault.InviteIssuer{{Key: org, Public: p.organisation.Signing}}}
	return nil
}

func certifyInvitationBootstrap(i vault.InviteContext, org vault.KeyRef, public vault.UserPublicKeys, signer ed25519.PrivateKey) (UnverifiedInvitationCertification, error) {
	enc := vault.KeyRef{ID: i.KeyID, Version: i.KeyVersion}
	sign := vault.KeyRef{ID: uuid.New(), Version: 1}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: 1, WorkspaceID: i.WorkspaceID, UserID: i.UserID, Sequence: 1,
		Active: true, Encryption: enc, Signing: sign, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: org}, signer)
	if err != nil {
		return UnverifiedInvitationCertification{}, err
	}
	base := vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: i.WorkspaceID, UserID: i.UserID, Revision: 1, Signer: org}
	base.Key, base.Kind, base.Suite, base.PublicKey = enc, "user-enc", vault.SuiteX25519HKDFSHA256AES256GCM, public.Encryption
	encCert, err := vault.SignUserKeyCertificate(base, signer)
	if err != nil {
		return UnverifiedInvitationCertification{}, err
	}
	base.Key, base.Kind, base.Suite, base.PublicKey = sign, "user-sign", 1, public.Signing
	signCert, err := vault.SignUserKeyCertificate(base, signer)
	if err != nil {
		return UnverifiedInvitationCertification{}, err
	}
	return UnverifiedInvitationCertification{State: state, Encryption: encCert, Signing: signCert}, nil
}

func newBoundaryRoot(raw []byte) (vault.BoundaryKey, error) {
	rand.Read(raw)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return vault.BoundaryKey{}, err
	}
	return vault.BoundaryKey{Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Public: key.PublicKey().Bytes()}, nil
}

func (p *workspaceBootstrap) prepareBoundary(keys *vault.UserKeys, recipient []byte, signer ed25519.PrivateKey) error {
	view, secret := make([]byte, 32), make([]byte, 32)
	defer vault.Wipe(view)
	defer vault.Wipe(secret)
	viewRoot, err := newBoundaryRoot(view)
	if err != nil {
		return err
	}
	secretRoot, err := newBoundaryRoot(secret)
	if err != nil {
		return err
	}
	b := vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: p.invitation.WorkspaceID, BoundaryID: uuid.New(), Revision: 1,
		OrgEscrow: true, Active: true, View: viewRoot, Secret: secretRoot, Signer: p.recovery.Signing}
	p.boundary, err = vault.SignBoundaryManifest(b, signer)
	if err != nil {
		return err
	}
	holder := p.certification.Encryption.Key
	for _, item := range []struct {
		ref vault.KeyRef
		raw []byte
	}{{p.recovery.Encryption, keys.EncryptionPrivate}, {p.recovery.Signing, keys.SigningSeed}, {viewRoot.Key, view}, {secretRoot.Key, secret}} {
		binding := vault.KeyCopyBinding{WorkspaceID: b.WorkspaceID, Key: item.ref, Holder: holder, Issuer: b.Signer}
		wrapped, err := vault.SealKeyCopy(item.raw, binding, recipient, keys.SigningSeed)
		if err != nil {
			return err
		}
		p.copies = append(p.copies, workspaceBootstrapCopy{binding, wrapped})
		p.manifest.Copies = append(p.manifest.Copies, binding)
		if item.ref == viewRoot.Key || item.ref == secretRoot.Key {
			binding.Holder = p.recovery.Encryption
			escrow, err := vault.SealKeyCopy(item.raw, binding, p.organisation.Encryption, keys.SigningSeed)
			if err != nil {
				return err
			}
			p.copies = append(p.copies, workspaceBootstrapCopy{binding, escrow})
		}
	}
	return nil
}

func (p *workspaceBootstrap) seal(bootstrap *vault.InviteBootstrap, keys *vault.UserKeys, secrets *workspaceBootstrapSecrets, now time.Time) error {
	var err error
	p.manifest, err = vault.SignInviteManifest(p.manifest, keys.SigningSeed)
	if err != nil {
		return err
	}
	wrapped, err := p.invitation.SealBootstrap(secrets.invitationCode[:], bootstrap, now)
	if err != nil {
		return err
	}
	p.envelope, err = EncodeInvitationBootstrapEnvelope(p.invitation, wrapped, now)
	if err != nil {
		return err
	}
	p.recoveryKeys, err = vault.SealOrganisationRecovery(secrets.recoveryKey[:], p.recovery, keys)
	return err
}
