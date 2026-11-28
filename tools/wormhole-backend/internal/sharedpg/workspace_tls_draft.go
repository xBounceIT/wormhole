package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxServerCSRBytes = 32 * 1024

const (
	workspaceCAValidity = 5 * 365 * 24 * time.Hour
	serverCertValidity  = 365 * 24 * time.Hour
)

type workspaceCAKeyCopy struct {
	Key  vault.KeyRef        `json:"key"`
	Copy vault.SignedKeyCopy `json:"copy"`
}

func (c workspaceCAKeyCopy) binding(org vault.OrganisationRecoveryBinding) vault.KeyCopyBinding {
	return vault.KeyCopyBinding{WorkspaceID: org.WorkspaceID, Key: c.Key, Holder: org.Encryption, Issuer: org.Signing}
}

type bootstrapOrganisation struct {
	binding   vault.OrganisationRecoveryBinding
	keys      *vault.UserKeys
	caKey     *workspaceCAKeyCopy
	caDER     []byte
	serverDER []byte
}

func newBootstrapOrganisation(workspace uuid.UUID) bootstrapOrganisation {
	keys := &vault.UserKeys{EncryptionPrivate: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	rand.Read(keys.EncryptionPrivate)
	rand.Read(keys.SigningSeed)
	return bootstrapOrganisation{
		binding: vault.OrganisationRecoveryBinding{
			WorkspaceID: workspace,
			Encryption:  vault.KeyRef{ID: uuid.New(), Version: 1},
			Signing:     vault.KeyRef{ID: uuid.New(), Version: 1},
		},
		keys: keys,
	}
}

type workspaceTLSDraftProtection struct {
	Slot    vault.Slot     `json:"slot"`
	Private vault.Envelope `json:"private"`
}

// WorkspaceTLSDraft contains public certificates, the organisation-wrapped CA
// key and a temporary password/ASK-protected copy of the organisation keys.
// Drop the temporary copy once the administrator checkpoint is durable.
type WorkspaceTLSDraft struct {
	Organisation vault.KeyRef                 `json:"organisationEncryption"`
	Signing      vault.KeyRef                 `json:"organisationSigning"`
	Public       vault.UserPublicKeys         `json:"organisation"`
	CA           workspaceCAKeyCopy           `json:"ca"`
	Certificate  []byte                       `json:"certificateDer"`
	ServerPEM    string                       `json:"serverPem"`
	Protection   *workspaceTLSDraftProtection `json:"protection,omitempty"`
}

// WorkspaceTLSInstallation pairs the native deployment scope with its saved
// built-in CA. An external CA uses the normal deployment path without a draft.
type WorkspaceTLSInstallation struct {
	Scope WorkspaceBootstrapScope
	Draft *WorkspaceTLSDraft
}

func (d WorkspaceTLSDraft) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.Certificate})
}

func (d WorkspaceTLSDraft) orgBinding(workspace uuid.UUID) vault.OrganisationRecoveryBinding {
	return vault.OrganisationRecoveryBinding{WorkspaceID: workspace, Encryption: d.Organisation, Signing: d.Signing}
}

func (d WorkspaceTLSDraft) factorBinding(scope WorkspaceBootstrapScope) (vault.Binding, error) {
	slot := d.Protection.Slot.ID
	d.Protection = nil
	raw, err := json.Marshal(d)
	if err != nil {
		return vault.Binding{}, err
	}
	digest := sha256.Sum256(raw)
	return vault.Binding{
		WorkspaceID: scope.WorkspaceID.String(), Table: "SharedWorkspaceTLS",
		OwnerID: hex.EncodeToString(scope.PlanDigest[:]), Field: hex.EncodeToString(digest[:]),
		KeyID: slot, KeyVersion: 1,
	}, nil
}

// PrepareWorkspaceTLS validates the full SAN set before issuing a server
// certificate. The public key comes from the verified CSR. The
// database server's private key never enters the setup process.
func PrepareWorkspaceTLS(ctx context.Context, scope WorkspaceBootstrapScope, endpoint string, hosts []string, csr, password, ask []byte, now time.Time) (*WorkspaceTLSDraft, error) {
	if ctx == nil || !scope.valid() || !validWorkspaceBootstrapFactors(password, ask) {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dns, ips, err := serverCertificateNames(hosts)
	if err != nil {
		return nil, err
	}
	// The configured endpoint must be one of the exact approved names.
	ip := net.ParseIP(endpoint)
	if !slices.Contains(dns, strings.ToLower(endpoint)) && !slices.ContainsFunc(ips, ip.Equal) {
		return nil, ErrServerCertificate
	}
	org := newBootstrapOrganisation(scope.WorkspaceID)
	defer org.keys.Wipe()
	public, err := org.keys.Public()
	if err != nil {
		return nil, err
	}
	key := workspaceCAKeyCopy{Key: vault.KeyRef{ID: uuid.New(), Version: 1}}
	binding := key.binding(org.binding)
	ca, err := CreateWorkspaceCA(binding, public.Encryption, org.keys.SigningSeed, hosts, now, now.Add(workspaceCAValidity))
	if err != nil {
		return nil, err
	}
	server, err := ca.IssueServerCertificate(binding, org.keys.EncryptionPrivate, public.Signing, csr, hosts, now, serverCertValidity)
	if err != nil {
		return nil, err
	}
	key.Copy = ca.KeyCopy
	draft := &WorkspaceTLSDraft{
		Organisation: org.binding.Encryption, Signing: org.binding.Signing, Public: public, CA: key,
		Certificate: ca.CertificateDER, ServerPEM: string(server), Protection: &workspaceTLSDraftProtection{},
	}
	root := vault.NewRecoveryKey()
	defer vault.Wipe(root)
	draft.Protection.Slot, err = vault.CreatePasswordSlot(ctx, scope.WorkspaceID.String(), uuid.NewString(), 1, root, password, ask, vault.KDFV1)
	if err != nil {
		return nil, err
	}
	aad, err := draft.factorBinding(scope)
	if err != nil {
		return nil, err
	}
	var plain [64]byte
	defer vault.Wipe(plain[:])
	copy(plain[:32], org.keys.EncryptionPrivate)
	copy(plain[32:], org.keys.SigningSeed)
	draft.Protection.Private, err = vault.Seal(root, aad, plain[:])
	if err != nil {
		return nil, err
	}
	return draft, nil
}

func (d *WorkspaceTLSDraft) open(ctx context.Context, scope WorkspaceBootstrapScope, password, ask []byte) (*bootstrapOrganisation, error) {
	if ctx == nil || d == nil || d.Protection == nil || !scope.valid() || !validWorkspaceBootstrapFactors(password, ask) {
		return nil, ErrConfiguration
	}
	slot := d.Protection.Slot
	if slot.Preset != vault.KDFV1 || slot.WrappedKey.KeyVersion != 1 || len(d.Protection.Private.Ciphertext) != 80 {
		return nil, vault.ErrFormat
	}
	root, err := vault.OpenPasswordSlot(ctx, scope.WorkspaceID.String(), slot, password, ask)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(root)
	aad, err := d.factorBinding(scope)
	if err != nil {
		return nil, err
	}
	plain, err := vault.Open(root, aad, d.Protection.Private)
	if err != nil {
		return nil, err
	}
	keys := &vault.UserKeys{EncryptionPrivate: plain[:32:32], SigningSeed: plain[32:]}
	binding := d.orgBinding(scope.WorkspaceID)
	public, err := keys.Public()
	server, rest := pem.Decode([]byte(d.ServerPEM))
	if err != nil || !bytes.Equal(public.Encryption, d.Public.Encryption) || !bytes.Equal(public.Signing, d.Public.Signing) ||
		vault.VerifyKeyCopy(d.CA.binding(binding), d.CA.Copy, public.Signing) != nil || server == nil || server.Type != "CERTIFICATE" || len(rest) != 0 {
		keys.Wipe()
		return nil, vault.ErrAuthentication
	}
	return &bootstrapOrganisation{binding: binding, keys: keys, caKey: &d.CA, caDER: d.Certificate, serverDER: server.Bytes}, nil
}
