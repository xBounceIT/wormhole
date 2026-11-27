package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxWorkspaceBootstrapCheckpointBytes = 1024 * 1024

const (
	bootstrapPrepared byte = iota + 1
	bootstrapRecoveryExported
	bootstrapRecoveryConfirmed
	bootstrapPublished
)

const bootstrapCodeEnd = 1 + vault.InviteCodeBytes
const bootstrapFactorsEnd = bootstrapCodeEnd + 32

// WorkspaceBootstrapScope comes from the independently saved deployment plan.
// Its digest binds the checkpoint to the native path and immutable target.
type WorkspaceBootstrapScope struct {
	WorkspaceID uuid.UUID
	RoleTag     string
	PlanDigest  [32]byte
}

func (s WorkspaceBootstrapScope) valid() bool {
	return s.PlanDigest != [32]byte{} && deploy.ValidateIdentity(s.RoleTag, s.WorkspaceID.String()) == nil
}

func (s WorkspaceBootstrapScope) binding(slotID string) vault.Binding {
	return vault.Binding{WorkspaceID: s.WorkspaceID.String(), Table: "SharedWorkspaceBootstrap", OwnerID: hex.EncodeToString(s.PlanDigest[:]),
		Field: s.RoleTag, KeyID: slotID, KeyVersion: 1}
}

type workspaceBootstrapCheckpointFile struct {
	Version uint16         `json:"version"`
	Slot    vault.Slot     `json:"slot"`
	Payload vault.Envelope `json:"payload"`
}

type workspaceBootstrapCheckpointData struct {
	Invitation Invitation      `json:"invitation"`
	Wire       json.RawMessage `json:"wire"`
}

// WorkspaceBootstrapCheckpoint is a short-lived native owner. Its methods
// borrow or seal factors for one operation. Always close it before replying.
type WorkspaceBootstrapCheckpoint struct {
	scope       WorkspaceBootstrapScope
	slot        vault.Slot
	key         []byte
	data        workspaceBootstrapCheckpointData
	wire        workspaceBootstrapWire
	phase       byte
	code        []byte
	recoveryKey []byte
}

func (c *WorkspaceBootstrapCheckpoint) Close() {
	if c == nil {
		return
	}
	vault.Wipe(c.key)
	vault.Wipe(c.code)
	vault.Wipe(c.recoveryKey)
	c.key, c.code, c.recoveryKey = nil, nil, nil
}

func (c *WorkspaceBootstrapCheckpoint) active() bool { return c != nil && len(c.key) == 32 }

// PrepareWorkspaceBootstrapCheckpoint checks the real deployment and prepares
// the same authenticated invitation used by ordinary Join. No SQL mutations
// occur during preparation. The caller must durably save Seal before proceeding.
func PrepareWorkspaceBootstrapCheckpoint(ctx context.Context, scope WorkspaceBootstrapScope, settings Settings, dbaPassword, password, ask []byte, login string, profile vault.Profile, tls *WorkspaceTLSInstallation) (*WorkspaceBootstrapCheckpoint, error) {
	if ctx == nil || !scope.valid() || !validWorkspaceBootstrapFactors(password, ask) {
		return nil, ErrConfiguration
	}
	var org *bootstrapOrganisation
	if tls != nil {
		if tls.Scope.WorkspaceID != scope.WorkspaceID || tls.Scope.RoleTag != scope.RoleTag {
			return nil, ErrConfiguration
		}
		var err error
		org, err = tls.Draft.open(ctx, tls.Scope, password, ask)
		if err != nil {
			return nil, err
		}
		defer org.keys.Wipe()
	}
	p, factors, err := prepareWorkspaceBootstrapFromDeployment(ctx, settings, dbaPassword, scope.WorkspaceID, scope.RoleTag, login, profile, len(ask) != 0, org)
	if err != nil {
		return nil, err
	}
	defer factors.wipe()
	return newWorkspaceBootstrapCheckpoint(ctx, scope, p, factors, password, ask)
}

func validWorkspaceBootstrapFactors(password, ask []byte) bool {
	return len(password) > 0 && len(password) <= 1024 && (len(ask) == 0 || len(ask) == 32)
}

func newWorkspaceBootstrapCheckpoint(ctx context.Context, scope WorkspaceBootstrapScope, p *workspaceBootstrap, factors *workspaceBootstrapSecrets, password, ask []byte) (*WorkspaceBootstrapCheckpoint, error) {
	raw, err := p.wire()
	if err != nil {
		return nil, err
	}
	data := workspaceBootstrapCheckpointData{p.invitation, raw}
	wire, err := validateWorkspaceBootstrapCheckpointData(scope, data)
	if err != nil {
		return nil, err
	}
	key := vault.NewRecoveryKey()
	slot, err := vault.CreatePasswordSlot(ctx, scope.WorkspaceID.String(), uuid.NewString(), 1, key, password, ask, vault.KDFV1)
	if err != nil {
		vault.Wipe(key)
		return nil, err
	}
	return &WorkspaceBootstrapCheckpoint{scope: scope, slot: slot, key: key, data: data, wire: wire, phase: bootstrapPrepared,
		code: bytes.Clone(factors.invitationCode[:]), recoveryKey: bytes.Clone(factors.recoveryKey[:])}, nil
}

func validateWorkspaceBootstrapCheckpointData(scope WorkspaceBootstrapScope, data workspaceBootstrapCheckpointData) (workspaceBootstrapWire, error) {
	i := data.Invitation
	var wire workspaceBootstrapWire
	// Expiry authorizes network activity, not access to local recovery material.
	if i.FormatVersion != 3 || i.Validate(time.Unix(i.ExpiresAt-1, 0)) != nil || i.WorkspaceID != scope.WorkspaceID ||
		i.Enrollment.RoleTag != scope.RoleTag || len(data.Wire) == 0 || len(data.Wire) > 256*1024 || json.Unmarshal(data.Wire, &wire) != nil ||
		wire.Version != 1 || wire.WorkspaceID != i.WorkspaceID || wire.RoleTag != scope.RoleTag || wire.Invite != i.Enrollment.Context ||
		wire.Database != i.Database || wire.ExpiresAt != i.ExpiresAt || !bytes.Equal(wire.TLSBundle, i.TLSIdentity.Bundle) ||
		!bytes.Equal(wire.Organisation.Signing, i.TLSIdentity.Organisation) {
		return workspaceBootstrapWire{}, vault.ErrFormat
	}
	tls, err := i.AuthenticatedTLSBundle(wire.Organisation.Signing, wire.OrganisationSigning)
	if err != nil {
		return workspaceBootstrapWire{}, err
	}
	if _, _, err := decodeWorkspaceBootstrapRecovery(wire, tls.bundle.CAs); err != nil {
		return workspaceBootstrapWire{}, err
	}
	return wire, nil
}

func (c *WorkspaceBootstrapCheckpoint) Seal() ([]byte, error) {
	if !c.active() {
		return nil, vault.ErrAuthentication
	}
	record, err := json.Marshal(c.data)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, bootstrapFactorsEnd+len(record))
	defer vault.Wipe(plaintext)
	plaintext[0] = c.phase
	copy(plaintext[1:bootstrapCodeEnd], c.code)
	copy(plaintext[bootstrapCodeEnd:bootstrapFactorsEnd], c.recoveryKey)
	copy(plaintext[bootstrapFactorsEnd:], record)
	envelope, err := vault.Seal(c.key, c.scope.binding(c.slot.ID), plaintext)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(workspaceBootstrapCheckpointFile{1, c.slot, envelope})
	if err != nil || len(raw) > MaxWorkspaceBootstrapCheckpointBytes {
		return nil, vault.ErrFormat
	}
	return raw, nil
}

// OpenWorkspaceBootstrapCheckpoint authenticates the exact saved workspace and
// plan before returning any factor. Its KDF is fixed by format version 1.
func OpenWorkspaceBootstrapCheckpoint(ctx context.Context, scope WorkspaceBootstrapScope, raw, password, ask []byte) (*WorkspaceBootstrapCheckpoint, error) {
	if ctx == nil || !scope.valid() || !validWorkspaceBootstrapFactors(password, ask) || len(raw) == 0 || len(raw) > MaxWorkspaceBootstrapCheckpointBytes {
		return nil, ErrConfiguration
	}
	var file workspaceBootstrapCheckpointFile
	if json.Unmarshal(raw, &file) != nil || file.Version != 1 || file.Slot.Preset != vault.KDFV1 || file.Slot.WrappedKey.KeyVersion != 1 {
		return nil, vault.ErrFormat
	}
	canonical, err := json.Marshal(file)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, vault.ErrFormat
	}
	key, err := vault.OpenPasswordSlot(ctx, scope.WorkspaceID.String(), file.Slot, password, ask)
	if err != nil {
		return nil, err
	}
	c := &WorkspaceBootstrapCheckpoint{scope: scope, key: key, slot: file.Slot}
	if err := c.openPayload(file.Payload); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *WorkspaceBootstrapCheckpoint) openPayload(envelope vault.Envelope) error {
	plain, err := vault.Open(c.key, c.scope.binding(c.slot.ID), envelope)
	if err != nil {
		return err
	}
	defer vault.Wipe(plain)
	if len(plain) <= bootstrapFactorsEnd || plain[0] < bootstrapPrepared || plain[0] > bootstrapPublished {
		return vault.ErrFormat
	}
	if json.Unmarshal(plain[bootstrapFactorsEnd:], &c.data) != nil {
		return vault.ErrFormat
	}
	canonical, err := json.Marshal(c.data)
	if err != nil || !bytes.Equal(canonical, plain[bootstrapFactorsEnd:]) {
		return vault.ErrFormat
	}
	c.wire, err = validateWorkspaceBootstrapCheckpointData(c.scope, c.data)
	if err != nil {
		return err
	}
	c.phase = plain[0]
	c.code = bytes.Clone(plain[1:bootstrapCodeEnd])
	if c.phase < bootstrapRecoveryConfirmed {
		c.recoveryKey = bytes.Clone(plain[bootstrapCodeEnd:bootstrapFactorsEnd])
	} else if !bytes.Equal(plain[bootstrapCodeEnd:bootstrapFactorsEnd], make([]byte, 32)) {
		return vault.ErrFormat
	}
	return nil
}
