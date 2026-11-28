package sharedcatalog

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type SlotRecord struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Protocol            string `json:"protocol"`
	DefaultCredentialID string `json:"defaultCredentialId"`
	AllowSelfService    bool   `json:"allowSelfService"`
	Deleted             bool   `json:"deleted"`
}

type SlotValueRecord struct {
	ID           string `json:"id"`
	SlotID       string `json:"slotId"`
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
	Deleted      bool   `json:"deleted"`
}

type OverrideRecord struct {
	UserID       string `json:"userId"`
	NodeID       string `json:"nodeId"`
	CredentialID string `json:"credentialId"`
	Deleted      bool   `json:"deleted"`
}

// SelectionRecord accepts only value forms of the signed record types.
// Pointers, nil and other implementations fail closed during validation.
type SelectionRecord interface{ selectionRecord() }

func (SlotRecord) selectionRecord()      {}
func (SlotValueRecord) selectionRecord() {}
func (OverrideRecord) selectionRecord()  {}

// SelectionScope binds the kind and logical identity, independent of row IDs.
// Slot values use (slot,user); overrides use (node,user). User is zero for slots, tunnel profiles and node field manifests.
type SelectionScope struct {
	Kind          string
	Subject, User uuid.UUID
}

type SelectionTrust struct {
	Workspace, Boundary, Author                                                uuid.UUID
	Scope                                                                      SelectionScope
	OrganisationKey                                                            vault.KeyRef
	Organisation                                                               ed25519.PublicKey
	MinimumStateSequence, MinimumCertificateRevision, MinimumSelectionRevision uint64
}

type SelectionObservation struct {
	StateSequence, CertificateRevision, SelectionRevision uint64
}

func selectionID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// SelectionIdentity validates content before exposing a floor namespace. A row
// replacement must not reset the history of a slot/user assignment.
func SelectionIdentity(record SelectionRecord) (SelectionScope, bool, error) {
	var kind, subject, user string
	var deleted bool
	switch r := record.(type) {
	case SlotRecord:
		if !selectionID(r.ID) || !utf8.ValidString(r.Name) || len(r.Name) > 1024 || strings.TrimSpace(r.Name) == "" || strings.ContainsRune(r.Name, 0) || (r.Protocol != "ssh" && r.Protocol != "rdp" && r.Protocol != "vnc") || (r.DefaultCredentialID != "" && !selectionID(r.DefaultCredentialID)) {
			return SelectionScope{}, false, vault.ErrFormat
		}
		kind, subject, deleted = "slot", r.ID, r.Deleted
	case SlotValueRecord:
		if !selectionID(r.ID) || !selectionID(r.SlotID) || !selectionID(r.UserID) || (!r.Deleted && r.CredentialID == "") || (r.CredentialID != "" && !selectionID(r.CredentialID)) {
			return SelectionScope{}, false, vault.ErrFormat
		}
		kind, subject, user, deleted = "slot-value", r.SlotID, r.UserID, r.Deleted
	case OverrideRecord:
		if !selectionID(r.NodeID) || !selectionID(r.UserID) || (!r.Deleted && r.CredentialID == "") || (r.CredentialID != "" && !selectionID(r.CredentialID)) {
			return SelectionScope{}, false, vault.ErrFormat
		}
		kind, subject, user, deleted = "override", r.NodeID, r.UserID, r.Deleted
	case TunnelRecord:
		if err := r.validate(); err != nil {
			return SelectionScope{}, false, err
		}
		kind, subject, deleted = "tunnel", r.Metadata.ID, r.Deleted
	case NodeFieldsRecord:
		if err := r.validate(); err != nil {
			return SelectionScope{}, false, err
		}
		kind, subject, deleted = "node-fields", r.NodeID, r.Deleted
	default:
		return SelectionScope{}, false, vault.ErrFormat
	}
	id, _ := uuid.Parse(subject)
	uid, _ := uuid.Parse(user)
	return SelectionScope{kind, id, uid}, deleted, nil
}

func selectionSigningBytes(workspace, boundary uuid.UUID, record SelectionRecord, seal vault.RecordSeal) ([]byte, error) {
	if err := validateRecordSeal(workspace, boundary, seal); err != nil {
		return nil, err
	}
	scope, _, err := SelectionIdentity(record)
	if err != nil {
		return nil, err
	}
	if tunnel, ok := record.(TunnelRecord); ok && tunnel.ConfigurationVersion > seal.Revision {
		return nil, vault.ErrFormat
	}
	seal.Signature = nil
	body, err := json.Marshal(struct {
		Workspace uuid.UUID        `json:"workspaceId"`
		Boundary  uuid.UUID        `json:"boundaryId"`
		Suite     uint16           `json:"suite"`
		Record    SelectionRecord  `json:"record"`
		Seal      vault.RecordSeal `json:"seal"`
	}{workspace, boundary, NodeSealEd25519, record, seal})
	if err != nil {
		return nil, vault.ErrFormat
	}
	return append([]byte("wormhole/v1/shared-"+scope.Kind+"\x00"), body...), nil
}

func SignSelection(workspace, boundary uuid.UUID, record SelectionRecord, revision uint64, signer vault.KeyRef, private ed25519.PrivateKey) (vault.RecordSeal, error) {
	if len(private) != ed25519.PrivateKeySize {
		return vault.RecordSeal{}, vault.ErrFormat
	}
	seal := vault.RecordSeal{FormatVersion: vault.FormatVersion, SignerKeyID: signer.ID.String(), SignerKeyVersion: signer.Version, Revision: revision}
	body, err := selectionSigningBytes(workspace, boundary, record, seal)
	if err != nil {
		return vault.RecordSeal{}, err
	}
	seal.Signature = ed25519.Sign(private, body)
	return seal, nil
}

// VerifyCurrentSelection authenticates membership and the entire record, not
// authorization. Persist authenticated observations even on later error, using
// both revisions and digests to reject same-revision forks. Tombstones are not
// usable selections, but advance their logical identity's revision floor.
func VerifyCurrentSelection(record SelectionRecord, boundary uuid.UUID, seal vault.RecordSeal, certificate vault.UserKeyCertificate, state vault.UserKeyState, trust SelectionTrust, enrollment ...vault.UserEnrollmentCertificate) (SelectionObservation, error) {
	author, err := verifyCurrentAuthor(certificate, state, vault.UserKeyTrust{WorkspaceID: trust.Workspace, UserID: trust.Author, Signer: trust.OrganisationKey, Organisation: trust.Organisation, MinimumSequence: trust.MinimumStateSequence}, trust.MinimumCertificateRevision, enrollment...)
	observed := SelectionObservation{StateSequence: author.StateSequence, CertificateRevision: author.CertificateRevision}
	if err != nil {
		return observed, err
	}
	scope, deleted, err := SelectionIdentity(record)
	if err != nil {
		return observed, err
	}
	if scope != trust.Scope || trust.Boundary == uuid.Nil || boundary != trust.Boundary || seal.SignerKeyID != author.Key.ID.String() || seal.SignerKeyVersion != author.Key.Version {
		return observed, vault.ErrAuthentication
	}
	body, err := selectionSigningBytes(trust.Workspace, boundary, record, seal)
	if err != nil {
		return observed, err
	}
	if !ed25519.Verify(author.Public, body, seal.Signature) {
		return observed, vault.ErrAuthentication
	}
	if seal.Revision < trust.MinimumSelectionRevision {
		return observed, vault.ErrRollback
	}
	observed.SelectionRevision = seal.Revision
	if deleted {
		return observed, vaultstore.ErrMissing
	}
	return observed, nil
}
