package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// WorkspaceRecoverySummary contains only the display and deployment fields
// needed to prepare a new cluster before the archive is applied.
type WorkspaceRecoverySummary struct {
	WorkspaceID uuid.UUID     `json:"workspaceId"`
	RoleTag     string        `json:"roleTag"`
	Schema      int           `json:"sourceSchemaVersion"`
	Profile     vault.Profile `json:"profile"`
	Accounts    int           `json:"accounts"`
	Nodes       int           `json:"nodes"`
}

type archivedWorkspaceIdentity struct {
	workspaceRecoverySnapshotIdentity
	Singleton       bool   `json:"singleton"`
	MinAPI          uint32 `json:"min_api"`
	MaxAPI          uint32 `json:"max_api"`
	ResolverVersion uint32 `json:"resolver_version"`
}

// InspectWorkspaceRecoverySnapshot accepts plaintext from the independently
// authenticated backup envelope. It verifies the workspace policy and TLS
// bundle against the archive's organisation signing key. The returned summary
// does not confer admission or authenticate individual graph records.
func InspectWorkspaceRecoverySnapshot(plaintext []byte) (WorkspaceRecoverySummary, error) {
	summary, _, err := authenticateWorkspaceRecoverySnapshot(plaintext)
	return summary, err
}

func authenticateWorkspaceRecoverySnapshot(plaintext []byte) (WorkspaceRecoverySummary, *VerifiedTLSBundle, error) {
	var snapshot WorkspaceRecoverySnapshot
	defer snapshot.Close()
	if len(plaintext) == 0 || len(plaintext) > maxRecoverySnapshotBytes+maxRecoverySnapshotRecords*32+128 ||
		!utf8.Valid(plaintext) || json.Unmarshal(plaintext, &snapshot) != nil ||
		snapshot.FormatVersion != 1 || snapshot.WorkspaceID == uuid.Nil {
		return WorkspaceRecoverySummary{}, nil, ErrAdmissionResponse
	}
	// The encrypted v1 snapshot is exactly the Go export encoding. This rejects
	// duplicate or ambiguous wrappers before any metadata can reach deployment.
	canonical, err := json.Marshal(&snapshot)
	equal := err == nil && bytes.Equal(canonical, plaintext)
	vault.Wipe(canonical)
	if !equal {
		return WorkspaceRecoverySummary{}, nil, ErrAdmissionResponse
	}
	var meta archivedWorkspaceIdentity
	counts, err := checkRecoverySnapshotRecords(snapshot.Records, func(raw []byte) error {
		if !decodeRecoveryTrustRow(raw, &meta) || !meta.Singleton || meta.WorkspaceID != snapshot.WorkspaceID ||
			deploy.ValidateIdentity(meta.RoleTag, meta.WorkspaceID.String()) != nil ||
			!supportsRecoveryArchiveSchema(meta.SchemaVersion) || meta.State != "ready" || !meta.RequireTLS ||
			meta.TLSSequence == 0 || meta.TLSSequence > math.MaxInt64 ||
			meta.MinAPI != 1 || meta.MaxAPI < meta.MinAPI || meta.ResolverVersion != 1 {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return WorkspaceRecoverySummary{}, nil, err
	}
	profile, tls, err := verifyRecoveryArchiveTrust(snapshot.Records, meta)
	if err != nil {
		return WorkspaceRecoverySummary{}, nil, err
	}
	return WorkspaceRecoverySummary{WorkspaceID: meta.WorkspaceID, RoleTag: meta.RoleTag, Schema: meta.SchemaVersion,
		Profile: profile, Accounts: counts["users"], Nodes: counts["nodes"]}, tls, nil
}

// PostgreSQL composite decoding matches case-sensitive column names. Prevent
// Go's case-insensitive struct decoder from authenticating different fields.
func decodeRecoveryTrustRow(raw []byte, target any) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for field := range fields {
		for _, c := range field {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
	}
	return json.Unmarshal(raw, target) == nil
}

func verifyRecoveryArchiveTrust(records []WorkspaceRecoveryRecord, meta archivedWorkspaceIdentity) (vault.Profile, *VerifiedTLSBundle, error) {
	signer, publicKey, err := recoveryArchiveSigner(records)
	if err != nil {
		return "", nil, err
	}
	policyWire, ok := decodeRecoverySnapshotBytea(meta.SignedProfile)
	if !ok {
		return "", nil, ErrProfileAuthentication
	}
	policy, err := verifySignedWorkspacePolicy(policyWire, PolicyTrust{WorkspaceID: meta.WorkspaceID,
		SignerKeyID: signer.ID.String(), SignerKeyVersion: signer.Version, PublicKey: publicKey, MinimumSequence: 1})
	if err != nil || policy.MinAPI != meta.MinAPI || policy.MaxAPI != meta.MaxAPI || !policy.OrgEscrow ||
		(policy.Profile != vault.Default && policy.Profile != vault.Standard) {
		return "", nil, ErrProfileAuthentication
	}
	tlsWire, ok := decodeRecoverySnapshotBytea(meta.TLSBundle)
	if !ok {
		return "", nil, vault.ErrAuthentication
	}
	bundle, err := DecodeTLSTrustBundle(tlsWire)
	if err != nil || bundle.Sequence != meta.TLSSequence {
		return "", nil, vault.ErrAuthentication
	}
	tls, err := VerifyTLSTrustBundle(bundle, TLSTrustPin{WorkspaceID: meta.WorkspaceID, Signer: signer,
		Organisation: publicKey, MinimumSequence: meta.TLSSequence})
	if err != nil {
		return "", nil, vault.ErrAuthentication
	}
	return policy.Profile, tls, nil
}

func recoveryArchiveSigner(records []WorkspaceRecoveryRecord) (vault.KeyRef, ed25519.PublicKey, error) {
	var signer vault.KeyRef
	var publicKey ed25519.PublicKey
	for _, record := range records {
		if record.Relation != "keys" {
			continue
		}
		var key struct {
			ID        uuid.UUID  `json:"key_id"`
			Version   uint32     `json:"key_version"`
			Kind      string     `json:"kind"`
			Status    string     `json:"status"`
			Owner     *uuid.UUID `json:"owner_id"`
			Suite     int        `json:"suite"`
			PublicKey string     `json:"public_key"`
		}
		if !decodeRecoveryTrustRow(record.Body, &key) {
			return vault.KeyRef{}, nil, ErrAdmissionResponse
		}
		if key.Kind != "org-sign" || key.Status != "active" {
			continue
		}
		raw, ok := decodeRecoverySnapshotBytea(key.PublicKey)
		if signer.ID != uuid.Nil || key.ID == uuid.Nil || key.Version == 0 || key.Version > math.MaxInt32 ||
			key.Owner != nil || key.Suite != 1 || !ok || len(raw) != ed25519.PublicKeySize {
			return vault.KeyRef{}, nil, vault.ErrAuthentication
		}
		signer, publicKey = vault.KeyRef{ID: key.ID, Version: key.Version}, ed25519.PublicKey(raw)
	}
	if signer.ID == uuid.Nil {
		return vault.KeyRef{}, nil, vault.ErrAuthentication
	}
	return signer, publicKey, nil
}
