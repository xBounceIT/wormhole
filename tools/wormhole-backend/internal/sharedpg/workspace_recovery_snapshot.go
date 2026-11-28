package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxRecoverySnapshotRecords = 100000
const maxRecoverySnapshotBytes = 42 * 1024 * 1024

const firstRecoveryArchiveSchema = 49
const lastRecoveryArchiveSchema = 102

func supportsRecoveryArchiveSchema(version int) bool {
	return version >= firstRecoveryArchiveSchema && version <= lastRecoveryArchiveSchema
}

const workspaceRecoverySnapshotSQL = `SELECT relation,body FROM wormhole_api_v1.export_workspace(` + serverCAArguments + `)`

// These are relation names in the schema-49 export format. Authentication and
// session state remain with the original cluster.
var recoverySnapshotRelations = map[string]struct{}{
	"workspace_meta":                 {},
	"users":                          {},
	"groups":                         {},
	"group_members":                  {},
	"group_member_rotation_jobs":     {},
	"group_boundary_rotation_queue":  {},
	"account_suspensions":            {},
	"account_suspension_enrollments": {},
	"account_suspension_roots":       {},
	"account_suspension_passwords":   {},
	"account_suspension_web_reports": {},
	"account_suspension_web_targets": {},
	"boundaries":                     {},
	"boundary_manifests":             {},
	"boundary_grants":                {},
	"keys":                           {},
	"key_copies":                     {},
	"user_key_states":                {},
	"user_key_wraps":                 {},
	"user_enrollments":               {},
	"user_enrollment_history":        {},
	"nodes":                          {},
	"grants":                         {},
	"credential_profiles":            {},
	"credential_slots":               {},
	"credential_slot_values":         {},
	"user_node_overrides":            {},
	"tunnel_profiles":                {},
	"node_secret_manifests":          {},
	"node_import_data":               {},
	"secret_values":                  {},
	"workspace_bootstrap":            {},
	"workspace_server_ca":            {},
}

type WorkspaceRecoveryRecord struct {
	Relation string          `json:"relation"`
	Body     json.RawMessage `json:"body"`
}

// WorkspaceRecoverySnapshot holds a bounded logical projection for sealing
// inside the native backup envelope. Never use it as a renderer response or
// accept its row contents as verified signatures on restore.
type WorkspaceRecoverySnapshot struct {
	FormatVersion uint16                    `json:"formatVersion"`
	WorkspaceID   uuid.UUID                 `json:"workspaceId"`
	Records       []WorkspaceRecoveryRecord `json:"records"`
}

func (s *WorkspaceRecoverySnapshot) Close() {
	if s == nil {
		return
	}
	for _, record := range s.Records {
		vault.Wipe(record.Body)
	}
	s.Records = nil
}

type workspaceRecoverySnapshotIdentity struct {
	WorkspaceID   uuid.UUID `json:"workspace_id"`
	RoleTag       string    `json:"role_tag"`
	SchemaVersion int       `json:"schema_version"`
	State         string    `json:"state"`
	RequireTLS    bool      `json:"require_tls"`
	TLSSequence   uint64    `json:"tls_sequence"`
	TLSBundle     string    `json:"tls_bundle"`
	SignedProfile string    `json:"signed_profile"`
}

// ReadWorkspaceRecoverySnapshot verifies the current custodian's signing
// copy against the independently pinned organisation signing identity. The
// SQL endpoint audits the release before this snapshot can reach a file owner.
func (s *Session) ReadWorkspaceRecoverySnapshot(ctx context.Context, trust TrustState, current *VerifiedTLSBundle, userPrivate, userSigningSeed []byte) (*WorkspaceRecoverySnapshot, error) {
	if ctx == nil || len(userPrivate) != 32 || len(userSigningSeed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	account, err := authenticatedServerCAContext(trust, current)
	if err != nil {
		return nil, err
	}
	profile, err := trust.Policy()
	if err != nil || !profile.OrgEscrow {
		return nil, ErrServerCertificateAuthority
	}
	var snapshot *WorkspaceRecoverySnapshot
	err = s.queryServerCA(ctx, trust, workspaceRecoverySnapshotSQL, nil,
		maxRecoverySnapshotBytes+4096, maxRecoverySnapshotRecords+1, 2, func(rows [][][]byte) error {
			if len(rows) < 3 || len(rows[0]) != 2 || string(rows[0][0]) != "custody" || len(rows[0][1]) > 1024 {
				return ErrAdmissionResponse
			}
			var proof workspaceAdminRecoveryCopy
			if json.Unmarshal(rows[0][1], &proof) != nil || proof.KeyRef != account.Signer ||
				len(proof.Enc) != 32 || len(proof.Ciphertext) != 48 || len(proof.Signature) != ed25519.SignatureSize {
				return vault.ErrAuthentication
			}
			copy := vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: vault.FormatVersion,
				SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: proof.Enc, Ciphertext: proof.Ciphertext}, Signature: proof.Signature}
			seed, err := openServerCAOrgCopy(trust, proof.KeyRef, copy, userPrivate, userSigningSeed)
			if err != nil {
				return err
			}
			defer vault.Wipe(seed)
			if len(seed) != ed25519.SeedSize {
				return vault.ErrAuthentication
			}
			key := ed25519.NewKeyFromSeed(seed)
			defer vault.Wipe(key)
			if !bytes.Equal(key.Public().(ed25519.PublicKey), account.Organisation) {
				return vault.ErrAuthentication
			}
			snapshot, err = parseWorkspaceRecoverySnapshot(rows[1:], trust, current)
			return err
		})
	return snapshot, err
}

func parseWorkspaceRecoverySnapshot(rows [][][]byte, trust TrustState, current *VerifiedTLSBundle) (*WorkspaceRecoverySnapshot, error) {
	if len(rows) < 2 || len(rows) > maxRecoverySnapshotRecords {
		return nil, ErrAdmissionResponse
	}
	records := make([]WorkspaceRecoveryRecord, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 || len(row[0]) > 32 {
			return nil, ErrAdmissionResponse
		}
		records = append(records, WorkspaceRecoveryRecord{Relation: string(row[0]), Body: row[1]})
	}
	_, err := checkRecoverySnapshotRecords(records, func(raw []byte) error {
		if !validRecoverySnapshotIdentity(raw, trust, current) {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Own raw rows only after the entire projection passes. queryServerCA wipes
	// the original response buffers as it releases the connection.
	for index := range records {
		records[index].Body = bytes.Clone(records[index].Body)
	}
	return &WorkspaceRecoverySnapshot{FormatVersion: 1, WorkspaceID: trust.WorkspaceID, Records: records}, nil
}

func checkRecoverySnapshotRecords(records []WorkspaceRecoveryRecord, checkIdentity func([]byte) error) (map[string]int, error) {
	if len(records) < 2 || len(records) > maxRecoverySnapshotRecords {
		return nil, ErrAdmissionResponse
	}
	counts := make(map[string]int, len(recoverySnapshotRelations))
	size := 0
	for _, row := range records {
		if _, known := recoverySnapshotRelations[row.Relation]; !known ||
			len(row.Body) < 2 || row.Body[0] != '{' || !json.Valid(row.Body) {
			return nil, ErrAdmissionResponse
		}
		size += len(row.Relation) + len(row.Body)
		if size > maxRecoverySnapshotBytes {
			return nil, ErrResultLimit
		}
		counts[row.Relation]++
		if row.Relation == "workspace_meta" {
			if err := checkIdentity(row.Body); err != nil {
				return nil, err
			}
		}
	}
	if counts["workspace_meta"] != 1 || counts["workspace_bootstrap"] != 1 || counts["workspace_server_ca"] > 1 {
		return nil, ErrAdmissionResponse
	}
	for _, required := range []string{"users", "user_enrollments", "user_key_states", "user_key_wraps", "keys", "key_copies", "boundaries", "boundary_manifests"} {
		if counts[required] == 0 {
			return nil, ErrAdmissionResponse
		}
	}
	return counts, nil
}

func validRecoverySnapshotIdentity(raw []byte, trust TrustState, current *VerifiedTLSBundle) bool {
	var meta workspaceRecoverySnapshotIdentity
	if json.Unmarshal(raw, &meta) != nil || meta.WorkspaceID != trust.WorkspaceID ||
		deploy.ValidateIdentity(meta.RoleTag, meta.WorkspaceID.String()) != nil ||
		!supportsRecoveryArchiveSchema(meta.SchemaVersion) || meta.State != "ready" || !meta.RequireTLS || meta.TLSSequence != trust.TLSSequence {
		return false
	}
	tls, ok := decodeRecoverySnapshotBytea(meta.TLSBundle)
	if !ok || !bytes.Equal(tls, current.Encode()) {
		return false
	}
	policy, ok := decodeRecoverySnapshotBytea(meta.SignedProfile)
	digest := sha256.Sum256(policy)
	return ok && bytes.Equal(digest[:], trust.PolicyDigest)
}

func decodeRecoverySnapshotBytea(encoded string) ([]byte, bool) {
	if len(encoded) < 2 || encoded[:2] != "\\x" {
		return nil, false
	}
	decoded, err := hex.DecodeString(encoded[2:])
	return decoded, err == nil
}
