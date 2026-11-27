package sharedpg

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const beginFallbackUseSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,expires_at::text,primary_tunnel_id::text,fallback_tunnel_id::text
 FROM wormhole_api_v1.begin_fallback_use(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid,$4::uuid,$5)`

const fetchFallbackSecretSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,primary_tunnel_id::text,fallback_tunnel_id::text,payload::text
 FROM wormhole_api_v1.fetch_fallback_secret(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid,$4::uuid,$5::uuid)`

// A distinct audit intent, not a decryption capability or proof of the encrypted
// primary-to-target reference. Never retry either issuance or consumption.
type FallbackUseIntent struct {
	UseIntent
	PrimaryTunnel, FallbackTunnel uuid.UUID
}

func (s *Session) BeginFallbackUse(ctx context.Context, node, primary, fallback uuid.UUID, source string) (*FallbackUseIntent, error) {
	if ctx == nil || node == uuid.Nil || primary == uuid.Nil || fallback == uuid.Nil || primary == fallback || (source != "ui" && source != "mcp") {
		return nil, ErrConfiguration
	}
	var result *FallbackUseIntent
	err := s.beginUseOperation(ctx, beginFallbackUseSQL, [][]byte{nil, []byte(node.String()), []byte(primary.String()), []byte(fallback.String()), []byte(source)}, func(rows [][][]byte) error {
		var err error
		result, err = parseFallbackUseIntent(rows, s.admission, node, primary, fallback)
		return err
	})
	return result, err
}

func parseFallbackUseIntent(rows [][][]byte, request AdmissionRequest, node, primary, fallback uuid.UUID) (*FallbackUseIntent, error) {
	if len(rows) != 1 || len(rows[0]) != 10 || string(rows[0][8]) != primary.String() || string(rows[0][9]) != fallback.String() {
		return nil, ErrAdmissionResponse
	}
	intent, err := parseUseIntent([][][]byte{rows[0][:8]}, request, node)
	if err != nil {
		return nil, err
	}
	return &FallbackUseIntent{UseIntent: *intent, PrimaryTunnel: primary, FallbackTunnel: fallback}, nil
}

// Private ciphertext fields cannot be opened by transport callers. Decoding
// authenticates nothing. Native verification, durable trust publication and the
// encrypted source-reference check must precede any secondary private-key use.
type UnverifiedFallbackRelease struct {
	source   *UnverifiedCredentialRelease
	target   UnverifiedSelectionRecord
	manifest vault.BoundaryManifest
	values   []UnverifiedSharedValue
	copy     UnverifiedKeyCopy
	root     UnverifiedKeyCopy
}

// DecodeFallbackRelease is a structural native codec, not a Use or decryption
// capability. Verify both source chains and durably publish their observations
// before the owning operation may borrow any account key.
func DecodeFallbackRelease(raw []byte, request AdmissionRequest, intent FallbackUseIntent) (*UnverifiedFallbackRelease, error) {
	return parseFallbackRelease(raw, request, intent)
}

func (s *Session) FetchFallbackSecret(ctx context.Context, intent FallbackUseIntent) (*UnverifiedFallbackRelease, error) {
	if ctx == nil || intent.Path != "" || intent.Node == uuid.Nil || intent.Ticket == uuid.Nil || intent.PrimaryTunnel == uuid.Nil || intent.FallbackTunnel == uuid.Nil || intent.PrimaryTunnel == intent.FallbackTunnel || intent.Epoch == 0 || intent.Epoch > math.MaxInt64 || intent.ChangeSeq > math.MaxInt64 || intent.ExpiresAt <= 0 {
		return nil, ErrConfiguration
	}
	var result *UnverifiedFallbackRelease
	err := s.queryConnection(ctx, intent.Node, fetchFallbackSecretSQL, [][]byte{[]byte(intent.Ticket.String()), []byte(intent.PrimaryTunnel.String()), []byte(intent.FallbackTunnel.String())}, MaxCredentialReleaseBytes, 10, func(rows [][][]byte, request AdmissionRequest) error {
		var err error
		result, err = parseFallbackSecret(rows, request, intent)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseFallbackSecret(rows [][][]byte, request AdmissionRequest, intent FallbackUseIntent) (*UnverifiedFallbackRelease, error) {
	if len(rows) != 1 || len(rows[0]) != 10 {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != request.UserID.String() || string(r[2]) != request.DeviceID.String() || string(r[3]) != intent.Node.String() || string(r[4]) != intent.Ticket.String() || string(r[5]) != strconv.FormatUint(intent.Epoch, 10) || string(r[6]) != strconv.FormatUint(intent.ChangeSeq, 10) || string(r[7]) != intent.PrimaryTunnel.String() || string(r[8]) != intent.FallbackTunnel.String() {
		return nil, ErrAdmissionResponse
	}
	return parseFallbackRelease(r[9], request, intent)
}

type fallbackReleaseWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Source        json.RawMessage `json:"source"`
	Target        json.RawMessage `json:"target"`
	Boundary      json.RawMessage `json:"boundary"`
	Values        json.RawMessage `json:"values"`
	Copies        json.RawMessage `json:"copies"`
	Roots         json.RawMessage `json:"roots"`
}

func parseFallbackRelease(raw []byte, request AdmissionRequest, intent FallbackUseIntent) (*UnverifiedFallbackRelease, error) {
	if intent.Path != "" || len(raw) == 0 || len(raw) > MaxCredentialReleaseBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	var w fallbackReleaseWire
	if _, err := strictCatalogObject(raw, w); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &w) != nil || w.FormatVersion != 1 {
		return nil, ErrAdmissionResponse
	}
	source, err := parseCredentialRelease(w.Source, request, intent.Node, intent.Epoch, intent.ChangeSeq)
	if err != nil {
		return nil, err
	}
	if source.metadata.format == 4 {
		imported := source.metadata.records.Chain[0].Node.Metadata.Imported
		if imported == nil || !imported.RetainedPins || source.metadata.records.Path != DefaultPlanPath(source.metadata.plan.Protocol) {
			return nil, ErrAdmissionResponse
		}
	} else if source.metadata.format != 3 {
		return nil, ErrAdmissionResponse
	}
	if source.metadata.plan.TunnelID != intent.PrimaryTunnel.String() || source.metadata.records.Tunnel == nil {
		return nil, ErrAdmissionResponse
	}
	row, err := snapshotOptionalRow(w.Target, 24)
	if err != nil || row == nil {
		return nil, ErrAdmissionResponse
	}
	target, author, err := parseSelectionProjection([][][]byte{row}, request, sharedcatalog.SelectionScope{Kind: "tunnel", Subject: intent.FallbackTunnel}, intent.Epoch, intent.ChangeSeq)
	if err != nil {
		return nil, err
	}
	record := target.Record.(sharedcatalog.TunnelRecord)
	if intent.PrimaryTunnel == intent.FallbackTunnel {
		return nil, ErrAdmissionResponse
	}
	row, err = snapshotOptionalRow(w.Boundary, 9)
	if err != nil || row == nil {
		return nil, ErrAdmissionResponse
	}
	manifest, err := parseBoundaryProjection([][][]byte{row}, request, target.Boundary, intent.Epoch, intent.ChangeSeq)
	if err != nil {
		return nil, err
	}
	for _, original := range source.metadata.manifests {
		if original.BoundaryID == manifest.BoundaryID && !reflect.DeepEqual(original, *manifest) {
			return nil, ErrAdmissionResponse
		}
	}
	if record.Deleted {
		// A tombstone is authenticated public material, not an invitation to open
		// stale keys. Preserve it for the verifier; no target ciphertext is used.
		return &UnverifiedFallbackRelease{source: source, target: UnverifiedSelectionRecord{Selection: *target, Author: *author}, manifest: *manifest}, nil
	}
	rows, err := snapshotRows(w.Values, 1, 9)
	if err != nil {
		return nil, err
	}
	values, err := parseManifestValues(rows, request, "tunnel", intent.FallbackTunnel, []vaultstore.CredentialField{{Field: "settings", Version: record.ConfigurationVersion, Present: true}}, intent.Epoch, intent.ChangeSeq)
	if err != nil || len(values) != 1 {
		return nil, ErrAdmissionResponse
	}
	for _, account := range source.accounts {
		for _, value := range account.values {
			if value.Binding.DEK == values[0].Binding.DEK {
				return nil, ErrAdmissionResponse
			}
		}
	}
	row, err = snapshotSingleFallbackCopy(w.Copies)
	if err != nil {
		return nil, err
	}
	holder, err := releaseKeyRef(row, 5)
	if err != nil || holder != manifest.Secret.Key && (manifest.PreviousSecret == nil || holder != manifest.PreviousSecret.Key) {
		return nil, ErrAdmissionResponse
	}
	copy, err := parseKeyCopyProjection([][][]byte{row}, request, values[0].Binding.DEK, holder, intent.Epoch, intent.ChangeSeq)
	if err != nil {
		return nil, err
	}
	recipient := source.account.Encryption
	if source.enrollment != nil {
		recipient = vault.KeyRef{ID: source.enrollment.Rekey.EncryptionKeyID, Version: source.enrollment.Rekey.KeyVersion}
	}
	roots, err := parseBoundaryRootCopies(w.Roots, request, []vault.KeyRef{holder}, recipient, intent.Epoch, intent.ChangeSeq, 24)
	if err != nil {
		return nil, err
	}
	return &UnverifiedFallbackRelease{source: source, target: UnverifiedSelectionRecord{Selection: *target, Author: *author}, manifest: *manifest, values: values, copy: *copy, root: roots[0]}, nil
}

func snapshotSingleFallbackCopy(raw []byte) ([][]byte, error) {
	rows, err := snapshotRows(raw, 1, 24)
	if err != nil || len(rows) != 1 {
		return nil, ErrAdmissionResponse
	}
	return rows[0], nil
}
