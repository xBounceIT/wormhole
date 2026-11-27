package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxConnectionPlanBytes = 18 * 1024 * 1024

type connectionPlanWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Profile       string          `json:"profile"`
	Account       json.RawMessage `json:"account"`
	Metadata      json.RawMessage `json:"metadata"`
}

// UnverifiedConnectionPlan contains public verification material only. It has no
// ciphertext/key copies and cannot be opened as a credential release.
type UnverifiedConnectionPlan struct {
	metadata        *UnverifiedConnectionSnapshot
	profile         []byte
	account         vault.UserKeyState
	epoch, sequence uint64
}

// ResolvedTunnel contains authenticated public data only. It is not a release
// capability and must not be used before the plan's trust observations commit.
type ResolvedTunnel struct {
	Metadata             vaultstore.TunnelMetadata
	Boundary             uuid.UUID
	RowVersion           uint64
	ConfigurationVersion uint64
}

// ResolvedConnectionPlan is authenticated public metadata. Revision binds the
// complete resolution inputs for a pending host confirmation, not just the leaf.
// The owner must durably publish observations before returning this value.
type ResolvedConnectionPlan struct {
	Plan                     resolver.Plan
	Revision                 string
	Tunnel                   *ResolvedTunnel
	Path                     string
	ConfiguredExternalClient bool
	SerialSettings           vault.SerialSettings
	// The signed leaf and database snapshot used by compare-and-set pin changes.
	leaf            *UnverifiedTreeNode
	epoch, sequence uint64
	// Retain the full public snapshot for SSH/SFTP so readback can rebuild
	// the original connection revision with its previously signed leaf.
	pinContext *UnverifiedConnectionPlan
}

// Replacing just the edited leaf reconstructs the revision a pending SSH
// confirmation saw, while keeping all other inputs from the current snapshot.
func (p *UnverifiedConnectionPlan) revision(originalLeaf *UnverifiedChainRecord) (string, error) {
	records := p.metadata.records
	if originalLeaf != nil {
		records.Chain = slices.Clone(records.Chain)
		records.Chain[0] = *originalLeaf
	}
	raw, err := json.Marshal(struct {
		Records   CatalogConnectionRecords
		Manifests []vault.BoundaryManifest
		Account   vault.UserKeyState
		Policy    []byte
	}{records, p.metadata.manifests, p.account, p.profile})
	if err != nil {
		return "", ErrTrustState
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func parseConnectionMaterial(profile string, account, metadata []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedConnectionPlan, error) {
	material, e := parseRuntimeMaterial(profile, account, request)
	if e != nil {
		return nil, e
	}
	snapshot, e := parseConnectionSnapshot(metadata, request, node, epoch, sequence)
	if e != nil {
		return nil, e
	}
	return &UnverifiedConnectionPlan{metadata: snapshot, profile: material.profile, account: material.account, epoch: epoch, sequence: sequence}, nil
}

// DecodeConnectionPlan is the bound native codec, not authentication or Use
// authority. VerifyConnectionPlan and durable publication must precede planning.
func DecodeConnectionPlan(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedConnectionPlan, error) {
	if len(raw) == 0 || len(raw) > MaxConnectionPlanBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	var wire connectionPlanWire
	if _, e := strictCatalogObject(raw, wire); e != nil {
		return nil, e
	}
	if json.Unmarshal(raw, &wire) != nil {
		return nil, ErrAdmissionResponse
	}
	if wire.FormatVersion > 1 {
		return nil, vault.ErrNewerFormat
	}
	if wire.FormatVersion != 1 {
		return nil, ErrAdmissionResponse
	}
	return parseConnectionMaterial(wire.Profile, wire.Account, wire.Metadata, request, node, epoch, sequence)
}

// VerifyConnectionPlan never decrypts, consumes a ticket or creates a prepared
// release. Persist nonzero observations even on error, then publish the plan only
// after commit. The later release must independently re-resolve and authorize it.
func (s TrustState) VerifyConnectionPlan(ctx context.Context, node uuid.UUID, input *UnverifiedConnectionPlan) (TrustState, ResolvedConnectionPlan, error) {
	if input == nil {
		return TrustState{}, ResolvedConnectionPlan{}, ErrConfiguration
	}
	observed, plan, e := s.verifyConnectionMaterial(ctx, node, input.metadata, input.profile, input.account)
	if e != nil {
		return observed, ResolvedConnectionPlan{}, e
	}
	revision, e := input.revision(nil)
	if e != nil {
		return observed, ResolvedConnectionPlan{}, ErrTrustState
	}
	result := ResolvedConnectionPlan{Plan: plan, Revision: revision, Path: input.metadata.records.Path,
		leaf: &input.metadata.records.Chain[0].Node, epoch: input.epoch, sequence: input.sequence}
	if plan.Protocol == 0 || plan.Protocol == 7 {
		result.pinContext = input
	}
	if plan.Protocol == 1 {
		for _, record := range input.metadata.records.Chain {
			if setting := record.Node.Metadata.RDPUseExternalClient; setting != nil {
				result.ConfiguredExternalClient = *setting
				break
			}
		}
	} else if plan.Protocol == 5 {
		chain := make([]vaultstore.NodeMetadata, 0, len(input.metadata.records.Chain))
		for _, record := range input.metadata.records.Chain {
			chain = append(chain, record.Node.Metadata)
		}
		result.SerialSettings = resolver.ProjectSerialSettings(chain)
	}
	if input.metadata.records.Tunnel != nil {
		r := input.metadata.records.Tunnel.Selection
		tunnel := r.Record.(sharedcatalog.TunnelRecord)
		result.Tunnel = &ResolvedTunnel{Metadata: tunnel.Metadata, Boundary: r.Boundary, RowVersion: r.Seal.Revision, ConfigurationVersion: tunnel.ConfigurationVersion}
	}
	return observed, result, nil
}

func (s TrustState) verifyConnectionMaterial(ctx context.Context, node uuid.UUID, metadata *UnverifiedConnectionSnapshot, profile []byte, account vault.UserKeyState) (observed TrustState, plan resolver.Plan, err error) {
	if ctx == nil || metadata == nil || node == uuid.Nil {
		return TrustState{}, plan, ErrConfiguration
	}
	observed, e := s.verifyRuntimeMaterial(ctx, profile, account)
	if e != nil {
		return observed, plan, e
	}
	changed := observed.Revision != s.Revision
	observed.Revision = s.Revision
	defer func() {
		if changed {
			observed.Revision = s.Revision + 1
		}
		if err != nil {
			plan = resolver.Plan{}
		}
	}()
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
	}
	next, p, e := observed.VerifyConnectionSnapshot(ctx, node, metadata)
	absorb(next)
	if e != nil {
		return observed, plan, e
	}
	if observed.Account.Sequence != account.Sequence {
		return observed, plan, ErrTreeSnapshotChanged
	}
	return observed, p, nil
}

const connectionPlanSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.connection_plan(pg_catalog.decode($1,'hex'),$2::uuid)`

const connectionPlanPathSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.connection_plan_path(pg_catalog.decode($1,'hex'),$2::uuid,$3::text)`

const webConnectionPlanSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.web_connection_plan(pg_catalog.decode($1,'hex'),$2::uuid)`

const WebConnectionPlanPath = "web"

// DefaultPlanPath also covers metadata-only HTTP(S). Credential consumers
// continue to use DefaultAuditedPath for the set of supported account paths.
func DefaultPlanPath(protocol int) string {
	if protocol == 3 || protocol == 4 {
		return WebConnectionPlanPath
	}
	return DefaultAuditedPath(protocol)
}

func (s *Session) WebConnectionPlanSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.web_connection_plan(bytea,uuid)') IS NOT NULL)::text`)
}

// WebConnectionPlan retrieves only the metadata needed for browsing. It omits
// the imported Reveal account and still requires Use on the node and tunnel.
func (s *Session) WebConnectionPlan(ctx context.Context, node uuid.UUID) (*UnverifiedConnectionPlan, error) {
	return s.connectionPlan(ctx, node, WebConnectionPlanPath)
}

// ConnectionPlan retrieves only signed metadata/current public state, never key
// copies or secret values. It does not issue or spend a use ticket.
func (s *Session) ConnectionPlan(ctx context.Context, node uuid.UUID) (*UnverifiedConnectionPlan, error) {
	return s.connectionPlan(ctx, node, "")
}

// ConnectionPlanPath binds a preview to an explicit account selection path.
// A path-aware plan must not be consumed by an older default-path caller.
func (s *Session) ConnectionPlanPath(ctx context.Context, node uuid.UUID, path string) (*UnverifiedConnectionPlan, error) {
	if path != DefaultConnectionPath && !resolver.KnownAccountPath(path) {
		return nil, ErrConfiguration
	}
	return s.connectionPlan(ctx, node, path)
}

func (s *Session) connectionPlan(ctx context.Context, node uuid.UUID, path string) (result *UnverifiedConnectionPlan, err error) {
	if ctx == nil || node == uuid.Nil {
		return nil, ErrConfiguration
	}
	statement, extra := connectionPlanSQL, [][]byte(nil)
	if path == WebConnectionPlanPath {
		statement = webConnectionPlanSQL
	} else if path != "" {
		statement, extra = connectionPlanPathSQL, [][]byte{[]byte(path)}
	}
	err = s.queryConnection(ctx, node, statement, extra, MaxConnectionPlanBytes, 7, func(rows [][][]byte, r AdmissionRequest) error {
		if len(rows) != 1 || len(rows[0]) != 7 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		if string(row[0]) != r.WorkspaceID.String() || string(row[1]) != r.UserID.String() || string(row[2]) != r.DeviceID.String() || string(row[3]) != node.String() {
			return ErrAdmissionResponse
		}
		epoch, ok := treeNumber(row[4], 1, math.MaxInt64)
		seq, ok2 := treeNumber(row[5], 0, math.MaxInt64)
		if !ok || !ok2 {
			return ErrAdmissionResponse
		}
		var e error
		result, e = DecodeConnectionPlan(row[6], r, node, epoch, seq)
		if e == nil {
			actual := result.metadata.records.Path
			if path == DefaultConnectionPath {
				if actual == "" || actual != DefaultPlanPath(result.metadata.plan.Protocol) {
					return ErrAdmissionResponse
				}
			} else if actual != path {
				return ErrAdmissionResponse
			}
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
