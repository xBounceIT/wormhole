package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountBoundaryRotationSignature = "wormhole_api_v1.rotate_account_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,integer,uuid,integer,bytea,jsonb)"
const accountBoundaryRotationAvailableSQL = "SELECT (pg_catalog.to_regprocedure('" + accountBoundaryRotationSignature + "') IS NOT NULL)::text"
const accountBoundaryRotationCall = ` FROM wormhole_api_v1.rotate_account_boundary(` + serverCAArguments +
	`,$10::uuid,$11::bigint,$12::uuid,$13::integer,$14::uuid,$15::integer,pg_catalog.decode($16,'hex'),$17::jsonb)`

type AccountBoundaryRotationRequest struct {
	AccountID  uuid.UUID
	Suspension uint64
	BoundaryID uuid.UUID
	Affected   permissions.Mask
	Root       vault.KeyRef
	Review     *[32]byte
}

func (r AccountBoundaryRotationRequest) Valid() bool {
	return r.AccountID != uuid.Nil && r.BoundaryID != uuid.Nil && r.Suspension > 0 &&
		r.Suspension <= math.MaxInt64 && r.Root.ID != uuid.Nil && r.Root.Version > 0 &&
		r.Root.Version < math.MaxInt32 && (r.Affected == permissions.View || r.Affected == permissions.Use)
}

func (r AccountBoundaryRotationRequest) arguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	return [][]byte{[]byte(r.AccountID.String()), strconv.AppendUint(nil, r.Suspension, 10),
		[]byte(r.BoundaryID.String()), strconv.AppendUint(nil, uint64(r.Affected), 10),
		[]byte(r.Root.ID.String()), strconv.AppendUint(nil, uint64(r.Root.Version), 10), review, publication}
}

type AccountBoundaryRotationReply struct {
	Status string `json:"status"`
	Review string `json:"review,omitempty"`
}

type AccountBoundaryRotationPreparation struct {
	request  AccountBoundaryRotationRequest
	rotation GroupBoundaryRotationPreparation
}

type accountBoundaryRotationSnapshot struct {
	AccountID  uuid.UUID        `json:"accountId"`
	Suspension string           `json:"suspension"`
	BoundaryID uuid.UUID        `json:"boundaryId"`
	Affected   permissions.Mask `json:"affected"`
	Root       vault.KeyRef     `json:"root"`
	Epoch      string           `json:"epoch"`
	ChangeSeq  string           `json:"changeSeq"`
	Boundary   string           `json:"boundary"`
	Recovery   vault.KeyRef     `json:"recovery"`
	Digest     string           `json:"graphDigest"`
}

func (s *Session) AccountBoundaryRotationSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, accountBoundaryRotationAvailableSQL)
}

func (s *Session) PrepareAccountBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request AccountBoundaryRotationRequest) (
	observed TrustState, reply AccountBoundaryRotationReply, plan *AccountBoundaryRotationPreparation, err error) {
	if ctx == nil || !request.Valid() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, boundaryRotationMaterialColumns+accountBoundaryRotationCall, request.arguments(nil),
		maxBoundaryRotationGraph+32768, 1, 15, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 15 {
				return ErrAdmissionResponse
			}
			row := rows[0]
			reply.Status = string(row[0])
			if reply.Status != "ready" {
				if (!boundaryRotationStatus(reply.Status, false) && reply.Status != "group-rotation-required") ||
					slices.ContainsFunc(row[1:], nonNullGrantColumn) {
					return ErrAdmissionResponse
				}
				return nil
			}
			input, boundary, review, e := decodeAccountBoundaryRotationSnapshot(request, row[1])
			if e != nil {
				return e
			}
			observed, e = observed.AdvanceBoundary(request.BoundaryID, boundary)
			if e != nil {
				return e
			}
			if boundary.OwnerUserID != uuid.Nil {
				policy, err := observed.Policy()
				if err != nil || !policy.OrgEscrow || (policy.Profile != vault.Default && policy.Profile != vault.Standard) {
					return vault.ErrPolicy
				}
			}
			if request.Review == nil {
				if slices.ContainsFunc(row[2:], nonNullGrantColumn) {
					return ErrAdmissionResponse
				}
				reply = AccountBoundaryRotationReply{Status: "review", Review: hex.EncodeToString(review[:])}
				return nil
			}
			prepared := &AccountBoundaryRotationPreparation{request: request, rotation: GroupBoundaryRotationPreparation{
				boundary: boundary, excludedUser: request.AccountID,
			}}
			if e := prepared.rotation.readCustody(pin, input.Recovery, row[3:]); e != nil {
				return e
			}
			observed, e = prepared.rotation.verifyGraph(ctx, observed, pin, boundaryRotationGraphScope{
				Epoch: input.Epoch, ChangeSeq: input.ChangeSeq, Digest: input.Digest, Affected: input.Affected,
			}, row[2])
			if e != nil {
				return e
			}
			prepared.rotation.trust = cloneTrustState(observed)
			plan = prepared
			return nil
		})
	return
}

func decodeAccountBoundaryRotationSnapshot(request AccountBoundaryRotationRequest, raw []byte) (accountBoundaryRotationSnapshot, vault.BoundaryManifest, [32]byte, error) {
	var input accountBoundaryRotationSnapshot
	var boundary vault.BoundaryManifest
	var review [32]byte
	if len(raw) > 32768 {
		return input, boundary, review, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, input); err != nil || json.Unmarshal(raw, &input) != nil ||
		input.AccountID != request.AccountID || input.BoundaryID != request.BoundaryID || input.Affected != request.Affected ||
		input.Suspension != strconv.FormatUint(request.Suspension, 10) || input.Root != request.Root ||
		input.Recovery.ID == uuid.Nil || input.Recovery.Version == 0 || input.Recovery.Version > math.MaxInt32 {
		return input, boundary, review, ErrAdmissionResponse
	}
	_, epochOK := treeNumber([]byte(input.Epoch), 1, math.MaxInt64)
	_, seqOK := treeNumber([]byte(input.ChangeSeq), 0, math.MaxInt64)
	hash, err := hex.DecodeString(input.Digest)
	if !epochOK || !seqOK || err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != input.Digest {
		return input, boundary, review, ErrAdmissionResponse
	}
	signed, hexErr := hex.DecodeString(input.Boundary)
	boundary, err = vault.DecodeBoundaryManifest(signed)
	if hexErr != nil || err != nil || boundary.BoundaryID != request.BoundaryID ||
		(boundary.OwnerUserID != uuid.Nil && (boundary.OwnerUserID != request.AccountID ||
			boundary.BoundaryID != personalImportBoundaryID(boundary.WorkspaceID, request.AccountID))) ||
		!boundary.Active || !boundary.OrgEscrow || boundary.PreviousView != nil || boundary.PreviousSecret != nil ||
		(input.Affected == permissions.View && boundary.View.Key != input.Root) ||
		(input.Affected == permissions.Use && boundary.Secret.Key != input.Root) {
		return input, boundary, review, ErrAdmissionResponse
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/account-boundary-review:"))
	h.Write(raw)
	copy(review[:], h.Sum(nil))
	if request.Review != nil && *request.Review != review {
		return input, boundary, review, vault.ErrAuthentication
	}
	return input, boundary, review, nil
}

func (s *Session) CommitPreparedAccountBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *AccountBoundaryRotationPreparation, keys *vault.UserKeys) (TrustState, AccountBoundaryRotationReply, error) {
	if plan == nil || plan.request.Review == nil {
		return trust, AccountBoundaryRotationReply{}, ErrConfiguration
	}
	next, reply, err := s.commitBoundaryRotation(ctx, trust, tls, &plan.rotation, keys, accountBoundaryRotationCall, plan.request.arguments)
	return next, AccountBoundaryRotationReply{Status: reply.Status}, err
}
