package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedNodeEditSession interface {
	sharedRuntimeStateSession
	NodeEditingSupported(context.Context) (bool, error)
	ReadNodeEdit(context.Context, sharedpg.TrustState, uuid.UUID, uint64) (sharedpg.TrustState, *sharedpg.NodeEdit, error)
	CommitNodeEdit(context.Context, sharedpg.TrustState, *sharedpg.NodeEdit, vaultstore.NodeMetadata, *vault.UserKeys) (uint64, error)
}

type sharedNodeMoveSession interface {
	NodeMovingSupported(context.Context) (bool, error)
	CommitNodeMove(context.Context, sharedpg.TrustState, *sharedpg.NodeEdit, *uuid.UUID, *vault.UserKeys) (*sharedpg.NodeMoveReceipt, error)
}

type sharedMoveDestination struct {
	id       *uuid.UUID
	revision uint64
}

// A null parent means the workspace root. A folder selection must include the
// signed revision the caller saw. A move cannot include scalar edits.
func decodeSharedMove(patch []byte) (*sharedMoveDestination, error) {
	var parent json.RawMessage
	if decodeVaultNullableObject(patch, map[string]any{"parent": &parent}, map[string]bool{"parent": true}, "parent") != nil {
		return nil, nil
	}
	if bytes.Equal(parent, []byte("null")) {
		return &sharedMoveDestination{}, nil
	}
	var id, rev string
	if decodeVaultObject(parent, map[string]any{"id": &id, "revision": &rev}, "id", "revision") != nil || !vaultCredentialID(id) {
		return nil, vaultwire.ErrProtocol
	}
	version, err := vaultCredentialRevision(rev, false)
	if err != nil {
		return nil, err
	}
	folder := uuid.MustParse(id)
	return &sharedMoveDestination{&folder, version}, nil
}

// Only public editable fields cross this boundary. Go retains structural IDs,
// import proofs, host pins, field manifests and every unedited setting.
func sharedNodeEditFields(n *vaultstore.NodeMetadata) map[string]any {
	return map[string]any{
		"name": &n.Name, "protocol": &n.Protocol, "host": &n.Host, "port": &n.Port, "username": &n.Username,
		"credentialMode": &n.CredentialMode, "credentialId": &n.CredentialID, "credentialSlotId": &n.CredentialSlotID,
		"tunnelEnabled": &n.TunnelEnabled, "tunnelConfigId": &n.TunnelConfigID,
		"httpPath": &n.HTTPPath, "httpIgnoreCertErrors": &n.HTTPIgnoreCertErrors, "rdpDomain": &n.RDPDomain,
		"rdpGatewayUsageMethod": &n.RDPGatewayUsageMethod, "rdpGatewayHostname": &n.RDPGatewayHostname,
		"rdpGatewayCredentialId": &n.RDPGatewayCredentialID, "rdpGatewayUseSameCreds": &n.RDPGatewayUseSameCreds, "rdpGatewayBypassLocal": &n.RDPGatewayBypassLocal,
	}
}

type sharedNodeEditReply struct {
	Status    string         `json:"status"`
	NodeID    string         `json:"nodeId,omitempty"`
	Revision  string         `json:"revision,omitempty"`
	Workspace string         `json:"workspaceId,omitempty"`
	Epoch     string         `json:"epoch,omitempty"`
	Sequence  string         `json:"changeSeq,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	CanMove   bool           `json:"canMove,omitempty"`
}

func (h *vaultFoundationHandler) sharedNodeEdit(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var action, encoded json.RawMessage
	defer func() { vault.Wipe(raw); vault.Wipe(encoded) }()
	if len(raw) > 512*1024 || decodeVaultObject(raw, map[string]any{"action": &action, "authentication": &encoded}, "action") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var id, version string
	var workspace, epoch, sequence *string
	var patch json.RawMessage
	if decodeVaultObject(action, map[string]any{"nodeId": &id, "revision": &version, "changes": &patch, "workspaceId": &workspace, "epoch": &epoch, "changeSeq": &sequence}, "nodeId", "revision") != nil || !vaultCredentialID(id) ||
		(patch == nil && (encoded != nil || workspace != nil || epoch != nil || sequence != nil)) ||
		(patch != nil && (workspace == nil || !vaultCredentialID(*workspace) || epoch == nil || sequence == nil)) {
		return nil, vaultwire.ErrProtocol
	}
	rev, err := vaultCredentialRevision(version, false)
	if err != nil || (patch != nil && rev == math.MaxInt64) {
		return nil, vaultwire.ErrProtocol
	}
	if patch != nil {
		if _, err := vaultCredentialRevision(*epoch, false); err != nil {
			return nil, err
		}
		if _, err := vaultCredentialRevision(*sequence, true); err != nil {
			return nil, err
		}
	}
	var auth vaultUnlockInput
	if encoded != nil {
		auth, err = decodeSharedExportAuthentication(encoded)
		defer auth.wipe()
		if err != nil {
			return nil, err
		}
	}
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedNodeEditSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := sharedNodeEditReply{Status: "unavailable"}
	node := uuid.MustParse(id)
	var edit *sharedpg.NodeEdit
	var desired vaultstore.NodeMetadata
	var committed uint64
	var fresh bool
	var inputErr error
	var destination *sharedMoveDestination
	if patch != nil {
		destination, err = decodeSharedMove(patch)
		if err != nil {
			return nil, err
		}
	}
	mover, _ := session.(sharedNodeMoveSession)
	var moved *sharedpg.NodeMoveReceipt
	err = c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
		supported, err := session.NodeEditingSupported(ctx)
		if err != nil || !supported {
			return err
		}
		runtime, err := c.observeRuntime(ctx, session, trust, pending)
		if err != nil {
			return err
		}
		if runtime.Security.Effective != vault.Default && runtime.Security.Effective != vault.Standard {
			return nil
		}
		if patch != nil && *workspace != pending.WorkspaceID.String() {
			return nil
		}
		next, item, err := session.ReadNodeEdit(ctx, *pending, node, rev)
		if next.Revision != 0 {
			*pending = next
		}
		if err != nil || item == nil {
			return err
		}
		desired, err = item.Metadata()
		if err != nil {
			return err
		}
		fields := sharedNodeEditFields(&desired)
		readEpoch, readSequence := item.Snapshot()
		currentEpoch, currentSequence := strconv.FormatUint(readEpoch, 10), strconv.FormatUint(readSequence, 10)
		if patch == nil {
			reply = sharedNodeEditReply{Status: "ready", NodeID: id, Revision: version, Workspace: pending.WorkspaceID.String(), Epoch: currentEpoch, Sequence: currentSequence, Fields: fields}
			if mover != nil {
				reply.CanMove, err = mover.NodeMovingSupported(ctx)
			}
			return err
		}
		if *epoch != currentEpoch || *sequence != currentSequence {
			return nil
		}
		if destination != nil {
			if mover == nil {
				return nil
			}
			available, err := mover.NodeMovingSupported(ctx)
			if err != nil || !available {
				return err
			}
			if destination.id == nil {
				if desired.ParentID == nil {
					return nil
				}
			} else {
				if *destination.id == node || (desired.ParentID != nil && *desired.ParentID == destination.id.String()) {
					return nil
				}
				next, folder, err := session.ReadNodeEdit(ctx, *pending, *destination.id, destination.revision)
				if next.Revision != 0 {
					*pending = next
				}
				if err != nil || folder == nil {
					return err
				}
				target, err := folder.Metadata()
				e, q := folder.Snapshot()
				if err != nil || target.Kind != 0 || e != readEpoch || q != readSequence {
					return err
				}
			}
			fresh = runtime.Security.Effective == vault.Standard
		} else {
			nullable := make(map[string]bool, len(fields))
			for name := range fields {
				nullable[name] = name != "name"
			}
			before, err := item.Metadata()
			if err != nil {
				return err
			}
			if decodeVaultNullableObject(patch, fields, nullable) != nil {
				inputErr = vaultwire.ErrProtocol
				return nil
			}
			if desired.Validate() != nil || reflect.DeepEqual(desired, before) {
				return nil
			}
			before.Name = desired.Name
			fresh = runtime.Security.Effective == vault.Standard && !reflect.DeepEqual(before, desired)
		}
		if fresh && encoded == nil {
			reply.Status = "authentication-required"
			return nil
		}
		edit = item
		return nil
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if edit == nil {
			return nil
		}
		if fresh {
			valid, err := h.verifySharedExportFactors(ctx, c, trust.Revision, auth)
			auth.wipe()
			if err != nil || !valid {
				return err
			}
		}
		return c.privateKeys.With(func(rawKeys []byte) error {
			if len(rawKeys) != 64 {
				return sharedpg.ErrTrustState
			}
			var err error
			keys := &vault.UserKeys{EncryptionPrivate: rawKeys[:32:32], SigningSeed: rawKeys[32:]}
			if destination != nil {
				moved, err = mover.CommitNodeMove(ctx, trust, edit, destination.id, keys)
				if moved != nil {
					committed = moved.Revision()
				}
			} else {
				committed, err = session.CommitNodeEdit(ctx, trust, edit, desired, keys)
			}
			return err
		})
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	if inputErr != nil {
		return nil, inputErr
	}
	if committed != 0 {
		err = c.withCatalogOperation(ctx, func(ctx context.Context, trust sharedpg.TrustState, pending *sharedpg.TrustState) error {
			if moved != nil {
				next, err := moved.Advance(*pending)
				if next.Revision != 0 {
					*pending = next
				}
				if err == nil {
					reply = sharedNodeEditReply{Status: "saved", NodeID: id, Revision: strconv.FormatUint(committed, 10)}
				}
				return err
			}
			next, after, err := session.ReadNodeEdit(ctx, trust, node, committed)
			if next.Revision != 0 {
				*pending = next
			}
			if err == nil && edit.Matches(after, desired) {
				reply = sharedNodeEditReply{Status: "saved", NodeID: id, Revision: strconv.FormatUint(committed, 10)}
			}
			return err
		}, nil, true)
		if err != nil {
			return nil, h.retire(err)
		}
		h.notifySharedCatalog()
	}
	return json.Marshal(reply)
}
