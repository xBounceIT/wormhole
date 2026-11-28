package sharedpg

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type UnverifiedSelectionRecord struct {
	Selection UnverifiedSelection
	Author    UnverifiedNodeAuthor
}

type UnverifiedCredentialRecord struct {
	Credential UnverifiedCredential
	Author     UnverifiedNodeAuthor
}

// CatalogConnectionRecords is one bounded server snapshot for a connection.
// Nil optional selections denote absence, never permission to ignore a record
// already observed locally. Such records require a current signed tombstone.
// The response decoder must bind every component to the same epoch/change_seq.
// Unrelated selection/credential records are rejected, not silently ignored.
type CatalogConnectionRecords struct {
	Chain                     []UnverifiedChainRecord
	Override, Slot, SlotValue *UnverifiedSelectionRecord
	Credential, Gateway       *UnverifiedCredentialRecord
	Tunnel                    *UnverifiedSelectionRecord
	Path                      string `json:",omitempty"`
	Imported                  []byte `json:",omitempty"`
}

// ResolveCatalogConnection authenticates the complete primary/gateway account
// selection and resolves it natively. It returns metadata, NOT authorization or
// a release capability. Persist nonzero observed state even on error, before using
// any plan. Use/Reveal, key manifests, envelope AAD, tunnel credentials and HPKE
// handoff still belong to the owning release operation.
func (s TrustState) ResolveCatalogConnection(ctx context.Context, node uuid.UUID, records CatalogConnectionRecords) (observed TrustState, plan resolver.Plan, err error) {
	if ctx == nil || node == uuid.Nil || len(records.Chain) == 0 || len(records.Chain) > vaultstore.MaxNodeDepth {
		return TrustState{}, resolver.Plan{}, ErrConfiguration
	}
	if !s.valid() || s.Account == nil || !s.Account.Active {
		return TrustState{}, resolver.Plan{}, ErrTrustState
	}
	observed = cloneTrustState(s)
	changed := false
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
	authors := make(map[uuid.UUID]uint64)
	inconsistent := false
	remember := func(author UnverifiedNodeAuthor) {
		user, seq := author.State.UserID, author.State.Sequence
		if old, ok := authors[user]; ok && old != seq {
			inconsistent = true
		}
		authors[user] = seq
	}
	selection := func(input *UnverifiedSelectionRecord, want sharedcatalog.SelectionScope) (bool, error) {
		if e := ctx.Err(); e != nil {
			return false, e
		}
		actual, deleted, e := sharedcatalog.SelectionIdentity(input.Selection.Record)
		if e != nil || actual != want {
			return false, ErrAdmissionResponse
		}
		next, e := observed.AdvanceSelection(input.Selection, input.Author)
		absorb(next)
		if e != nil && e != vaultstore.ErrMissing {
			return false, e
		}
		remember(input.Author)
		return deleted, nil
	}
	absent := func(kind string, subject, user uuid.UUID) error {
		key := kind + "/" + subject.String()
		if user != uuid.Nil {
			key += "/" + user.String()
		}
		if _, ok := observed.Catalog[key]; ok {
			return ErrAdmissionResponse
		}
		return nil
	}
	override := ""
	web := records.Path == WebConnectionPlanPath
	if web {
		if records.Override != nil || records.Slot != nil || records.SlotValue != nil || records.Credential != nil || records.Gateway != nil || records.Imported != nil {
			return observed, plan, ErrAdmissionResponse
		}
	} else if records.Override != nil {
		deleted, e := selection(records.Override, sharedcatalog.SelectionScope{Kind: "override", Subject: node, User: s.UserID})
		if e != nil {
			return observed, plan, e
		}
		if !deleted {
			override = records.Override.Selection.Record.(sharedcatalog.OverrideRecord).CredentialID
		}
	} else if e := absent("override", node, s.UserID); e != nil {
		return observed, plan, e
	}
	next, resolved, e := observed.resolveCatalogChain(ctx, node, records.Chain, override, records.Path != "")
	absorb(next)
	if e != nil {
		return observed, plan, e
	}
	for _, entry := range records.Chain {
		remember(entry.Author)
	}
	plan = resolved
	if web && plan.Protocol != 3 && plan.Protocol != 4 {
		return observed, plan, ErrAdmissionResponse
	}
	if plan.Credential.Kind == "slot" {
		if records.Slot == nil {
			return observed, plan, ErrAdmissionResponse
		}
		slotID, e := uuid.Parse(plan.Credential.ID)
		if e != nil {
			return observed, plan, ErrAdmissionResponse
		}
		deleted, e := selection(records.Slot, sharedcatalog.SelectionScope{Kind: "slot", Subject: slotID})
		if e != nil {
			return observed, plan, e
		}
		if deleted {
			return observed, plan, vaultstore.ErrMissing
		}
		slot := records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
		var value *resolver.CredentialSlotValue
		if records.SlotValue != nil {
			deleted, e := selection(records.SlotValue, sharedcatalog.SelectionScope{Kind: "slot-value", Subject: slotID, User: s.UserID})
			if e != nil {
				return observed, plan, e
			}
			if !deleted {
				v := records.SlotValue.Selection.Record.(sharedcatalog.SlotValueRecord)
				value = &resolver.CredentialSlotValue{SlotID: v.SlotID, UserID: v.UserID, CredentialID: v.CredentialID}
			}
		} else if e := absent("slot-value", slotID, s.UserID); e != nil {
			return observed, plan, e
		}
		plan, e = resolver.ResolveSlot(plan, s.UserID.String(), resolver.CredentialSlot{ID: slot.ID, Protocol: slot.Protocol, DefaultCredentialID: slot.DefaultCredentialID, AllowSelfService: slot.AllowSelfService}, value)
		if e != nil {
			return observed, plan, e
		}
	} else if records.Slot != nil || records.SlotValue != nil {
		return observed, plan, ErrAdmissionResponse
	}
	var retained *resolver.EffectiveCredentialSnapshot
	if records.Path != "" && !web {
		data, e := workspaceimport.DecodeNodeData(records.Chain[0].Node.Metadata, records.Imported)
		if e != nil {
			return observed, plan, e
		}
		var pins []resolver.EffectiveCredentialSnapshot
		if data != nil {
			pins = data.Pins
		}
		retained, e = resolver.RetainedAccount(plan, records.Path, pins)
		if e != nil {
			return observed, plan, e
		}
		if retained != nil {
			plan = resolver.ApplyRetainedAccount(plan, *retained)
		} else if records.Path == "rdp-gateway" {
			plan = resolver.GatewayCandidate(plan)
		}
		if records.Path == "rdp" || records.Path == "rdp-gateway" {
			// Each RDP path describes exactly one account. The paired release
			// proves both choices before the owning protocol can open either.
			plan.GatewayCredentialID = ""
		}
	} else if records.Imported != nil {
		return observed, plan, ErrAdmissionResponse
	}
	credential := func(input *UnverifiedCredentialRecord, id, protocol string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if input == nil || input.Credential.Record.Metadata.ID != id {
			return ErrAdmissionResponse
		}
		next, e := observed.AdvanceCredential(input.Credential, input.Author)
		absorb(next)
		if e != nil {
			return e
		}
		remember(input.Author)
		if protocol != "" && input.Credential.Record.Metadata.Protocol != protocol {
			return resolver.ErrCredential
		}
		return nil
	}
	switch plan.Credential.Kind {
	case "saved", "override":
		protocol := resolver.CredentialProtocol(plan.Protocol)
		if records.Path == "reveal" && retained != nil {
			protocol = ""
		}
		if e := credential(records.Credential, plan.Credential.ID, protocol); e != nil {
			return observed, plan, e
		}
		if retained == nil {
			plan, e = resolver.ApplyCredential(plan, records.Credential.Credential.Record.Metadata)
			if e != nil {
				return observed, plan, e
			}
		}
	default:
		if records.Credential != nil {
			return observed, plan, ErrAdmissionResponse
		}
	}
	if plan.GatewayCredentialID != "" {
		if e := credential(records.Gateway, plan.GatewayCredentialID, "rdp"); e != nil {
			return observed, plan, e
		}
	} else if records.Gateway != nil {
		return observed, plan, ErrAdmissionResponse
	}
	if plan.TunnelID != "" {
		id, e := uuid.Parse(plan.TunnelID)
		if e != nil || records.Tunnel == nil {
			return observed, plan, ErrAdmissionResponse
		}
		deleted, e := selection(records.Tunnel, sharedcatalog.SelectionScope{Kind: "tunnel", Subject: id})
		if e != nil {
			return observed, plan, e
		}
		if deleted {
			return observed, plan, vaultstore.ErrMissing
		}
	} else if records.Tunnel != nil {
		return observed, plan, ErrAdmissionResponse
	}
	if e := ctx.Err(); e != nil {
		return observed, plan, e
	}
	if inconsistent {
		return observed, plan, ErrTreeSnapshotChanged
	}
	if observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		return observed, plan, vault.ErrAuthentication
	}
	return observed, plan, nil
}
