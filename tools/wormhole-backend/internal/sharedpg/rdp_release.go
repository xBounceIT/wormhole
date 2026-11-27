package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type rdpReleaseWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Primary       json.RawMessage `json:"primary"`
	Gateway       json.RawMessage `json:"gateway"`
}

func parseRDPRelease(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedCredentialRelease, error) {
	var wire rdpReleaseWire
	if _, err := strictCatalogObject(raw, wire, "gateway"); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &wire) != nil || wire.FormatVersion != 6 {
		return nil, ErrAdmissionResponse
	}
	primary, err := parseCredentialPathRelease(wire.Primary, request, node, epoch, sequence, "rdp")
	if err != nil {
		return nil, err
	}
	primary.pairedRDP = true
	noGateway := bytes.Equal(bytes.TrimSpace(wire.Gateway), []byte("null"))
	if noGateway != (primary.metadata.plan.GatewayMethod == 0) {
		return nil, ErrAdmissionResponse
	}
	if noGateway {
		return primary, nil
	}
	gateway, err := parseCredentialPathRelease(wire.Gateway, request, node, epoch, sequence, "rdp-gateway")
	if err != nil {
		return nil, err
	}
	a, b := primary.metadata.records, gateway.metadata.records
	if !bytes.Equal(primary.profile, gateway.profile) || !reflect.DeepEqual(primary.account, gateway.account) ||
		!reflect.DeepEqual(primary.enrollment, gateway.enrollment) || !reflect.DeepEqual(a.Chain, b.Chain) ||
		!bytes.Equal(a.Imported, b.Imported) || !reflect.DeepEqual(a.Override, b.Override) ||
		!reflect.DeepEqual(a.Slot, b.Slot) || !reflect.DeepEqual(a.SlotValue, b.SlotValue) ||
		!reflect.DeepEqual(a.Tunnel, b.Tunnel) || !consistentRDPValues(primary, gateway) {
		return nil, ErrAdmissionResponse
	}
	primary.rdpGateway = gateway
	return primary, nil
}

// The same field must come from the same encrypted record in both paths.
// Different fields must use distinct DEKs, including across the two graphs.
func consistentRDPValues(primary, gateway *UnverifiedCredentialRelease) bool {
	type field struct {
		kind string
		id   uuid.UUID
		name string
	}
	fields := make(map[field]UnverifiedSharedValue)
	keys := make(map[vault.KeyRef]field)
	for _, graph := range []*UnverifiedCredentialRelease{primary, gateway} {
		for _, account := range graph.accounts {
			for _, item := range account.values {
				b := item.Binding
				id := field{b.OwnerKind, b.OwnerID, b.Field}
				if previous, ok := fields[id]; ok && !reflect.DeepEqual(previous, item) {
					return false
				}
				if previous, ok := keys[b.DEK]; ok && previous != id {
					return false
				}
				fields[id], keys[b.DEK] = item, id
			}
		}
	}
	return true
}

func (s TrustState) verifyRDPRelease(ctx context.Context, node uuid.UUID, graph *UnverifiedCredentialRelease) (TrustState, *VerifiedCredentialRelease, error) {
	next, primary, primaryErr := s.verifyCredentialPathRelease(ctx, node, graph)
	base := s
	if next.Revision != 0 {
		base = next
		base.Revision = s.Revision
	}
	facts, gateway, gatewayErr := base.verifyCredentialPathRelease(ctx, node, graph.rdpGateway)
	if facts.Revision != 0 {
		facts.Revision = max(facts.Revision, next.Revision)
		next = facts
	}
	if err := errors.Join(primaryErr, gatewayErr); err != nil {
		return next, nil, err
	}
	// A valid newer gateway observation can invalidate the first proof.
	// Recheck the primary against all facts before preparing either account.
	rechecked, _, err := next.verifyCredentialPathRelease(ctx, node, graph)
	if err != nil {
		return next, nil, err
	}
	if !reflect.DeepEqual(next, rechecked) {
		return next, nil, ErrTreeSnapshotChanged
	}
	primary.trust, gateway.trust = cloneTrustState(next), cloneTrustState(next)
	primary.rdpGateway = gateway
	return next, primary, nil
}

type rdpReleaseAccount struct {
	Plan   resolver.Plan
	Values CredentialReleaseValues
}

// withRDPAccounts opens both roles only after one committed verification and
// under the release's one-use fence. A manual primary call can skip every
// saved primary value while still borrowing the separately verified gateway.
// The callback owns neither the credential bytes nor their lifetime.
func (v *VerifiedCredentialRelease) withRDPAccounts(ctx context.Context, committed TrustState, private []byte, includePrimary, includeGateway bool, use func(rdpReleaseAccount, *rdpReleaseAccount) error) error {
	if v == nil || v.graph == nil || !v.graph.pairedRDP || use == nil {
		return ErrConfiguration
	}
	return v.withValues(ctx, committed, private, false, !includePrimary, func(p resolver.Plan, values CredentialReleaseValues) error {
		primary := rdpReleaseAccount{Plan: p, Values: values}
		if !includeGateway || v.rdpGateway == nil {
			return use(primary, nil)
		}
		return v.rdpGateway.withValues(ctx, committed, private, false, false, func(g resolver.Plan, values CredentialReleaseValues) error {
			return use(primary, &rdpReleaseAccount{Plan: g, Values: values})
		})
	})
}

// RDPPlan keeps the configured gateway route and derives credential reuse from
// the two resolved identities. For a manual primary account only a separately
// kept or configured gateway identity is selected for opening.
func (v *VerifiedCredentialRelease) RDPPlan(manual bool) (resolver.Plan, error) {
	if v == nil || v.graph == nil || v.graph.metadata == nil || v.plan.Protocol != 1 {
		return resolver.Plan{}, ErrConfiguration
	}
	plan := v.plan
	if !v.graph.pairedRDP {
		return plan, nil
	}
	data, err := workspaceimport.DecodeNodeData(v.graph.metadata.records.Chain[0].Node.Metadata, v.graph.metadata.records.Imported)
	if err != nil {
		return resolver.Plan{}, err
	}
	var pins []resolver.EffectiveCredentialSnapshot
	if data != nil {
		pins = data.Pins
	}
	primaryPin, err := resolver.RetainedAccount(plan, "rdp", pins)
	if err != nil {
		return resolver.Plan{}, err
	}
	if manual {
		plan.Username, plan.Domain = "", ""
		plan.Credential = resolver.Choice{Kind: "none"}
		plan.ExternalRDPClient = resolver.ProjectRDPSettings(v.rdpChain()).UseExternalClient
	} else if primaryPin != nil && primaryPin.SourceKind == "system" {
		return resolver.Plan{}, vault.ErrPolicy
	}
	if v.rdpGateway == nil {
		return plan, nil
	}
	gateway := v.rdpGateway.plan
	gatewayPin, err := resolver.RetainedAccount(gateway, "rdp-gateway", pins)
	if err != nil {
		return resolver.Plan{}, err
	}
	if gatewayPin != nil && gatewayPin.SourceKind == "system" {
		return resolver.Plan{}, vault.ErrPolicy
	}
	same := v.plan.GatewaySameCredentials
	if manual {
		same = same && gatewayPin == nil
	} else {
		same = same && plan.Credential.Kind == gateway.Credential.Kind && plan.Credential.ID == gateway.Credential.ID &&
			plan.Username == gateway.Username && plan.Domain == gateway.Domain
	}
	plan.GatewaySameCredentials = same
	if !same && (gateway.Credential.Kind == "saved" || gateway.Credential.Kind == "override") {
		plan.GatewayCredentialID = gateway.Credential.ID
	}
	return plan, nil
}

func (v *VerifiedCredentialRelease) withPairedRDPValues(ctx context.Context, committed TrustState, private []byte, manual bool, use func(resolver.Plan, CredentialReleaseValues) error) error {
	if use == nil {
		return ErrConfiguration
	}
	plan, err := v.RDPPlan(manual)
	if err != nil {
		return err
	}
	openGateway := plan.GatewayMethod != 0 && !plan.GatewaySameCredentials
	return v.withRDPAccounts(ctx, committed, private, !manual, openGateway, func(primary rdpReleaseAccount, gateway *rdpReleaseAccount) error {
		values := primary.Values
		if gateway != nil {
			var err error
			values.Gateway, err = gateway.borrowedGateway(plan.NodeID, plan.GatewayCredentialID)
			if err != nil {
				return err
			}
		}
		return use(plan, values)
	})
}

func (a rdpReleaseAccount) borrowedGateway(node, credential string) (*BorrowedCredential, error) {
	value := BorrowedCredential{Metadata: vaultstore.CredentialMetadata{Protocol: "rdp", Provider: "local", Kind: "password"}}
	switch a.Plan.Credential.Kind {
	case "saved", "override":
		if a.Values.Primary == nil || a.Values.Primary.Metadata.ID != credential {
			return nil, ErrAdmissionResponse
		}
		value = *a.Values.Primary
	case "inline":
		if a.Values.Inline == nil || a.Values.Inline.NodeID != node {
			return nil, ErrAdmissionResponse
		}
		if secret, present := a.Values.Inline.Fields["inlinePassword"]; present {
			value.Fields = map[string][]byte{"password": secret}
		}
	case "none":
	default:
		return nil, ErrAdmissionResponse
	}
	value.Metadata.Username, value.Metadata.Domain = a.Plan.Username, a.Plan.Domain
	return &value, nil
}
