// Package workspaceimport prepares an authenticated local catalog for import
// into a shared workspace. Only Preview may cross the renderer boundary.
package workspaceimport

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"runtime"
	"sort"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type Destination string

const (
	Personal Destination = "personal"
	Shared   Destination = "shared"
)

type ItemID struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Item struct {
	ItemID
	Name        string      `json:"name"`
	Destination Destination `json:"destination"`
}

// A shared item cannot depend on an item confined to the importer's personal
// scope. Report both source IDs so the user can revise their selections.
type PlacementConflict struct {
	Item       ItemID `json:"item"`
	Dependency ItemID `json:"dependency"`
}

type Preview struct {
	Items               []Item                     `json:"items"`
	Conflicts           []PlacementConflict        `json:"conflicts"`
	Changes             []resolver.MigrationReport `json:"resolverChanges"`
	ResolverFingerprint string                     `json:"resolverFingerprint"`
}

type Target struct {
	WorkspaceID uuid.UUID `json:"workspaceId"`
	UserID      uuid.UUID `json:"userId"`
	RequestID   uuid.UUID `json:"requestId"`
}

type Selection struct {
	Shared []ItemID
	Review *ResolverReview
}

type ResolverReview struct {
	Fingerprint string
	Decisions   []resolver.MigrationDecision // Node IDs from Preview.
}

type placement struct {
	id          string
	destination Destination
}

// Plan is native staging metadata. The translated graph uses new IDs, and its
// accounts must resolve with the selected pins when installed in PostgreSQL.
type Plan struct {
	Target            Target
	SourceFingerprint [sha256.Size]byte
	Nodes             []vaultstore.NodeMetadata // Parent before child for insertion.
	Credentials       []vaultstore.CredentialMetadata
	Tunnels           []vaultstore.TunnelMetadata
	Pins              resolver.MigrationPlan
	placements        map[ItemID]placement
	digest            [sha256.Size]byte
}

func (Plan) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

func (p *Plan) preparationDigest() ([sha256.Size]byte, error) {
	type prepared Plan
	raw, err := json.Marshal((*prepared)(p))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// DestinationFor translates original field owners, including tunnels whose
// destination ownership is represented by their PostgreSQL boundary.
func (p *Plan) DestinationFor(item ItemID) (string, Destination, bool) {
	result, ok := p.placements[item]
	return result.id, result.destination, ok
}

func (p *Plan) IncludesDestination(destination Destination) bool {
	for _, place := range p.placements {
		if place.destination == destination {
			return true
		}
	}
	return false
}

// ApprovalDigest identifies the confirmed logical import independently of
// randomized ciphertext. Include the tunnel placements, which are not part
// of the translated tunnel metadata.
func (p *Plan) ApprovalDigest() ([sha256.Size]byte, error) {
	digest, err := p.preparationDigest()
	if err != nil || digest != p.digest {
		return [sha256.Size]byte{}, vault.ErrAuthentication
	}
	ids := make([]string, 0, len(p.placements))
	for _, place := range p.placements {
		ids = append(ids, place.id+":"+string(place.destination))
	}
	sort.Strings(ids)
	encoded, err := json.Marshal(ids)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/workspace-import-approval\x00"))
	h.Write(digest[:])
	h.Write(encoded)
	var result [sha256.Size]byte
	h.Sum(result[:0])
	return result, nil
}

// Prepare defaults every item to personal, translating references without
// changing inheritance. Conflicts return a usable preview and no staging plan.
func Prepare(ctx context.Context, source localvault.WorkspaceImport, target Target, selection Selection) (Preview, *Plan, error) {
	if ctx == nil || target.WorkspaceID == uuid.Nil || target.UserID == uuid.Nil || target.RequestID == uuid.Nil ||
		source.Fingerprint == ([sha256.Size]byte{}) || !validItemID(source.Source.WorkspaceID) || !validItemID(source.Source.FileID) ||
		source.Source.WorkspaceID == target.WorkspaceID.String() ||
		len(selection.Shared) > len(source.Catalog.Nodes)+len(source.Catalog.Credentials)+len(source.Catalog.Tunnels) ||
		(selection.Review != nil && len(selection.Review.Decisions) > len(source.Accounts)) {
		return Preview{}, nil, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return Preview{}, nil, err
	}
	preview := Preview{Items: []Item{}, Conflicts: []PlacementConflict{}, Changes: []resolver.MigrationReport{}}
	plan := &Plan{Target: target, SourceFingerprint: source.Fingerprint, placements: make(map[ItemID]placement)}
	chosen := make(map[ItemID]bool, len(selection.Shared))
	for _, item := range selection.Shared {
		if chosen[item] {
			return Preview{}, nil, vault.ErrFormat
		}
		chosen[item] = true
	}
	namespace := uuid.NewSHA1(target.RequestID, []byte("wormhole/v1/workspace-import/"+target.WorkspaceID.String()+"/"+
		target.UserID.String()+"/"+source.Source.WorkspaceID+"/"+source.Source.FileID))
	add := func(kind, id, name string) error {
		key := ItemID{Kind: kind, ID: id}
		if _, exists := plan.placements[key]; exists || !validItemID(key.ID) {
			return vault.ErrAuthentication
		}
		destination := Personal
		if chosen[key] {
			destination = Shared
			delete(chosen, key)
		}
		plan.placements[key] = placement{id: uuid.NewSHA1(namespace, []byte(kind+"/"+id)).String(), destination: destination}
		preview.Items = append(preview.Items, Item{ItemID: key, Name: name, Destination: destination})
		return nil
	}
	for _, node := range source.Catalog.Nodes {
		if err := add("node", node.ID, node.Name); err != nil {
			return Preview{}, nil, err
		}
	}
	for _, profile := range source.Catalog.Credentials {
		if err := add("credential", profile.ID, profile.Name); err != nil {
			return Preview{}, nil, err
		}
	}
	for _, tunnel := range source.Catalog.Tunnels {
		if err := add("tunnel", tunnel.ID, tunnel.Name); err != nil {
			return Preview{}, nil, err
		}
	}
	if len(chosen) != 0 {
		return Preview{}, nil, vault.ErrFormat
	}
	if err := plan.translate(ctx, source, selection.Review, &preview); err != nil {
		return Preview{}, nil, err
	}
	if len(preview.Conflicts) != 0 {
		return preview, nil, nil
	}
	digest, err := plan.preparationDigest()
	if err != nil {
		return Preview{}, nil, err
	}
	plan.digest = digest
	return preview, plan, nil
}

func validItemID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && value == id.String()
}

func (p *Plan) translate(ctx context.Context, source localvault.WorkspaceImport, review *ResolverReview, preview *Preview) error {
	nodeIDs := make(map[string]string, len(source.Catalog.Nodes))
	credentialIDs := make(map[string]string, len(source.Catalog.Credentials))
	credentials := make(map[string]vaultstore.CredentialMetadata, len(source.Catalog.Credentials))
	sourceCredential := make(map[string]string, len(source.Catalog.Credentials))
	nodes := make(map[string]vaultstore.NodeMetadata, len(source.Catalog.Nodes))
	sourceByTarget := make(map[string]string, len(source.Catalog.Nodes))
	owner := p.Target.UserID.String()
	for _, c := range source.Catalog.Credentials {
		place := p.placements[ItemID{Kind: "credential", ID: c.ID}]
		metadata := c.CredentialMetadata
		metadata.ID, metadata.OwnerUserID = place.id, ""
		if place.destination == Personal {
			metadata.OwnerUserID = owner
		}
		credentialIDs[c.ID], credentials[metadata.ID] = metadata.ID, metadata
		sourceCredential[metadata.ID] = c.ID
		p.Credentials = append(p.Credentials, metadata)
	}
	for _, t := range source.Catalog.Tunnels {
		metadata := t.TunnelMetadata
		metadata.ID = p.placements[ItemID{Kind: "tunnel", ID: t.ID}].id
		p.Tunnels = append(p.Tunnels, metadata)
	}
	seen := make(map[PlacementConflict]bool)
	check := func(item, dependency ItemID) (string, error) {
		place, exists := p.placements[dependency]
		if !exists {
			return "", vault.ErrAuthentication
		}
		conflict := PlacementConflict{Item: item, Dependency: dependency}
		if p.placements[item].destination == Shared && place.destination == Personal && !seen[conflict] {
			seen[conflict] = true
			preview.Conflicts = append(preview.Conflicts, conflict)
		}
		return place.id, nil
	}
	tunnelKinds := make(map[string]int, len(source.Catalog.Tunnels))
	for _, tunnel := range source.Catalog.Tunnels {
		tunnelKinds[tunnel.ID] = tunnel.Kind
	}
	for _, tunnel := range source.Catalog.Tunnels {
		if fallback := source.TunnelFallbacks[tunnel.ID]; fallback != "" {
			if tunnel.Kind != 9 || tunnelKinds[fallback] != 2 {
				return vault.ErrPolicy
			}
			if _, err := check(ItemID{Kind: "tunnel", ID: tunnel.ID}, ItemID{Kind: "tunnel", ID: fallback}); err != nil {
				return err
			}
		}
	}
	for _, n := range source.Catalog.Nodes {
		item := ItemID{Kind: "node", ID: n.ID}
		place := p.placements[item]
		metadata := n.NodeMetadata
		metadata.ID, metadata.OwnerUserID = place.id, nil
		if place.destination == Personal {
			metadata.OwnerUserID = &owner
		}
		if n.CredentialSlotID != nil {
			return vault.ErrPolicy // The local source has no portable slot catalog.
		}
		for _, ref := range []struct {
			kind  string
			value **string
		}{{"node", &metadata.ParentID}, {"credential", &metadata.CredentialID},
			{"credential", &metadata.RDPGatewayCredentialID}, {"tunnel", &metadata.TunnelConfigID}} {
			if *ref.value != nil {
				id, err := check(item, ItemID{Kind: ref.kind, ID: **ref.value})
				if err != nil {
					return err
				}
				*ref.value = &id
			}
		}
		nodeIDs[n.ID], sourceByTarget[metadata.ID] = metadata.ID, n.ID
		nodes[metadata.ID] = metadata
		p.Nodes = append(p.Nodes, metadata)
	}
	var candidate []resolver.EffectiveCredentialSnapshot
	depths := make(map[string]int, len(p.Nodes))
	for _, n := range p.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		chain, err := importChain(n, nodes)
		if err != nil {
			return err
		}
		depths[n.ID] = len(chain)
		if n.Kind == 0 {
			continue
		}
		accounts, err := shadowAccounts(chain, credentials)
		if err != nil {
			return err
		}
		candidate = append(candidate, accounts...)
	}
	sort.SliceStable(p.Nodes, func(i, j int) bool { return depths[p.Nodes[i].ID] < depths[p.Nodes[j].ID] })
	pins, err := source.ResolverMigration(p.Target.WorkspaceID.String(), nodeIDs, credentialIDs, candidate)
	if err != nil {
		return err
	}
	if review != nil {
		decisions := make([]resolver.MigrationDecision, 0, len(review.Decisions))
		for _, decision := range review.Decisions {
			decision.NodeID = nodeIDs[decision.NodeID]
			decisions = append(decisions, decision)
		}
		pins, err = pins.Decide(review.Fingerprint, decisions)
		if err != nil {
			return err
		}
	}
	// A retained pin can introduce a dependency outside the structural graph.
	for _, pin := range pins.Entries {
		if pin.Choice == "keep" && pin.Legacy.SourceKind == "saved" {
			item := ItemID{Kind: "node", ID: sourceByTarget[pin.Legacy.NodeID]}
			dependency := ItemID{Kind: "credential", ID: sourceCredential[pin.Legacy.CredentialID]}
			if _, err := check(item, dependency); err != nil {
				return err
			}
		}
	}
	report, err := pins.Report()
	if err != nil {
		return err
	}
	for i, change := range report {
		before, after := pins.Entries[i].Legacy, pins.Entries[i].Candidate
		report[i].NodeID = sourceByTarget[change.NodeID]
		report[i].OldCredentialID, report[i].NewCredentialID = sourceCredential[change.OldCredentialID], sourceCredential[change.NewCredentialID]
		if before.SourceKind == "inline" {
			report[i].OldCredentialID = report[i].NodeID
		}
		if after.SourceKind == "inline" {
			report[i].NewCredentialID = report[i].NodeID
		}
	}
	p.Pins, preview.Changes, preview.ResolverFingerprint = pins, report, pins.Fingerprint
	return ctx.Err()
}

func importChain(leaf vaultstore.NodeMetadata, nodes map[string]vaultstore.NodeMetadata) ([]vaultstore.NodeMetadata, error) {
	chain := []vaultstore.NodeMetadata{leaf}
	for parent := leaf.ParentID; parent != nil; {
		ancestor, ok := nodes[*parent]
		if !ok || ancestor.Kind != 0 || len(chain) >= vaultstore.MaxNodeDepth {
			return nil, resolver.ErrChain
		}
		chain = append(chain, ancestor)
		parent = ancestor.ParentID
	}
	return chain, nil
}

func shadowAccounts(chain []vaultstore.NodeMetadata, credentials map[string]vaultstore.CredentialMetadata) ([]resolver.EffectiveCredentialSnapshot, error) {
	plan, err := resolver.Resolve(chain, "")
	if err != nil {
		return nil, err
	}
	if plan.Credential.Kind == "saved" {
		plan, err = resolver.ApplyCredential(plan, credentials[plan.Credential.ID])
		if err != nil {
			return nil, err
		}
	}
	lookup := func(id string) (vaultstore.CredentialMetadata, error) {
		return credentials[id], nil // AccountSnapshot checks the typed identity.
	}
	paths := resolver.AccountPaths(plan.Protocol)
	accounts := make([]resolver.EffectiveCredentialSnapshot, 0, len(paths))
	for _, path := range paths {
		account, err := resolver.AccountSnapshot(plan, path, runtime.GOOS, lookup)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}
