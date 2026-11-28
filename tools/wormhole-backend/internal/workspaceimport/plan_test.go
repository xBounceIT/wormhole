package workspaceimport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type importFixture struct {
	owner                                         *localvault.Owner
	source                                        localvault.WorkspaceImport
	target                                        Target
	folder, connection, current, retained, tunnel ItemID
}

func fixture(t *testing.T) importFixture {
	t.Helper()
	ctx := context.Background()
	identity := vaultstore.Identity{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), Root: vaultstore.KeyRef{ID: uuid.NewString(), Version: 1}}
	key := vault.NewRecoveryKey()
	defer vault.Wipe(key)
	slot, err := vault.CreateRecoverySlot(identity.WorkspaceID, uuid.NewString(), 1, key, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	slots := vault.SlotFile{FormatVersion: 1, VaultID: identity.WorkspaceID, FileID: identity.FileID, Sequence: 1, FileEpoch: 1, Slots: []vault.Slot{slot}, RootKeyID: identity.Root.ID, RootKeyVersion: 1}
	raw, err := vault.EncodeSlotFile(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	o, err := localvault.Open(ctx, filepath.Join(t.TempDir(), "source.db"), localvault.OpenOptions{Identity: identity, Slots: slots, MinimumSequence: 1, Create: true}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := o.Close(); err != nil {
			t.Error(err)
		}
	})
	current := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Current profile", Protocol: "ssh", Kind: "password", Provider: "local", Username: "current-test-identity"}
	retained := current
	retained.ID, retained.Name, retained.Username = uuid.NewString(), "Legacy profile", "retained-test-identity"
	for _, profile := range []vaultstore.CredentialMetadata{current, retained} {
		if _, err := o.PutCredential(ctx, profile, []localvault.SecretChange{{Field: "password", Value: []byte("synthetic-test-private-field")}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	tunnel := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Route"}
	if _, err := o.PutTunnel(ctx, tunnel, []byte(`{"password":"synthetic-tunnel-secret"}`), 0); err != nil {
		t.Fatal(err)
	}
	protocol, mode, enabled, host := 0, 2, true, "private-host.example"
	folder := vaultstore.NodeMetadata{ID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Name: "Folder", CredentialID: &current.ID, CredentialMode: &mode}
	if _, err := o.PutNode(ctx, folder, nil, 0); err != nil {
		t.Fatal(err)
	}
	connection := vaultstore.NodeMetadata{ID: "11111111-1111-4111-8111-111111111111", Name: "SSH", ParentID: &folder.ID, Kind: 1, Protocol: &protocol, Host: &host, TunnelEnabled: &enabled, TunnelConfigID: &tunnel.ID}
	n, err := o.PutNode(ctx, connection, []localvault.SecretChange{{Field: "notes", Value: []byte("synthetic-private-note")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var old, next []resolver.EffectiveCredentialSnapshot
	for _, path := range resolver.AccountPaths(protocol) {
		resolved, err := o.ResolveConnectionPath(ctx, connection.ID, "", path)
		if err != nil {
			t.Fatal(err)
		}
		before := resolved.Account
		before.ResolverVersion = 0
		if path == "ssh" {
			before.CredentialID, before.Username = retained.ID, retained.Username
		}
		old, next = append(old, before), append(next, resolved.Account)
	}
	pin, err := resolver.BuildMigration(identity.WorkspaceID, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, pin, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	source, err := o.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return importFixture{owner: o, source: source, target: Target{WorkspaceID: uuid.New(), UserID: uuid.New(), RequestID: uuid.New()},
		folder: ItemID{"node", folder.ID}, connection: ItemID{"node", connection.ID}, current: ItemID{"credential", current.ID},
		retained: ItemID{"credential", retained.ID}, tunnel: ItemID{"tunnel", tunnel.ID}}
}

func TestPrepareDefaultsToPersonalAndPinsTranslatedAccounts(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	preview, plan, err := Prepare(ctx, f.source, f.target, Selection{})
	if err != nil || plan == nil || len(preview.Items) != 5 || len(preview.Conflicts) != 0 || len(preview.Changes) != 1 {
		t.Fatal("could not prepare the personal import", err)
	}
	for _, item := range preview.Items {
		if item.Destination != Personal {
			t.Fatal("a record was shared by default")
		}
	}
	folder, _, _ := plan.DestinationFor(f.folder)
	connection, _, _ := plan.DestinationFor(f.connection)
	current, _, _ := plan.DestinationFor(f.current)
	retained, _, _ := plan.DestinationFor(f.retained)
	tunnel, _, _ := plan.DestinationFor(f.tunnel)
	if root, leaf := plan.Nodes[0], plan.Nodes[1]; root.ID != folder || leaf.ID != connection || *leaf.ParentID != folder ||
		*root.CredentialID != current || leaf.CredentialID != nil || *leaf.TunnelConfigID != tunnel ||
		*root.OwnerUserID != f.target.UserID.String() || *leaf.OwnerUserID != f.target.UserID.String() {
		t.Fatal("the destination graph lost ownership, parent order or inheritance")
	}
	if plan.Tunnels[0].ID != tunnel || plan.SourceFingerprint != f.source.Fingerprint {
		t.Fatal("the source configuration was not bound to the new tunnel")
	}
	pin := plan.Pins.Entries[0]
	change := preview.Changes[0]
	if pin.Legacy.NodeID != connection || pin.Legacy.CredentialID != retained || pin.Candidate.CredentialID != current ||
		pin.Choice != "keep" || pin.Legacy.ProtocolPath != "ssh" || change.NodeID != f.connection.ID ||
		change.OldCredentialID != f.retained.ID || change.NewCredentialID != f.current.ID || !change.UsernameChanged {
		t.Fatal("resolver continuity was not bound to the correct destination IDs")
	}
	if _, err := json.Marshal(plan); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("native plan could be serialized", err)
	}
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"retained-test-identity", "current-test-identity", "synthetic-test-private-field", "synthetic-private-note", "synthetic-tunnel-secret", "private-host.example", folder, tunnel} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("the preview contained native-only information")
		}
	}
	_, retry, err := Prepare(ctx, f.source, f.target, Selection{})
	if err != nil || retry.Nodes[1].ID != connection || retry.Pins.Fingerprint != plan.Pins.Fingerprint {
		t.Fatal("retry changed the destination graph", err)
	}
	f.target.RequestID = uuid.New()
	_, next, err := Prepare(ctx, f.source, f.target, Selection{})
	if err != nil || next.Nodes[1].ID == connection {
		t.Fatal("separate imports reused the same destination IDs", err)
	}
}

func TestPrepareReportsPrivateDependenciesAndHonorsResolverReview(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	selection := Selection{Shared: []ItemID{f.connection}}
	preview, plan, err := Prepare(ctx, f.source, f.target, selection)
	if err != nil || plan != nil || len(preview.Conflicts) != 3 {
		t.Fatal("shared references to personal data were accepted", err)
	}
	want := map[ItemID]bool{f.folder: true, f.retained: true, f.tunnel: true}
	for _, conflict := range preview.Conflicts {
		if conflict.Item != f.connection || !want[conflict.Dependency] {
			t.Fatal("a placement conflict identified the wrong item")
		}
		delete(want, conflict.Dependency)
	}
	selection.Shared = append(selection.Shared, f.folder, f.current, f.tunnel)
	preview, plan, err = Prepare(ctx, f.source, f.target, selection)
	if err != nil || plan != nil || len(preview.Conflicts) != 1 || preview.Conflicts[0].Dependency != f.retained {
		t.Fatal("the retained identity bypassed boundary checks", err)
	}
	selection.Review = &ResolverReview{Fingerprint: preview.ResolverFingerprint, Decisions: []resolver.MigrationDecision{{NodeID: f.connection.ID, ProtocolPath: "ssh", Choice: "new"}}}
	preview, plan, err = Prepare(ctx, f.source, f.target, selection)
	if err != nil || plan == nil || len(preview.Conflicts) != 0 || preview.Changes[0].Choice != "new" {
		t.Fatal("an explicit new identity did not resolve the placement conflict", err)
	}
	if plan.Nodes[1].OwnerUserID != nil || plan.Pins.Entries[0].Choice != "new" {
		t.Fatal("the prepared destination did not retain the approved choices")
	}
	_, scope, available := plan.DestinationFor(f.retained)
	if !available || scope != Personal {
		t.Fatal("resolving a conflict implicitly shared a credential")
	}
	selection.Review.Fingerprint = "stale"
	if _, _, err := Prepare(ctx, f.source, f.target, selection); !errors.Is(err, resolver.ErrMigrationStale) {
		t.Fatal("a stale claim selected a new resolver identity", err)
	}
	// A personal child may still use components deliberately selected for sharing.
	selection = Selection{Shared: []ItemID{f.folder, f.current, f.tunnel}}
	if _, plan, err := Prepare(ctx, f.source, f.target, selection); err != nil || plan == nil || plan.Nodes[1].OwnerUserID == nil {
		t.Fatal("private child could not use explicitly shared resources", err)
	}
}

func TestPrepareRejectsMalformedSelectionAndIncompleteSource(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	for _, selection := range []Selection{{Shared: []ItemID{f.folder, f.folder}}, {Shared: []ItemID{{Kind: "tunnel", ID: f.folder.ID}}}} {
		if _, plan, err := Prepare(ctx, f.source, f.target, selection); err != vault.ErrFormat || plan != nil {
			t.Fatal("an invalid placement was accepted", err)
		}
	}
	target := f.target
	target.UserID = uuid.Nil
	if _, _, err := Prepare(ctx, f.source, target, Selection{}); err != vault.ErrFormat {
		t.Fatal("an unauthenticated destination was accepted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := Prepare(cancelled, f.source, f.target, Selection{}); err != context.Canceled {
		t.Fatal("cancelled import kept preparing data", err)
	}
	source := f.source
	source.Accounts = source.Accounts[:len(source.Accounts)-1]
	if _, plan, err := Prepare(ctx, source, f.target, Selection{}); !errors.Is(err, resolver.ErrMigration) || plan != nil {
		t.Fatal("partial path capture could publish a changed identity", err)
	}
	source = f.source
	source.Catalog.Tunnels = nil
	if _, plan, err := Prepare(ctx, source, f.target, Selection{}); err != vault.ErrAuthentication || plan != nil {
		t.Fatal("missing referenced tunnel produced a dangling destination graph", err)
	}
}

func TestPrepareKeepsRDPGatewaySeparateAcrossPlacements(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	makeProfile := func(name string) ItemID {
		t.Helper()
		profile := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: name, Username: name, Protocol: "rdp", Kind: "password", Provider: "local"}
		if _, err := f.owner.PutCredential(ctx, profile, []localvault.SecretChange{{Field: "password", Value: []byte("synthetic-rdp-private-field")}}, 0); err != nil {
			t.Fatal(err)
		}
		return ItemID{Kind: "credential", ID: profile.ID}
	}
	primary, gateway := makeProfile("Desktop account"), makeProfile("Gateway account")
	protocol, method, host, gatewayHost := 1, 1, "desktop.example", "gateway.example"
	node := vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 1, Name: "RDP", Protocol: &protocol, Host: &host, CredentialID: &primary.ID,
		RDPGatewayUsageMethod: &method, RDPGatewayHostname: &gatewayHost, RDPGatewayCredentialID: &gateway.ID}
	if _, err := f.owner.PutNode(ctx, node, nil, 0); err != nil {
		t.Fatal(err)
	}
	source, err := f.owner.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := ItemID{Kind: "node", ID: node.ID}
	selection := Selection{Shared: []ItemID{item, primary}}
	preview, plan, err := Prepare(ctx, source, f.target, selection)
	if err != nil || plan != nil || len(preview.Conflicts) != 1 || preview.Conflicts[0] != (PlacementConflict{Item: item, Dependency: gateway}) {
		t.Fatal("a shared RDP node could reach a personal gateway account", err)
	}
	selection.Shared = append(selection.Shared, gateway)
	preview, plan, err = Prepare(ctx, source, f.target, selection)
	if err != nil || plan == nil || len(preview.Changes) != 1 || preview.Changes[0].NodeID != f.connection.ID {
		t.Fatal("assigning both profiles to the shared destination changed the RDP identities", err)
	}
	nodeID, _, _ := plan.DestinationFor(item)
	primaryID, _, _ := plan.DestinationFor(primary)
	gatewayID, _, _ := plan.DestinationFor(gateway)
	for _, translated := range plan.Nodes {
		if translated.ID == nodeID && translated.CredentialID != nil && translated.RDPGatewayCredentialID != nil &&
			*translated.CredentialID == primaryID && *translated.RDPGatewayCredentialID == gatewayID {
			return
		}
	}
	t.Fatal("the destination merged or lost the RDP account references")
}
