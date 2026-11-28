package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedWebArchiveProbe struct {
	*credentialReleaseProbe
	supported bool
	views     map[uuid.UUID]uuid.UUID
	batches   []int
}

type sharedWebCheckpointProbe struct {
	*sharedWebArchiveProbe
	checkpointSupported bool
	checkpointErr       error
	onCheckpoint        func(uuid.UUID, uuid.UUID, bool) bool
}

func (p *sharedWebCheckpointProbe) WebSessionCheckpointsSupported(context.Context) (bool, error) {
	return p.checkpointSupported, p.checkpointErr
}

func (p *sharedWebCheckpointProbe) SetWebSessionCheckpoint(_ context.Context, node, generation uuid.UUID, present bool) (bool, error) {
	return p.onCheckpoint(node, generation, present), nil
}

type sharedWebPlanProbe struct {
	*sharedWebArchiveProbe
	webPlan       func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error)
	webPlanExists func() (bool, error)
}

func (p *sharedWebPlanProbe) WebConnectionPlanSupported(context.Context) (bool, error) {
	return p.webPlanExists()
}

func (p *sharedWebPlanProbe) WebConnectionPlan(ctx context.Context, node uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
	return p.webPlan(ctx, node)
}

func (p *sharedWebArchiveProbe) WebSessionViewsSupported(context.Context) (bool, error) {
	return p.supported, nil
}

func (p *sharedWebArchiveProbe) OpenWebSessionView(_ context.Context, node uuid.UUID) (uuid.UUID, error) {
	generation := p.views[node]
	if generation == uuid.Nil {
		generation = uuid.New()
		p.views[node] = generation
	}
	return generation, nil
}

func (p *sharedWebArchiveProbe) CheckWebSessionViews(_ context.Context, nodes []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	p.batches = append(p.batches, len(nodes))
	result := make(map[uuid.UUID]uuid.UUID, len(nodes))
	for _, node := range nodes {
		if generation := p.views[node]; generation != uuid.Nil {
			result[node] = generation
		}
	}
	return result, nil
}

func webSessionPacket(t *testing.T, h *vaultFoundationHandler, node string) map[string]any {
	t.Helper()
	request := map[string]any{"nodeId": node, "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "7", "credentialOverride": ""}
	raw, err := h.Handle(context.Background(), "web-plan", vaultInput(t, request))
	var plan vaultWebPlan
	if err != nil || json.Unmarshal(raw, &plan) != nil || len(plan.ArchiveBinding) != 64 {
		t.Fatalf("missing archive binding for saved node: %v", err)
	}
	delete(request, "credentialOverride")
	request["archiveBinding"] = plan.ArchiveBinding
	return request
}

func readWebSessionPacket(t *testing.T, h *vaultFoundationHandler, request map[string]any) (webArchiveReply, error) {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	request = cloneSFTPPacket(request)
	request["recipient"] = key.PublicKey().Bytes()
	body, err := h.Handle(context.Background(), "web-session-read", vaultInput(t, request))
	var result webArchiveReply
	if err == nil {
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("fixture web archive")) {
			t.Fatal("plaintext left native vault")
		}
	}
	return result, err
}

func TestNativeWebSessionStatePinsSavedEndpointAndRevision(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	host, protocol := "browser.example", 4
	node, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 1,
		Name: "Saved browser", Host: &host, Protocol: &protocol}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := webSessionPacket(t, h, node.ID)
	for _, bad := range []map[string]any{
		{"epoch": "07", "recipient": bytes.Repeat([]byte{2}, 32)},
		{"recipient": []byte{1}},
		{"archiveBinding": "wrong", "recipient": bytes.Repeat([]byte{2}, 32)},
		{"recipient": bytes.Repeat([]byte{2}, 32), "host": "override.example"},
	} {
		packet := cloneSFTPPacket(request)
		for field, value := range bad {
			packet[field] = value
		}
		if _, err := h.Handle(ctx, "web-session-read", vaultInput(t, packet)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatalf("malformed archive read: %v", err)
		}
	}
	for _, bad := range []struct {
		revision string
		archive  []byte
	}{
		{"00", []byte{1}}, {"9223372036854775807", []byte{1}}, {"0", nil},
		{"0", make([]byte, vault.MaxWebSessionArchiveBytes+1)},
	} {
		packet := cloneSFTPPacket(request)
		packet["revision"], packet["archive"] = bad.revision, bad.archive
		if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, packet)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatalf("malformed archive save: %v", err)
		}
	}
	if _, err := h.Handle(ctx, "web-session-save", make([]byte, 2*vault.MaxWebSessionArchiveBytes+1)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatalf("oversized archive frame: %v", err)
	}
	load, err := readWebSessionPacket(t, h, request)
	if err != nil || load.Revision != 0 || load.Bundle != nil {
		t.Fatalf("unexpected initial archive: %v", err)
	}
	save := cloneSFTPPacket(request)
	save["revision"], save["archive"] = "0", []byte("fixture web archive")
	body := vaultInput(t, save)
	if ack, err := h.Handle(ctx, "web-session-save", body); err != nil || string(ack) != `{"revision":"1"}` {
		t.Fatalf("save receipt: %s %v", ack, err)
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("native secret packet survived consumption")
	}
	load, err = readWebSessionPacket(t, h, request)
	if err != nil || load.Revision != 1 || load.Bundle == nil || len(load.Bundle.Ciphertext) <= 16 {
		t.Fatalf("missing sealed archive: %v", err)
	}
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("stale revision overwrote archive: %v", err)
	}
	changed := node.NodeMetadata
	newHost := "replacement.example"
	changed.Host = &newHost
	if _, err := h.owner.PutNode(ctx, changed, nil, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := readWebSessionPacket(t, h, request); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("stale route read succeeded: %v", err)
	}
	next := webSessionPacket(t, h, node.ID)
	load, err = readWebSessionPacket(t, h, next)
	if err != nil || load.Revision != 1 || load.Bundle != nil {
		t.Fatalf("previous endpoint archive moved to a new host: %v", err)
	}
	forget := cloneSFTPPacket(next)
	forget["revision"] = "1"
	if ack, err := h.Handle(ctx, "web-session-forget", vaultInput(t, forget)); err != nil || string(ack) != `{"revision":"2"}` {
		t.Fatalf("forget receipt: %s %v", ack, err)
	}
}

func TestSharedWebSessionUsesPersonalCacheUnderCurrentAdmission(t *testing.T) {
	ctx := context.Background()
	c, p, options, _, keys, _, node, wire := credentialControllerFixture(t)
	editSharedConnectionFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire,
		func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
			protocol, noAccount := 4, 1
			n.Protocol, n.CredentialID, n.CredentialMode = &protocol, nil, &noAccount
		})
	wire["metadata"].(map[string]any)["credential"] = nil
	p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
		t.Fatal("web archive acquired a credential ticket")
		return nil, nil
	}
	fileID := uuid.NewString()
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: fileID}}
	q := map[string]any{"nodeId": node.String(), "sessionId": uuid.NewString(), "requestId": uuid.NewString(),
		"epoch": "7", "credentialOverride": ""}
	checkUnavailable := func() {
		t.Helper()
		raw, err := h.Handle(ctx, "web-plan", vaultInput(t, q))
		var plan vaultWebPlan
		if err != nil || json.Unmarshal(raw, &plan) != nil || plan.ArchiveBinding != "" || !c.Unlocked() {
			t.Fatalf("unavailable persistence affected shared browsing: %v", err)
		}
	}
	checkUnavailable()
	personal := vaultCredentialFixture(t)
	c.vpnSSO = &sharedVPNSSOStorage{owner: personal.owner, fileID: fileID}
	probe := &sharedWebArchiveProbe{credentialReleaseProbe: p, views: make(map[uuid.UUID]uuid.UUID)}
	c.session = probe
	checkUnavailable()
	probe.supported = true
	request := webSessionPacket(t, h, node.String())
	save := cloneSFTPPacket(request)
	save["revision"], save["archive"] = "0", []byte("fixture web archive")
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); !errors.Is(err, vaultstore.ErrConflict) || !c.Unlocked() {
		t.Fatalf("concurrent browser save terminated the admission: %v", err)
	}
	if result, err := readWebSessionPacket(t, h, request); err != nil || result.Bundle == nil {
		t.Fatalf("personal cache failed: %v", err)
	}
	owner := localvault.WebSessionArchiveOwner{WorkspaceID: options.Binding.WorkspaceID,
		FileID: uuid.MustParse(fileID), AccountID: options.Binding.UserID}
	archives, _, err := personal.owner.ListWebSessionArchives(ctx, owner, "", 32)
	if err != nil || len(archives) != 1 || archives[0].Generation != probe.views[node] || archives[0].Generation == uuid.Nil {
		t.Fatalf("archive omitted the authenticated View generation: %v", err)
	}
	// The account regained View while this client was offline. Its resolver is
	// valid again, but the old generation must neither restore nor overwrite.
	delete(probe.views, node)
	if result, err := readWebSessionPacket(t, h, request); result.Bundle != nil || !errors.Is(err, vault.ErrPolicy) || !c.Unlocked() {
		t.Fatalf("a retired View generation stayed usable: %v", err)
	}
	replacement := webSessionPacket(t, h, node.String())
	if replacement["archiveBinding"] == request["archiveBinding"] {
		t.Fatal("a fresh View grant reused the archive binding")
	}
	if result, err := readWebSessionPacket(t, h, request); result.Bundle != nil || !errors.Is(err, vaultstore.ErrConflict) || !c.Unlocked() {
		t.Fatalf("a stale browser restored the old generation: %v", err)
	}
	p.accountState = func(context.Context) (*vault.UserKeyState, error) { return keys.State, nil }
	if err := c.refreshWorkspaceAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if records, _, err := personal.owner.ListWebSessionArchives(ctx, owner, "", 32); err != nil || len(records) != 0 {
		t.Fatalf("native background scan retained a stale archive outside the catalog pages: %v", err)
	}
	if result, err := readWebSessionPacket(t, h, replacement); err != nil || result.Bundle != nil || result.Revision != 2 {
		t.Fatalf("new View received an old archive: %v", err)
	}
	p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		return nil, sharedpg.ErrQuery
	}
	if result, err := readWebSessionPacket(t, h, request); result.Bundle != nil || !errors.Is(err, vaultwire.ErrRetired) || c.Unlocked() {
		t.Fatalf("denied admission retained archive access: %v", err)
	}
}

func TestSharedWebCheckpointInventoryTracksDurableLocalState(t *testing.T) {
	ctx := context.Background()
	c, p, options, _, keys, _, node, wire := credentialControllerFixture(t)
	editSharedConnectionFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire,
		func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
			protocol, noAccount := 4, 1
			n.Protocol, n.CredentialID, n.CredentialMode = &protocol, nil, &noAccount
		})
	wire["metadata"].(map[string]any)["credential"] = nil
	file := uuid.New()
	personal := vaultCredentialFixture(t)
	c.vpnSSO = &sharedVPNSSOStorage{owner: personal.owner, fileID: file.String()}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: file.String()}}
	probe := &sharedWebCheckpointProbe{sharedWebArchiveProbe: &sharedWebArchiveProbe{
		credentialReleaseProbe: p, supported: true, views: make(map[uuid.UUID]uuid.UUID),
	}}
	c.session = probe
	request := webSessionPacket(t, h, node.String())
	save := cloneSFTPPacket(request)
	save["revision"], save["archive"] = "0", []byte("fixture web archive")
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); err != nil {
		t.Fatal("the earlier server could not save a cookie checkpoint", err)
	}
	probe.checkpointSupported = true
	owner := localvault.WebSessionArchiveOwner{WorkspaceID: options.Binding.WorkspaceID, FileID: file, AccountID: options.Binding.UserID}
	var observed []bool
	allowed := true
	probe.onCheckpoint = func(id, generation uuid.UUID, present bool) bool {
		if id != node || generation != probe.views[node] || generation == uuid.Nil {
			t.Fatal("checkpoint metadata did not bind the current admission and node")
		}
		archives, _, err := personal.owner.ListWebSessionArchives(ctx, owner, "", 32)
		if err != nil || !present && len(archives) != 0 {
			t.Fatal("the server marker was removed before the local archive", err)
		}
		if len(observed) >= 3 && present && len(archives) != 0 {
			t.Fatal("the local archive was committed before reserving the server marker")
		}
		observed = append(observed, present)
		return allowed
	}
	if loaded, err := readWebSessionPacket(t, h, request); err != nil || loaded.Bundle == nil || loaded.Revision != 1 {
		t.Fatal("an earlier checkpoint did not restore and report its presence after upgrade", err)
	}
	allowed = false
	if loaded, err := readWebSessionPacket(t, h, request); !errors.Is(err, vault.ErrPolicy) || loaded.Bundle != nil || !c.Unlocked() {
		t.Fatal("a denied generation restored old data or retired unrelated sessions", err)
	}
	allowed = true
	forget := cloneSFTPPacket(request)
	forget["revision"] = "1"
	if _, err := h.Handle(ctx, "web-session-forget", vaultInput(t, forget)); err != nil {
		t.Fatal(err)
	}
	save["revision"] = "2"
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 4 || !observed[0] || !observed[1] || observed[2] || !observed[3] {
		t.Fatal("unexpected sequence of checkpoint markers", observed)
	}
	probe.checkpointErr = sharedpg.ErrQuery
	if loaded, err := readWebSessionPacket(t, h, request); !errors.Is(err, sharedpg.ErrQuery) || loaded.Bundle != nil || c.Unlocked() {
		t.Fatal("a missing authority receipt must stop the native owner", err)
	}
}

func TestSharedImportedWebPlanAndArchiveOmitRevealAccount(t *testing.T) {
	ctx := context.Background()
	c, p, options, _, keys, _, node, wire := credentialControllerFixture(t)
	metadata := wire["metadata"].(map[string]any)
	credentialID := metadata["plan"].(resolver.Plan).Credential.ID
	editSharedConnectionFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire,
		func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
			protocol, noAccount := 3, 1
			n.Protocol, n.CredentialID, n.CredentialMode = &protocol, nil, &noAccount
		})
	signSharedPathFixture(t, options.Binding.WorkspaceID, keys.State.Signing, wire, []resolver.EffectiveCredentialSnapshot{{
		NodeID: node.String(), ProtocolPath: "reveal", SourceKind: "saved", CredentialID: credentialID, Username: "retained-user",
	}})
	addSharedPathProjection(wire, sharedpg.WebConnectionPlanPath, nil)
	metadata["credential"] = nil
	loadSignedPlan := p.plan
	p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		return nil, sharedpg.ErrImportedConnectionPins
	}
	p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
		t.Fatal("opening the browser issued an account release ticket")
		return nil, nil
	}
	fileID := uuid.NewString()
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: fileID}}
	q := map[string]any{"nodeId": node.String(), "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "7", "credentialOverride": ""}
	if _, err := h.Handle(ctx, "web-plan", vaultInput(t, q)); err == nil || !c.Unlocked() {
		t.Fatal("an unsupported database accepted the pinned plan or lost admission", err)
	}
	personal := vaultCredentialFixture(t)
	c.vpnSSO = &sharedVPNSSOStorage{owner: personal.owner, fileID: fileID}
	probe := &sharedWebPlanProbe{
		sharedWebArchiveProbe: &sharedWebArchiveProbe{credentialReleaseProbe: p, supported: true, views: make(map[uuid.UUID]uuid.UUID)},
		webPlanExists:         func() (bool, error) { return false, nil },
		webPlan: func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
			t.Fatal("the old database was queried for a missing API")
			return nil, nil
		},
	}
	c.session = probe
	if _, err := h.Handle(ctx, "web-plan", vaultInput(t, q)); err == nil || !c.Unlocked() {
		t.Fatal("missing server support did not keep the normal pinned-plan guard", err)
	}
	plans := 0
	probe.webPlanExists = func() (bool, error) { return true, nil }
	probe.webPlan = func(ctx context.Context, id uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		if id != node {
			t.Fatal("web planning selected the wrong node")
		}
		plans++
		return loadSignedPlan(ctx, id)
	}
	request := webSessionPacket(t, h, node.String())
	save := cloneSFTPPacket(request)
	save["revision"], save["archive"] = "0", []byte("fixture web archive")
	if _, err := h.Handle(ctx, "web-session-save", vaultInput(t, save)); err != nil {
		t.Fatal("the native archive did not use the web-only plan", err)
	}
	result, err := readWebSessionPacket(t, h, request)
	if err != nil || result.Bundle == nil || plans != 3 || !c.Unlocked() {
		t.Fatal("the pinned web target did not restore through the authenticated plan", err)
	}
	probe.webPlanExists = func() (bool, error) { return false, nil }
	if result, err := readWebSessionPacket(t, h, request); result.Bundle != nil || !errors.Is(err, sharedpg.ErrImportedConnectionPins) || !c.Unlocked() {
		t.Fatal("missing plan support released an archive or lost the admission", err)
	}
	failedProbe := errors.New("web capability fixture failure")
	probe.webPlanExists = func() (bool, error) { return false, failedProbe }
	if _, err := h.Handle(ctx, "web-plan", vaultInput(t, q)); !errors.Is(err, failedProbe) || c.Unlocked() {
		t.Fatal("a failed capability query kept the shared admission", err)
	}
}

func TestSharedWebViewReconciliationBatchesAllTrackedNodes(t *testing.T) {
	ctx := context.Background()
	c, p, options, _, keys, _, _, _ := credentialControllerFixture(t)
	p.accountState = func(context.Context) (*vault.UserKeyState, error) { return keys.State, nil }
	probe := &sharedWebArchiveProbe{credentialReleaseProbe: p, supported: true, views: make(map[uuid.UUID]uuid.UUID)}
	c.session = probe
	cache := vaultCredentialFixture(t).owner
	fileID := uuid.New()
	c.vpnSSO = &sharedVPNSSOStorage{owner: cache, fileID: fileID.String()}
	for i := 0; i < sharedpg.MaxTreePage+3; i++ {
		id, generation := uuid.New(), uuid.New()
		if i != 0 {
			probe.views[id] = generation
		}
		if i == 1 {
			probe.views[id] = uuid.New()
		}
		b := localvault.WebSessionBinding{WorkspaceID: options.Binding.WorkspaceID.String(), FileID: fileID.String(),
			AccountID: options.Binding.UserID.String(), NodeID: id.String(), Protocol: "https", Host: "fixture.example",
			Port: 443, ViewGeneration: generation.String()}
		if _, err := cache.SaveWebSessionState(ctx, b, 0, []byte("synthetic browser state")); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.refreshWorkspaceAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	if len(probe.batches) != 2 || probe.batches[0] != sharedpg.MaxTreePage || probe.batches[1] != 3 {
		t.Fatalf("reconciliation omitted archives or exceeded its batch bound: %v", probe.batches)
	}
	owner := localvault.WebSessionArchiveOwner{WorkspaceID: options.Binding.WorkspaceID, FileID: fileID,
		AccountID: options.Binding.UserID}
	found, _, err := cache.ListWebSessionArchives(ctx, owner, "", 128)
	if err != nil || len(found) != sharedpg.MaxTreePage+1 {
		t.Fatalf("reconciliation erased unrelated scopes or missed a revocation: %v", err)
	}
	for _, record := range found {
		if record.Generation != probe.views[record.Node] {
			t.Fatal("reconciliation kept a retired generation")
		}
	}
}

func TestVaultWebSessionViewChecksDoNotReregisterOrRetireHealthyOwners(t *testing.T) {
	ctx := context.Background()
	c, p, _, _, keys, _, node, _ := credentialControllerFixture(t)
	p.accountState = func(context.Context) (*vault.UserKeyState, error) { return keys.State, nil }
	generation, old, missing := uuid.New(), uuid.New(), uuid.New()
	probe := &sharedWebArchiveProbe{credentialReleaseProbe: p, supported: true,
		views: map[uuid.UUID]uuid.UUID{node: generation}}
	c.session = probe
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	request := func(node, generation uuid.UUID) map[string]string {
		return map[string]string{"nodeId": node.String(), "generation": generation.String()}
	}
	views := []map[string]string{request(node, old), request(missing, generation), request(node, generation)}
	payload := map[string]any{"views": views}
	read := func(want string) {
		t.Helper()
		out, err := h.Handle(ctx, "web-session-verify-views", vaultInput(t, payload))
		if err != nil || string(out) != want || !c.Unlocked() {
			t.Fatalf("unexpected live browser generation verdict: %s %v", out, err)
		}
	}
	read(`{"current":[false,false,true]}`)
	if len(probe.batches) != 1 || probe.batches[0] != 2 || len(probe.views) != 1 {
		t.Fatalf("the verifier registered a missing generation or repeated a node lookup: %v", probe.batches)
	}
	probe.supported = false
	read(`{"current":[false,false,false]}`)

	for _, bad := range [][]byte{
		[]byte(`{"views":[]}`), []byte(`{"views":null}`), []byte(`{"views":[{"nodeId":"invalid","generation":"invalid"}]}`),
		[]byte(`{"views":[null]}`), make([]byte, 4097),
		vaultInput(t, map[string]any{"views": make([]any, sharedpg.MaxTreePage+1)}),
		vaultInput(t, map[string]any{"views": []map[string]string{
			{"nodeId": node.String(), "generation": generation.String(), "other": "extra"},
		}}),
	} {
		if _, err := h.Handle(ctx, "web-session-verify-views", bad); !errors.Is(err, vaultwire.ErrProtocol) || !c.Unlocked() {
			t.Fatalf("invalid check reached the shared admission: %v", err)
		}
	}
}

func TestWebSessionPersistenceFollowsEffectiveProfile(t *testing.T) {
	for _, tc := range []struct {
		profile vault.Profile
		allowed bool
	}{{vault.Default, true}, {vault.Standard, true}, {vault.Hardened, false}, {vault.Paranoid, false}} {
		if webSessionPersistenceAllowed(tc.profile) != tc.allowed {
			t.Fatalf("unexpected persistence policy for %v", tc.profile)
		}
	}
}
