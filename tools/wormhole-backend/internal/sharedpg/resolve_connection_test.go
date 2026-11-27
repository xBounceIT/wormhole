package sharedpg

import (
	"context"
	"crypto/ed25519"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type connectionFixture struct {
	s        TrustState
	records  CatalogConnectionRecords
	org, key ed25519.PrivateKey
}

func newConnectionFixture(t *testing.T) connectionFixture {
	t.Helper()
	s, chain, org, key := resolutionChainFixture(t)
	f := connectionFixture{s: s, records: CatalogConnectionRecords{Chain: chain}, org: org, key: key}
	f.records.Credential = f.profile(t, "ssh")
	mode, user := 2, "node-user"
	chain[0].Node.Metadata.CredentialMode = &mode
	chain[0].Node.Metadata.CredentialID = &f.records.Credential.Credential.Record.Metadata.ID
	chain[0].Node.Metadata.Username = &user
	f.signChain(t)
	return f
}
func (f connectionFixture) profile(t *testing.T, protocol string) *UnverifiedCredentialRecord {
	t.Helper()
	a := f.records.Chain[0].Author
	r := &UnverifiedCredentialRecord{Credential: UnverifiedCredential{Record: sharedcatalog.CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Account", Protocol: protocol, Kind: "password", Provider: "local", Username: "profile-user", Domain: "profile-domain"}}, Boundary: f.records.Chain[0].Node.Boundary}, Author: a}
	f.signProfile(t, r, 1)
	return r
}
func (f connectionFixture) signProfile(t *testing.T, r *UnverifiedCredentialRecord, revision uint64) {
	t.Helper()
	var e error
	r.Credential.Seal, e = sharedcatalog.SignCredential(f.s.WorkspaceID, r.Credential.Boundary, r.Credential.Record, revision, r.Author.Key, f.key)
	if e != nil {
		t.Fatal(e)
	}
}
func (f connectionFixture) selection(t *testing.T, r sharedcatalog.SelectionRecord) *UnverifiedSelectionRecord {
	t.Helper()
	a := f.records.Chain[0].Author
	s := &UnverifiedSelectionRecord{Selection: UnverifiedSelection{Record: r, Boundary: f.records.Chain[0].Node.Boundary}, Author: a}
	f.signSelection(t, s, 1)
	return s
}
func (f connectionFixture) signSelection(t *testing.T, r *UnverifiedSelectionRecord, revision uint64) {
	t.Helper()
	var e error
	r.Selection.Seal, e = sharedcatalog.SignSelection(f.s.WorkspaceID, r.Selection.Boundary, r.Selection.Record, revision, r.Author.Key, f.key)
	if e != nil {
		t.Fatal(e)
	}
}
func (f connectionFixture) signChain(t *testing.T) {
	signResolutionChain(t, f.s, f.records.Chain, f.key)
}
func (f connectionFixture) node() uuid.UUID {
	return uuid.MustParse(f.records.Chain[0].Node.Metadata.ID)
}
func (f *connectionFixture) slot(t *testing.T, personal bool) {
	t.Helper()
	id := uuid.NewString()
	mode := 3
	f.records.Chain[0].Node.Metadata.CredentialMode = &mode
	f.records.Chain[0].Node.Metadata.CredentialID = nil
	f.records.Chain[0].Node.Metadata.CredentialSlotID = &id
	f.records.Slot = f.selection(t, sharedcatalog.SlotRecord{ID: id, Name: "Slot", Protocol: "ssh", DefaultCredentialID: f.records.Credential.Credential.Record.Metadata.ID})
	if personal {
		f.records.Credential = f.profile(t, "ssh")
		f.records.SlotValue = f.selection(t, sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: id, UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID})
	}
	f.signChain(t)
}

func TestResolveCatalogConnectionChoices(t *testing.T) {
	for _, mode := range []string{"saved", "none", "inline", "override", "deleted-override", "slot-default", "slot-personal", "slot-deleted-value", "gateway"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectionFixture(t)
			kind, user := "saved", "node-user"
			switch mode {
			case "none":
				v := 1
				f.records.Chain[0].Node.Metadata.CredentialMode = &v
				f.records.Credential = nil
				kind = "none"
			case "inline":
				v := true
				f.records.Chain[0].Node.Metadata.UseInlinePassword = &v
				f.records.Credential = nil
				kind = "inline"
			case "override", "deleted-override":
				r := sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID}
				if mode == "deleted-override" {
					r.Deleted = true
					r.CredentialID = ""
				} else {
					kind = "override"
					user = "profile-user"
				}
				f.records.Override = f.selection(t, r)
			case "slot-default", "slot-personal", "slot-deleted-value":
				f.slot(t, mode == "slot-personal")
				user = "profile-user"
				if mode == "slot-deleted-value" {
					slot := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
					f.records.SlotValue = f.selection(t, sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: slot.ID, UserID: f.s.UserID.String(), Deleted: true})
				}
			case "gateway":
				protocol, method, host := 1, 1, "gateway.example"
				f.records.Chain[0].Node.Metadata.Protocol = &protocol
				f.records.Chain[0].Node.Metadata.RDPGatewayUsageMethod = &method
				f.records.Chain[0].Node.Metadata.RDPGatewayHostname = &host
				f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
				f.signProfile(t, f.records.Credential, 1)
				f.records.Gateway = f.profile(t, "rdp")
				f.records.Chain[0].Node.Metadata.RDPGatewayCredentialID = &f.records.Gateway.Credential.Record.Metadata.ID
			}
			f.signChain(t)
			next, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			if e != nil || plan.Credential.Kind != kind || plan.Username != user || plan.Host != "server.example" || next.Revision != f.s.Revision+1 || f.s.ValidateAdvance(next) != nil {
				t.Fatal("resolve", plan, e)
			}
			if mode == "gateway" && plan.GatewayCredentialID != f.records.Gateway.Credential.Record.Metadata.ID {
				t.Fatal("gateway")
			}
			again, p, e := next.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			if e != nil || p != plan || !reflect.DeepEqual(next, again) {
				t.Fatal("idempotence", e)
			}
			if f.s.Catalog != nil {
				t.Fatal("mutated caller")
			}
		})
	}
}

func TestResolveCatalogConnectionFailures(t *testing.T) {
	for _, mode := range []string{"chain-signature", "override-user", "override-node", "override-kind", "override-signature", "slot-missing", "slot-id", "slot-deleted", "slot-protocol", "value-user", "value-signature", "extra-slot", "extra-value", "credential-missing", "credential-id", "credential-signature", "credential-protocol", "credential-deleted", "extra-credential", "gateway-missing", "gateway-protocol", "extra-gateway"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectionFixture(t)
			switch mode {
			case "chain-signature":
				f.records.Chain[0].Node.Seal.Signature = make([]byte, 64)
			case "override-user", "override-node", "override-kind", "override-signature":
				r := sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID}
				if mode == "override-user" {
					r.UserID = uuid.NewString()
				}
				if mode == "override-node" {
					r.NodeID = uuid.NewString()
				}
				f.records.Override = f.selection(t, r)
				if mode == "override-signature" {
					f.records.Override.Selection.Seal.Signature = make([]byte, 64)
				}
				if mode == "override-kind" {
					f.records.Override = f.selection(t, sharedcatalog.SlotRecord{ID: f.node().String(), Name: "Bad", Protocol: "ssh"})
				}
			case "slot-missing", "slot-id", "slot-deleted", "slot-protocol", "value-user", "value-signature":
				f.slot(t, true)
				if mode == "slot-missing" {
					f.records.Slot = nil
					break
				}
				if mode == "value-user" {
					r := f.records.SlotValue.Selection.Record.(sharedcatalog.SlotValueRecord)
					r.UserID = uuid.NewString()
					f.records.SlotValue = f.selection(t, r)
					break
				}
				if mode == "value-signature" {
					f.records.SlotValue.Selection.Seal.Signature = make([]byte, 64)
					break
				}
				r := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
				if mode == "slot-id" {
					r.ID = uuid.NewString()
				}
				if mode == "slot-deleted" {
					r.Deleted = true
				}
				if mode == "slot-protocol" {
					r.Protocol = "rdp"
				}
				f.records.Slot = f.selection(t, r)
			case "extra-slot", "extra-value":
				r := f.selection(t, sharedcatalog.SlotRecord{ID: uuid.NewString(), Name: "extra", Protocol: "ssh"})
				if mode == "extra-slot" {
					f.records.Slot = r
				} else {
					f.records.SlotValue = r
				}
			case "credential-missing":
				f.records.Credential = nil
			case "credential-id":
				f.records.Credential = f.profile(t, "ssh")
			case "credential-signature":
				f.records.Credential.Credential.Seal.Signature = make([]byte, 64)
			case "credential-protocol":
				f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
				f.signProfile(t, f.records.Credential, 1)
			case "credential-deleted":
				f.records.Credential.Credential.Record.Deleted = true
				f.signProfile(t, f.records.Credential, 1)
			case "extra-credential":
				v := 1
				f.records.Chain[0].Node.Metadata.CredentialMode = &v
				f.signChain(t)
			case "gateway-missing", "gateway-protocol":
				protocol, method, host, id := 1, 1, "gateway.example", uuid.NewString()
				f.records.Chain[0].Node.Metadata.Protocol = &protocol
				f.records.Chain[0].Node.Metadata.RDPGatewayUsageMethod = &method
				f.records.Chain[0].Node.Metadata.RDPGatewayHostname = &host
				f.records.Chain[0].Node.Metadata.RDPGatewayCredentialID = &id
				f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
				f.signProfile(t, f.records.Credential, 1)
				if mode == "gateway-protocol" {
					f.records.Gateway = f.profile(t, "ssh")
					f.records.Gateway.Credential.Record.Metadata.ID = id
					f.signProfile(t, f.records.Gateway, 1)
				}
				f.signChain(t)
			case "extra-gateway":
				f.records.Gateway = f.profile(t, "rdp")
			}
			next, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			want := error(ErrAdmissionResponse)
			switch mode {
			case "chain-signature", "override-signature", "value-signature", "credential-signature":
				want = vault.ErrAuthentication
			case "slot-deleted", "credential-deleted":
				want = vaultstore.ErrMissing
			case "slot-protocol", "credential-protocol", "gateway-protocol":
				want = resolver.ErrCredential
			}
			if e != want || plan != (resolver.Plan{}) || next.Revision == 0 || (!reflect.DeepEqual(next, f.s) && f.s.ValidateAdvance(next) != nil) {
				t.Fatal("failure leaked plan/lost floors", e)
			}
		})
	}
}

func TestResolveCatalogConnectionOmissionAndTombstones(t *testing.T) {
	for _, kind := range []string{"override", "slot-value"} {
		t.Run(kind, func(t *testing.T) {
			f := newConnectionFixture(t)
			if kind == "override" {
				f.records.Override = f.selection(t, sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID})
			} else {
				f.slot(t, true)
			}
			next, _, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			if e != nil {
				t.Fatal(e)
			}
			var saved *UnverifiedSelectionRecord
			if kind == "override" {
				saved = f.records.Override
				f.records.Override = nil
			} else {
				saved = f.records.SlotValue
				f.records.SlotValue = nil
			}
			omitted, plan, e := next.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			if e != ErrAdmissionResponse || plan != (resolver.Plan{}) || !reflect.DeepEqual(omitted, next) {
				t.Fatal("omission reset selection", e)
			}
			if kind == "override" {
				r := saved.Selection.Record.(sharedcatalog.OverrideRecord)
				r.Deleted = true
				r.CredentialID = ""
				saved.Selection.Record = r
				f.records.Override = saved
			} else {
				r := saved.Selection.Record.(sharedcatalog.SlotValueRecord)
				r.Deleted = true
				r.CredentialID = ""
				saved.Selection.Record = r
				f.records.SlotValue = saved
				slot := f.records.Slot.Selection.Record.(sharedcatalog.SlotRecord)
				f.records.Credential.Credential.Record.Metadata.ID = slot.DefaultCredentialID
				f.signProfile(t, f.records.Credential, 1)
			}
			f.signSelection(t, saved, 2)
			deleted, _, e := next.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			if e != nil || next.ValidateAdvance(deleted) != nil {
				t.Fatal("signed removal", e)
			}
			if kind == "override" {
				f.records.Override = nil
			} else {
				f.records.SlotValue = nil
			}
			if _, _, e = deleted.ResolveCatalogConnection(context.Background(), f.node(), f.records); e != ErrAdmissionResponse {
				t.Fatal("tombstone omitted", e)
			}
		})
	}
}

func TestResolveCatalogConnectionRevisionAndCancellation(t *testing.T) {
	f := newConnectionFixture(t)
	f.slot(t, true)
	f.s.Revision = math.MaxUint64 - 1
	next, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != nil || next.Revision != math.MaxUint64 || plan.NodeID != f.node().String() {
		t.Fatal("atomic counter", e)
	}
	same, p, e := next.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != nil || !reflect.DeepEqual(same, next) || p != plan {
		t.Fatal("max idempotence", e)
	}
	f.s.Revision = math.MaxUint64
	next, plan, e = f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != ErrTrustState || next.Revision != math.MaxUint64 || plan != (resolver.Plan{}) {
		t.Fatal("overflow", e)
	}
	for after := 0; after < 7; after++ {
		f := newConnectionFixture(t)
		f.slot(t, true)
		ctx := &cancelResolutionContext{Context: context.Background(), after: after}
		observed, p, e := f.s.ResolveCatalogConnection(ctx, f.node(), f.records)
		if e != context.Canceled || p != (resolver.Plan{}) || observed.Revision == 0 || (!reflect.DeepEqual(observed, f.s) && f.s.ValidateAdvance(observed) != nil) {
			t.Fatal("cancellation", after, e)
		}
	}
	for _, bad := range []struct {
		ctx     context.Context
		node    uuid.UUID
		records CatalogConnectionRecords
	}{{nil, f.node(), f.records}, {context.Background(), uuid.Nil, f.records}, {context.Background(), f.node(), CatalogConnectionRecords{}}} {
		if _, _, e := f.s.ResolveCatalogConnection(bad.ctx, bad.node, bad.records); e != ErrConfiguration {
			t.Fatal(e)
		}
	}
	invalid := f.s
	invalid.Account = nil
	if _, _, e := invalid.ResolveCatalogConnection(context.Background(), f.node(), f.records); e != ErrTrustState {
		t.Fatal(e)
	}
}

func TestResolveCatalogConnectionCurrentAuthorConsistency(t *testing.T) {
	for _, mode := range []string{"newer", "revoked", "bad-state", "rotated-before-chain"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectionFixture(t)
			a := f.records.Credential.Author
			state := *a.State
			state.Sequence++
			if mode == "revoked" {
				state.Active = false
			}
			if mode == "rotated-before-chain" {
				state.Signing.Version++
				cert := *a.Certificate
				cert.Key = state.Signing
				cert.Revision++
				var e error
				cert, e = vault.SignUserKeyCertificate(cert, f.org)
				if e != nil {
					t.Fatal(e)
				}
				a.Key = state.Signing
				a.Certificate = &cert
			}
			if mode != "bad-state" {
				var e error
				state, e = vault.SignUserKeyState(state, f.org)
				if e != nil {
					t.Fatal(e)
				}
			}
			a.State = &state
			f.records.Credential.Author = a
			f.signProfile(t, f.records.Credential, 1)
			if mode == "rotated-before-chain" {
				for i := range f.records.Chain {
					f.records.Chain[i].Author = a
				}
				f.signChain(t)
				f.records.Override = f.selection(t, sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID})
			}
			next, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
			want := error(ErrTreeSnapshotChanged)
			switch mode {
			case "revoked":
				want = vault.ErrPolicy
			case "bad-state", "rotated-before-chain":
				want = vault.ErrAuthentication
			}
			if e != want || plan != (resolver.Plan{}) || next.Revision != f.s.Revision+1 || f.s.ValidateAdvance(next) != nil {
				t.Fatal("author consistency", e)
			}
			if mode != "bad-state" && next.Account.Sequence != state.Sequence {
				t.Fatal("new state lost")
			}
			if mode == "revoked" && next.Account.Active {
				t.Fatal("revocation lost")
			}
		})
	}
}

func TestResolveCatalogConnectionPersistsPartialFailure(t *testing.T) {
	f := newConnectionFixture(t)
	f.slot(t, true)
	f.records.Credential.Credential.Seal.Signature = make([]byte, 64)
	observed, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != vault.ErrAuthentication || plan != (resolver.Plan{}) || f.s.ValidateAdvance(observed) != nil {
		t.Fatal("partial failure", e)
	}
	binding := TrustBinding{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, DeviceID: f.s.DeviceID, KeyID: uuid.New(), KeyVersion: 1}
	root := make([]byte, 32)
	raw, e := SealTrustState(root, binding, observed)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := OpenTrustState(root, binding, raw, observed.Revision)
	if e != nil || !reflect.DeepEqual(restored, observed) {
		t.Fatal("durable observations", e)
	}
	f.records.SlotValue = nil
	if _, _, e = restored.ResolveCatalogConnection(context.Background(), f.node(), f.records); e != ErrAdmissionResponse {
		t.Fatal("failed release forgot assignment", e)
	}
}
