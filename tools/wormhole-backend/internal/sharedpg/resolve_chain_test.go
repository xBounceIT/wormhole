package sharedpg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func resolutionChainFixture(t *testing.T) (TrustState, []UnverifiedChainRecord, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	_, _, s, leaf, author, org, key := catalogTrustFixture(t)
	s, err := s.AdvanceAccount(*author.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	parent := leaf
	parent.Metadata = vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Folder", Kind: 0}
	host, user, protocol := "server.example", "inherited-user", 0
	parent.Metadata.Host = &host
	parent.Metadata.Username = &user
	parent.Metadata.Protocol = &protocol
	leaf.Metadata.ParentID = &parent.Metadata.ID
	chain := []UnverifiedChainRecord{{leaf, author}, {parent, author}}
	signResolutionChain(t, s, chain, key)
	return s, chain, org, key
}
func signResolutionChain(t *testing.T, s TrustState, chain []UnverifiedChainRecord, key ed25519.PrivateKey) {
	t.Helper()
	for i := range chain {
		revision := chain[i].Node.Seal.Revision
		if revision == 0 {
			revision = 1
		}
		seal, err := sharedcatalog.SignNode(s.WorkspaceID, chain[i].Node.Boundary, chain[i].Node.Metadata, revision, chain[i].Author.Key, key)
		if err != nil {
			t.Fatal(err)
		}
		chain[i].Node.Seal = seal
	}
}
func TestResolveCatalogChain(t *testing.T) {
	s, chain, _, key := resolutionChainFixture(t)
	id := uuid.MustParse(chain[0].Node.Metadata.ID)
	next, plan, err := s.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != nil || plan.Host != "server.example" || plan.Username != "inherited-user" || plan.Port != 22 || plan.NodeID != id.String() {
		t.Fatal("resolution", err)
	}
	if s.Catalog != nil || next.Revision <= s.Revision {
		t.Fatal("trust alias/advance")
	}
	if err := s.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	repeated, again, err := next.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != nil || !reflect.DeepEqual(repeated, next) || again != plan {
		t.Fatal("repeat", err)
	}
	override := uuid.NewString()
	_, over, err := next.ResolveCatalogChain(context.Background(), id, chain, override)
	if err != nil || over.Credential.Kind != "override" || over.Credential.ID != override || over.Username != "" {
		t.Fatal("override", err)
	}
	changed := "new.example"
	chain[1].Node.Metadata.Host = &changed
	chain[1].Node.Seal.Revision++
	signResolutionChain(t, s, chain, key)
	newest, newPlan, err := next.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != nil || newPlan.Host != changed {
		t.Fatal("ancestor update", err)
	}
	chain[1].Node.Seal.Revision--
	signResolutionChain(t, s, chain, key)
	observed, denied, err := newest.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != vault.ErrRollback || denied != (resolver.Plan{}) || observed.Revision == 0 {
		t.Fatal("ancestor rollback", err)
	}
}
func TestResolveCatalogChainRejectsUnauthenticatedAndIncomplete(t *testing.T) {
	for _, mode := range []string{"leaf-host", "parent-host", "parent-link", "boundary", "signature", "certificate", "missing-state", "truncate", "reverse", "cycle", "duplicate", "ancestor-kind", "override", "target"} {
		t.Run(mode, func(t *testing.T) {
			s, chain, _, key := resolutionChainFixture(t)
			id := uuid.MustParse(chain[0].Node.Metadata.ID)
			override := ""
			attacker := "attacker.example"
			switch mode {
			case "leaf-host":
				chain[0].Node.Metadata.Host = &attacker
			case "parent-host":
				chain[1].Node.Metadata.Host = &attacker
			case "parent-link":
				chain[0].Node.Metadata.ParentID = nil
			case "boundary":
				chain[1].Node.Boundary = uuid.New()
			case "signature":
				chain[1].Node.Seal.Signature[0] ^= 1
			case "certificate":
				chain[1].Author.Certificate = nil
			case "missing-state":
				chain[1].Author.State = nil
			case "truncate":
				chain = chain[:1]
			case "reverse":
				chain[0], chain[1] = chain[1], chain[0]
			case "cycle":
				chain[1].Node.Metadata.ParentID = &chain[0].Node.Metadata.ID
				signResolutionChain(t, s, chain, key)
			case "duplicate":
				chain = append(chain, chain[1])
			case "ancestor-kind":
				chain[1].Node.Metadata.Kind = 1
				signResolutionChain(t, s, chain, key)
			case "override":
				override = "bad-id"
			case "target":
				chain[1].Node.Metadata.Host = nil
				signResolutionChain(t, s, chain, key)
			}
			_, plan, err := s.ResolveCatalogChain(context.Background(), id, chain, override)
			if err == nil || plan != (resolver.Plan{}) {
				t.Fatal("unsafe plan", err)
			}
		})
	}
}
func TestResolveCatalogChainPreservesStateObservations(t *testing.T) {
	for _, mode := range []string{"revoked", "inconsistent", "rotated", "bad-second"} {
		t.Run(mode, func(t *testing.T) {
			s, chain, org, _ := resolutionChainFixture(t)
			id := uuid.MustParse(chain[0].Node.Metadata.ID)
			state := *chain[1].Author.State
			state.Sequence++
			if mode == "revoked" {
				state.Active = false
			}
			if mode == "rotated" {
				state.Encryption.Version++
			}
			state, err := vault.SignUserKeyState(state, org)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "rotated" {
				chain[0].Author.State = &state
			}
			chain[1].Author.State = &state
			if mode == "bad-second" {
				chain[1].Node.Seal.Signature[0] ^= 1
			}
			next, plan, err := s.ResolveCatalogChain(context.Background(), id, chain, "")
			if err == nil || plan != (resolver.Plan{}) || next.Revision <= s.Revision || next.Account.Sequence != state.Sequence {
				t.Fatal("lost authenticated observation", err)
			}
			if mode == "revoked" && next.Account.Active {
				t.Fatal("lost revocation")
			}
			if mode == "inconsistent" && err != ErrTreeSnapshotChanged {
				t.Fatal(err)
			}
			if mode == "rotated" && err != vault.ErrAuthentication {
				t.Fatal(err)
			}
			if err := s.ValidateAdvance(next); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestResolveCatalogChainBoundaries(t *testing.T) {
	s, chain, _, _ := resolutionChainFixture(t)
	id := uuid.MustParse(chain[0].Node.Metadata.ID)
	for _, v := range []struct {
		ctx   context.Context
		id    uuid.UUID
		chain []UnverifiedChainRecord
	}{{nil, id, chain}, {context.Background(), uuid.Nil, chain}, {context.Background(), id, nil}, {context.Background(), id, make([]UnverifiedChainRecord, vaultstore.MaxNodeDepth+1)}} {
		if _, _, err := s.ResolveCatalogChain(v.ctx, v.id, v.chain, ""); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	for _, bad := range []TrustState{{}, func() TrustState { v := cloneTrustState(s); v.Account = nil; return v }()} {
		if _, _, err := bad.ResolveCatalogChain(context.Background(), id, chain, ""); err != ErrTrustState {
			t.Fatal(err)
		}
	}
	if _, _, err := s.ResolveCatalogChain(context.Background(), uuid.New(), chain, ""); err != ErrAdmissionResponse {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ResolveCatalogChain(ctx, id, chain, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResolveCatalogChainRevisionLimit(t *testing.T) {
	s, chain, _, _ := resolutionChainFixture(t)
	id := uuid.MustParse(chain[0].Node.Metadata.ID)
	s.Revision = math.MaxUint64 - 1
	next, plan, err := s.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != nil || next.Revision != math.MaxUint64 || plan.NodeID != id.String() {
		t.Fatal("one remaining revision must fit whole chain", err)
	}
	if err := s.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	s.Revision = math.MaxUint64
	failed, plan, err := s.ResolveCatalogChain(context.Background(), id, chain, "")
	if err != ErrTrustState || failed.Revision != s.Revision || plan != (resolver.Plan{}) {
		t.Fatal("revision overflow", err)
	}
}

type cancelResolutionContext struct {
	context.Context
	checks int
	after  int
}

func (c *cancelResolutionContext) Err() error {
	c.checks++
	if c.checks > c.after {
		return context.Canceled
	}
	return nil
}
func TestResolveCatalogChainCancellationPreservesFloors(t *testing.T) {
	for _, after := range []int{1, 2} {
		s, chain, _, _ := resolutionChainFixture(t)
		id := uuid.MustParse(chain[0].Node.Metadata.ID)
		ctx := &cancelResolutionContext{Context: context.Background(), after: after}
		next, plan, err := s.ResolveCatalogChain(ctx, id, chain, "")
		if err != context.Canceled || plan != (resolver.Plan{}) || next.Revision != s.Revision+1 {
			t.Fatal("canceled observation", err)
		}
		if err := s.ValidateAdvance(next); err != nil {
			t.Fatal(err)
		}
	}
}
