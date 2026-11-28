package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedCatalogChanges(t *testing.T) {
	for _, mode := range []string{"success", "reset", "nil", "source-error", "revoked", "rotated", "anchor-error", "epoch", "sequence", "reset-nodes", "duplicate", "zero-id", "unchanged-nodes", "too-many", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, org := catalogControllerFixture(t)
			initial := c.trustRevision
			calls := 0
			id := uuid.New()
			p.changes = func(ctx context.Context, e, s uint64) (*sharedpg.CatalogChanges, error) {
				calls++
				if e != 1 || s != 8 {
					t.Fatal("cursor changed")
				}
				r := &sharedpg.CatalogChanges{Epoch: 1, ChangeSeq: 9, Nodes: []uuid.UUID{id}}
				switch mode {
				case "nil":
					return nil, nil
				case "source-error":
					return nil, sharedpg.ErrChangeInProgress
				case "reset":
					r.Reset = true
					r.Nodes = nil
				case "epoch":
					r.Epoch = 0
				case "sequence":
					r.ChangeSeq = 7
				case "reset-nodes":
					r.Reset = true
				case "duplicate":
					r.Nodes = append(r.Nodes, id)
				case "zero-id":
					r.Nodes[0] = uuid.Nil
				case "unchanged-nodes":
					r.ChangeSeq = 8
				case "too-many":
					r.Nodes = make([]uuid.UUID, 33)
				case "cancel":
					c.cancel()
					<-ctx.Done()
				}
				return r, nil
			}
			if mode == "revoked" || mode == "rotated" {
				state := *account.State
				state.Sequence++
				if mode == "revoked" {
					state.Active = false
				} else {
					state.Signing.ID = uuid.New()
				}
				state, _ = vault.SignUserKeyState(state, org)
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return &state, nil }
			}
			if mode == "anchor-error" {
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return errors.New("anchor")
				}
			}
			result, err := c.CatalogChanges(context.Background(), 1, 8)
			if mode == "success" || mode == "reset" {
				if err != nil || result == nil || !c.Unlocked() || result.ChangeSeq != 9 {
					t.Fatal(result, err)
				}
				if result.Reset != (mode == "reset") {
					t.Fatal("reset")
				}
			} else if err == nil || result != nil || c.Unlocked() {
				t.Fatal("unsafe result", result, err)
			}
			if mode == "revoked" || mode == "rotated" {
				if calls != 0 {
					t.Fatal("queried after invalid account")
				}
				stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
				if err != nil || stored.Account.Sequence != account.State.Sequence+1 {
					t.Fatal("observation not durable", err)
				}
			}
		})
	}
}

func TestSharedCatalogChangesValidation(t *testing.T) {
	c, p, _, _, _, _ := catalogControllerFixture(t)
	if _, err := c.CatalogChanges(nil, 0, 0); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	for _, v := range [][2]uint64{{0, 1}, {1 << 63, 0}, {1, 1 << 63}} {
		if _, err := c.CatalogChanges(context.Background(), v[0], v[1]); err != sharedpg.ErrConfiguration {
			t.Fatal(err)
		}
	}
	c.session = p.sharedAdmissionProbe
	if _, err := c.CatalogChanges(context.Background(), 0, 0); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	c.session = p
	c.unlocked.Store(false)
	if _, err := c.CatalogChanges(context.Background(), 0, 0); err != sharedpg.ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestSharedCatalogChangesConcurrentClose(t *testing.T) {
	c, p, _, _, _, _ := catalogControllerFixture(t)
	entered := make(chan struct{})
	p.changes = func(ctx context.Context, _, _ uint64) (*sharedpg.CatalogChanges, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	finished := make(chan error, 1)
	go func() {
		r, err := c.CatalogChanges(context.Background(), 0, 0)
		if r != nil {
			err = errors.New("late result")
		}
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("owner retained")
	}
	if c.root != nil || c.privateKeys != nil {
		t.Fatal("secrets retained")
	}
}
