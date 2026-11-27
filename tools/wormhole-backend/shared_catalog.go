package main

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type sharedCatalogSession interface {
	TreePage(context.Context, sharedpg.TreeCursor, int) (*sharedpg.UnverifiedTreePage, error)
	NodeAuthor(context.Context, uuid.UUID, uint64, uint64) (*sharedpg.UnverifiedNodeAuthor, error)
}

// Only display metadata, never an effective credential or a secret capability.
type sharedCatalogPage struct {
	Epoch, ChangeSeq uint64
	Nodes            []sharedCatalogNode
	Next             *sharedpg.TreeCursor
}

type sharedCatalogNode struct {
	vaultstore.NodeMetadata
	CanUse        bool   // Public presentation hint; planning/release independently authorize Use.
	NotesRevision uint64 // Zero if the server cannot serve imported notes.
	EditRevision  uint64 // Selection hint. The write transaction checks current access.
	GrantRevision uint64 // Advisory selection hint. The database repeats the Manage check.
	GrantBoundary uuid.UUID
}

// CatalogPage authenticates and durably records a complete page before exposing
// metadata. Any failed read retires this owner; retry through fresh admission.
func (c *sharedAdmissionController) CatalogPage(ctx context.Context, cursor sharedpg.TreeCursor, limit int) (result *sharedCatalogPage, err error) {
	if ctx == nil || limit < 1 || limit > sharedpg.MaxTreePage || cursor.Epoch > math.MaxInt64 || cursor.ChangeSeq > math.MaxInt64 ||
		(cursor.After == uuid.Nil && (cursor.Epoch != 0 || cursor.ChangeSeq != 0)) || (cursor.After != uuid.Nil && cursor.Epoch == 0) {
		return nil, sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedCatalogSession)
	if !ok {
		return nil, sharedpg.ErrConfiguration
	}
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		page, e := session.TreePage(ctx, cursor, limit)
		if e != nil {
			return e
		}
		if page == nil || len(page.Nodes) > limit {
			return sharedpg.ErrAdmissionResponse
		}
		result = &sharedCatalogPage{Epoch: page.Epoch, ChangeSeq: page.ChangeSeq, Next: page.Next}
		notesSupported, notesChecked := false, false
		editSupported, editChecked := false, false
		for _, node := range page.Nodes {
			if e := ctx.Err(); e != nil {
				return e
			}
			id, e := uuid.Parse(node.Metadata.ID)
			if e != nil || node.Permissions&permissions.View == 0 {
				return sharedpg.ErrAdmissionResponse
			}
			author, e := session.NodeAuthor(ctx, id, page.Epoch, page.ChangeSeq)
			if e != nil {
				return e
			}
			if author == nil {
				return sharedpg.ErrAdmissionResponse
			}
			next, e := pending.AdvanceCatalog(node, *author)
			if next.Revision != 0 {
				*pending = next
			}
			if e != nil {
				return e
			}
			if pending.Account.Signing != current.Account.Signing || pending.Account.Encryption != current.Account.Encryption {
				return vault.ErrAuthentication
			}
			public := sharedCatalogNode{NodeMetadata: node.Metadata, CanUse: node.Metadata.Kind == 1 && node.Permissions&permissions.Use != 0}
			if node.Permissions&permissions.Write != 0 && node.Seal.Revision < math.MaxInt64 {
				if edits, ok := session.(sharedNodeEditSession); ok && !editChecked {
					editChecked = true
					editSupported, e = edits.NodeEditingSupported(ctx)
					if e != nil {
						return e
					}
				}
				if editSupported {
					public.EditRevision = node.Seal.Revision
				}
			}
			if node.Metadata.OwnerUserID == nil && node.Permissions&permissions.Manage != 0 {
				public.GrantRevision = node.Seal.Revision
				public.GrantBoundary = node.Boundary
			}
			if node.Metadata.Imported != nil {
				if notes, ok := session.(sharedNoteViewSession); ok && !notesChecked {
					notesChecked = true
					notesSupported, e = notes.NoteViewSupported(ctx)
					if e != nil {
						return e
					}
				}
				if notesSupported {
					public.NotesRevision = node.Seal.Revision
				}
			}
			result.Nodes = append(result.Nodes, public)
		}
		return nil
	}, func(ctx context.Context, _ sharedpg.TrustState) error {
		return c.reconcileVisibleWebArchives(ctx, cursor, result)
	}, true)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *sharedAdmissionController) withCatalogTrust(ctx context.Context, read func(context.Context, sharedpg.TrustState, *sharedpg.TrustState) error) (err error) {
	return c.withCatalogOperation(ctx, read, nil, true)
}

// The optional use stage runs only after both the trust file and its startup
// anchor have committed, while the same gate/lifetime still protects native keys.
// Release graphs carry their own current account state; metadata reads fetch it.
func (c *sharedAdmissionController) withCatalogOperation(ctx context.Context, read func(context.Context, sharedpg.TrustState, *sharedpg.TrustState) error, use func(context.Context, sharedpg.TrustState) error, freshAccount bool) (err error) {
	if ctx == nil || read == nil {
		return sharedpg.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if !c.Unlocked() || c.root == nil || c.privateKeys == nil {
		return sharedpg.ErrSessionClosed
	}
	defer func() {
		fault := recover()
		if err != nil || fault != nil {
			c.cancel()
			c.admitted.Store(false)
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if c.closeLocked(cleanup) != nil {
				err = errSharedAdmissionCleanup
			}
		}
		if fault != nil {
			panic(fault)
		}
	}()
	var current sharedpg.TrustState
	err = c.root.With(func(root []byte) error {
		var e error
		current, e = readSharedTrustFile(c.trustPath, root, c.trustBinding, c.trustRevision)
		return e
	})
	if err != nil {
		return err
	}
	if current.Revision != c.trustRevision {
		return errSharedTrustConflict
	}
	if current.Account == nil || !current.Account.Active {
		return vault.ErrPolicy
	}
	if c.tlsManaged {
		if err := c.refreshTLSLocked(ctx, sharedAdmissionOptions{TrustPath: c.trustPath, Binding: c.trustBinding}, current); err != nil {
			return err
		}
	}
	pending := current
	// Retain authentic observations on every failure, including cancellation and
	// revocation. Persist once per read, with a single local CAS revision.
	defer func() {
		fault := recover()
		defer func() {
			if fault != nil {
				panic(fault)
			}
		}()
		if pending.Revision != current.Revision {
			if current.Revision == math.MaxUint64 {
				err = sharedpg.ErrTrustState
				return
			}
			pending.Revision = current.Revision + 1
		}
		if e := c.commitCatalogTrust(current, pending); e != nil {
			err = e
			return
		}
		if err == nil && fault == nil {
			if e := ctx.Err(); e != nil {
				err = e
			} else if !c.Unlocked() {
				err = sharedpg.ErrSessionClosed
			} else if use != nil {
				err = use(ctx, pending)
			}
		}
	}()
	if !freshAccount {
		return read(ctx, current, &pending)
	}
	state, e := c.session.AccountKeyState(ctx)
	if e != nil {
		return e
	}
	if state == nil {
		return sharedpg.ErrAdmissionResponse
	}
	pending, e = current.AdvanceAccount(*state, current.WrappingRevision)
	if e != nil {
		pending = current
		return e
	}
	if !state.Active {
		return vault.ErrPolicy
	}
	if state.Signing != current.Account.Signing || state.Encryption != current.Account.Encryption {
		return vault.ErrAuthentication
	}
	return read(ctx, current, &pending)
}

func (c *sharedAdmissionController) commitCatalogTrust(current, next sharedpg.TrustState) error {
	if _, err := c.persistAccountTrust(current, next); err != nil {
		return err
	}
	return c.checkpointCatalogTrust(next)
}

func (c *sharedAdmissionController) checkpointCatalogTrust(next sharedpg.TrustState) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.root.With(func(root []byte) error {
		refresh := c.catalogAnchor
		if refresh == nil {
			refresh = func(ctx context.Context, path string, key []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
				_, err := refreshSharedCatalogAnchor(ctx, path, key, binding, trust, nativeSharedStartupProtection())
				return err
			}
		}
		err := refresh(ctx, c.trustPath, root, c.trustBinding, next)
		if errors.Is(err, errSharedTrustCommitUncertain) {
			err = refresh(ctx, c.trustPath, root, c.trustBinding, next)
		}
		return err
	})
}
