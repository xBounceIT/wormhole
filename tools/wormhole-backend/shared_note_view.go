package main

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var errSharedNoteUnavailable = errors.New("shared node note unavailable")

type sharedNoteViewSession interface {
	NoteViewSupported(context.Context) (bool, error)
	BeginNoteView(context.Context, uuid.UUID, uint64) (*sharedpg.NoteViewIntent, error)
	FetchNote(context.Context, *sharedpg.NoteViewIntent) (*sharedpg.UnverifiedNoteView, error)
}

func (c *sharedAdmissionController) sealNodeNotes(ctx context.Context, node uuid.UUID, request string, revision uint64, key []byte) (localvault.NotesDisplay, error) {
	session, ok := c.session.(sharedNoteViewSession)
	if !ok || ctx == nil || node == uuid.Nil || !vaultCredentialID(request) || revision == 0 || len(key) != 32 {
		return localvault.NotesDisplay{}, sharedpg.ErrConfiguration
	}
	var result localvault.NotesDisplay
	var view *sharedpg.VerifiedNoteView
	unavailable := false
	err := c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		supported, err := session.NoteViewSupported(ctx)
		if err != nil || !supported {
			unavailable = !supported
			return err
		}
		intent, err := session.BeginNoteView(ctx, node, revision)
		if err != nil || intent == nil {
			unavailable = intent == nil
			return err
		}
		graph, err := session.FetchNote(ctx, intent)
		if err != nil {
			return err
		}
		next, prepared, err := current.VerifyNoteView(ctx, node, revision, graph)
		if next.Revision != 0 {
			*pending = next
		}
		view = prepared
		return err
	}, func(ctx context.Context, committed sharedpg.TrustState) error {
		if unavailable {
			return nil
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrTrustState
			}
			return view.WithValue(ctx, committed, keys[:32], func(note []byte) error {
				if !localvault.ValidNodeNotes(note) {
					return vault.ErrFormat
				}
				workspace := committed.WorkspaceID.String()
				bundle, err := vault.SealNotesDisplay(key, workspace, node.String(), request, revision, note)
				if err == nil {
					result = localvault.NotesDisplay{WorkspaceID: workspace, NodeID: node.String(), RequestID: request,
						RowVersion: strconv.FormatUint(revision, 10), Bundle: bundle}
				}
				return err
			})
		})
	}, false)
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.NotesDisplay{}, err
	}
	if unavailable {
		return localvault.NotesDisplay{}, errSharedNoteUnavailable
	}
	return result, nil
}
