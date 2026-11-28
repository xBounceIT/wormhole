package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestAccountResetHandoverStagesBeforeSQLAndReleasesOnlyAfterConfirmation(t *testing.T) {
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"confirmed", "save-failed", "unsupported-recipient", "already-cancelled", "cancel-after-save", "preflight-failed", "publish-failed", "unconfirmed", "cancel-after-publish", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secret, err := securemem.New(vault.InviteCodeBytes+32, false)
			if err != nil {
				t.Fatal(err)
			}
			p := &PreparedAccountReset{factors: secret, document: []byte("synthetic signed offer"),
				offer: accountResetOffer{WorkspaceID: uuid.New(), ID: uuid.New(),
					Subject: accountResetSubject{LoginName: "reset-test"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}}
			defer p.Close()
			request := uuid.New()
			pub := recipient.PublicKey().Bytes()
			if mode == "already-cancelled" {
				cancel()
			}
			if mode == "expired" {
				p.offer.ExpiresAt = time.Now().Add(-time.Hour).Unix()
			}
			if mode == "unsupported-recipient" {
				pub = make([]byte, 32)
			}
			saved, dispatched := false, false
			result, err := p.publishHandover(ctx, pub, request, func(file []byte) error {
				saved = true
				if !bytes.Equal(file, p.document) {
					t.Fatal("the saved offer did not match the issued document")
				}
				file[0] ^= 1
				if bytes.Equal(file, p.document) {
					t.Fatal("the artifact writer unexpectedly owns the signed document")
				}
				if mode == "save-failed" {
					return errors.New("file exists")
				}
				if mode == "cancel-after-save" {
					cancel()
				}
				return nil
			}, func(stage func() error) error {
				if mode == "preflight-failed" {
					return ErrAccountResetLogging
				}
				if err := stage(); err != nil {
					return err
				}
				if !saved {
					t.Fatal("SQL publication preceded file acknowledgement")
				}
				dispatched = true
				if mode == "publish-failed" {
					return ErrAccountResetLogging
				}
				if mode != "unconfirmed" {
					p.published = true
				}
				if mode == "cancel-after-publish" {
					cancel()
				}
				return nil
			})
			if mode == "confirmed" {
				if err != nil || !p.delivered || result.OfferID != p.offer.ID || result.WorkspaceID != p.offer.WorkspaceID ||
					result.RequestID != request || len(result.Bundle.Ciphertext) != 64 {
					t.Fatal("confirmed reset handover was not emitted", err)
				}
				if err := p.BorrowHandover(func(_, _, _ []byte) error { return nil }); !errors.Is(err, ErrAccountRecovery) {
					t.Fatal("confirmed factors could be delivered again", err)
				}
				return
			}
			want := map[string]error{"save-failed": ErrAccountResetSave, "unsupported-recipient": ErrAccountResetRecipient,
				"already-cancelled": context.Canceled, "cancel-after-save": context.Canceled, "publish-failed": ErrAccountResetLogging, "preflight-failed": ErrAccountResetLogging,
				"unconfirmed": ErrAdmissionResponse, "cancel-after-publish": context.Canceled, "expired": ErrConfiguration}[mode]
			if !errors.Is(err, want) || result.Bundle.Ciphertext != nil || p.delivered {
				t.Fatal("unconfirmed reset exposed a receipt or factors", err)
			}
			if dispatched != (mode == "publish-failed" || mode == "unconfirmed" || mode == "cancel-after-publish") {
				t.Fatal("the issue transaction ignored the publication gate")
			}
			if mode == "preflight-failed" && saved {
				t.Fatal("failed PostgreSQL preflight saved an offer")
			}
		})
	}
}
