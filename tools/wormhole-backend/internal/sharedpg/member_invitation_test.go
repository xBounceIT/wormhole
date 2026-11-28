package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresMemberInvitation(t *testing.T) {
	database, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dba, err := Connect(ctx, database, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(dba)
	workspace := uuid.New()
	const tag = "memberscope"
	if _, err := DeploySchema(ctx, database, password, tag, workspace.String()); err != nil {
		t.Fatal(err)
	}
	rls := "BEGIN; SET LOCAL ROLE wh_" + tag + "_owner; SELECT wormhole_data.set_row_security('" + workspace.String() + "',true); COMMIT"
	if _, err := dba.Exec(ctx, rls).ReadAll(); err != nil {
		t.Fatal("enable row security for member enrollment", err)
	}
	first, factors, err := prepareWorkspaceBootstrapFromDeployment(ctx, database, password, workspace, tag, "admin", vault.Standard, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer factors.wipe()
	if _, err := publishWorkspaceBootstrap(ctx, first, database.DeviceRole, password, factors.invitationCode[:]); err != nil {
		t.Fatal(err)
	}
	ask := bytes.Repeat([]byte{45}, 32)
	defer vault.Wipe(ask)
	joinTestAdministrator(t, ctx, first.invitation, factors.invitationCode[:], first.organisation.Signing, first.recovery.Signing, ask, nil,
		func(admin *Session, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) {
			settings := Settings{Endpoints: database.Endpoints, Database: database.Database, TLS: TLSVerified, TLSBundle: tls,
				DeviceRole: "wh_" + tag + "_d_" + trust.DeviceID.String()}
			draft, err := admin.prepareNewMember(ctx, trust, settings, keys, "operator", "Operations member")
			if err != nil || draft == nil {
				t.Fatal("prepare member", err)
			}
			defer draft.close()
			concurrent, err := admin.prepareNewMember(ctx, trust, settings, keys, "operator", "Other display name")
			if err != nil {
				t.Fatal(err)
			}
			defer concurrent.close()
			var publication memberInvitationPublication
			if err := json.Unmarshal(draft.publication, &publication); err != nil {
				t.Fatal(err)
			}
			manifest, err := vault.DecodeInviteManifest(publication.Manifest)
			if err != nil || len(manifest.Issuers) != 0 || len(manifest.Copies) != 0 {
				t.Fatal("ungrouped member received workspace key copies", err)
			}
			if err := admin.publishNewMember(ctx, trust, draft); !errors.Is(err, ErrAccountResetLogging) {
				t.Fatal("publication with parameter logging", err)
			}
			device := pgx.Identifier{settings.DeviceRole}.Sanitize()
			if _, err := dba.Exec(ctx, "GRANT SET ON PARAMETER log_parameter_max_length TO "+device).ReadAll(); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Query(ctx, "SET log_parameter_max_length=0", nil); err != nil {
				t.Fatal(err)
			}
			request := MemberInvitationRequest{Login: "teammate", RequestID: uuid.New(), Recipient: make([]byte, 32)}
			if handover, err := admin.IssueMemberInvitation(ctx, trust, settings, keys, request); !errors.Is(err, ErrMemberInvitationRecipient) || handover.Token != "" {
				t.Fatal("issuing to an invalid protected window", err)
			}
			recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			request.Recipient = recipient.PublicKey().Bytes()
			handover, err := admin.IssueMemberInvitation(ctx, trust, settings, keys, request)
			if err != nil || handover.WorkspaceID != workspace || handover.RequestID != request.RequestID || len(handover.Bundle.Ciphertext) != vault.InviteCodeBytes+16 {
				t.Fatal("protected invitation delivery", err)
			}
			document, err := DecodeInvitation(handover.Token, time.Now())
			if err != nil || document.LoginName != "teammate" || document.Enrollment.Context.InviteID != handover.InviteID {
				t.Fatal("delivered public document did not match its member", err)
			}
			for range 2 {
				if err := admin.publishNewMember(ctx, trust, draft); err != nil {
					t.Fatal("publish or reconcile member invitation", err)
				}
			}
			if err := admin.publishNewMember(ctx, trust, concurrent); !errors.Is(err, ErrAccountRevision) {
				t.Fatal("competing publication changed the existing member", err)
			}
			if other, err := admin.prepareNewMember(ctx, trust, settings, keys, "operator", "Another member"); !errors.Is(err, ErrAccountRevision) || other != nil {
				t.Fatal("duplicate initial issuance", err)
			}
			if err := draft.code.With(func(code []byte) error {
				joinConfirmedTestAccount(t, ctx, draft.invitation, code, first.organisation.Signing, first.recovery.Signing, ask, false,
					func(member *Session, _ *AccountMaster, _ *UnverifiedAccountKeys, _ TrustState, _ *VerifiedTLSBundle) error {
						page, err := member.AdminInventory(ctx, AdminInventoryRequest{Kind: "invitations"})
						if err != nil || page != nil {
							t.Fatal("regular member received admin invitation inventory", err)
						}
						return nil
					})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := admin.publishNewMember(ctx, trust, draft); !errors.Is(err, ErrAccountRevision) {
				t.Fatal("repeated issuance of a redeemed invite", err)
			}
			page, err := admin.AdminInventory(ctx, AdminInventoryRequest{Kind: "invitations"})
			if err != nil || page == nil {
				t.Fatal("member invitation inventory unavailable", err)
			}
			for _, item := range page.Entries {
				if item.ID == draft.invitation.Enrollment.Context.InviteID && item.Login == "operator" && item.Name == "Operations member" && item.Status == "active" {
					return
				}
			}
			t.Fatal("confirmed ordinary member missing from invitation inventory")
		})
}
