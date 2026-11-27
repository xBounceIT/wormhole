package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type resetIssuanceProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p resetIssuanceProbe) AccountResetSupported(context.Context) (bool, error) {
	p.t.Fatal("reset capability was queried on unmanaged TLS")
	return false, nil
}

func (p resetIssuanceProbe) PrepareAccountReset(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []sharedpg.Endpoint, *vault.UserKeys, string) (*sharedpg.PreparedAccountReset, error) {
	p.t.Fatal("unmanaged workspace borrowed custodian keys")
	return nil, nil
}

func (p resetIssuanceProbe) PublishAccountResetHandover(context.Context, sharedpg.TrustState, *sharedpg.PreparedAccountReset, []byte, uuid.UUID, func([]byte) error) (sharedpg.AccountResetHandover, error) {
	p.t.Fatal("reset was issued for an unmanaged workspace")
	return sharedpg.AccountResetHandover{}, nil
}

func TestSharedResetIssueRequiresCompleteFreshFactorsAndManagedTLS(t *testing.T) {
	ctx := context.Background()
	const operation = "shared-account-reset-issue"
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = resetIssuanceProbe{credentialReleaseProbe: probe, t: t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	path := filepath.Join(t.TempDir(), "reset.whreset")
	fields := func() map[string]any {
		return map[string]any{"path": path, "targetLogin": "test-user", "recipient": make([]byte, 32), "requestId": uuid.NewString(),
			"authentication": []byte(vaultInput(t, map[string]any{"vaultId": uuid.NewString(), "slotId": uuid.NewString(), "password": []byte("synthetic confirmation")}))}
	}
	for key, bad := range map[string]any{"path": "relative.whreset", "targetLogin": "", "targetUserId": "bad-id", "recipient": make([]byte, 31), "requestId": "not-uuid", "authentication": nil} {
		value := fields()
		value[key] = bad
		if raw, err := h.Handle(ctx, operation, vaultInput(t, value)); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatalf("invalid %s reached the issue operation: %v", key, err)
		}
	}
	value := fields()
	value["suspension"] = "5"
	if raw, err := h.Handle(ctx, operation, vaultInput(t, value)); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("an unbound suspension reached the native issuer", err)
	}
	target := uuid.New()
	value["targetUserId"] = target.String()
	for _, bad := range []any{nil, 5, "0", "05", "9223372036854775808"} {
		value["suspension"] = bad
		if raw, err := h.Handle(ctx, operation, vaultInput(t, value)); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("an invalid suspension reached the native issuer", err)
		}
	}
	value["suspension"] = "5"
	scoped, err := decodeSharedAccountResetIssue(vaultInput(t, value))
	scoped.auth.wipe()
	if err != nil || scoped.targetID != target || scoped.suspension != 5 {
		t.Fatal("the native issuer lost its suspension scope", err)
	}
	valid := vaultInput(t, fields())
	locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if raw, err := locked.Handle(ctx, operation, valid); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("locked workspace accepted account reset", err)
	}
	raw, err := h.Handle(ctx, operation, valid)
	var result sharedAccountResetIssueReply
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Status != "unavailable" || result.Handover != nil || !controller.Unlocked() {
		t.Fatal("unmanaged attempt affected the active workspace", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unmanaged workspace saved a reset file", err)
	}
	controller.session = probe
	if _, err := h.Handle(ctx, operation, valid); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("missing issuer session was not retired", err)
	}
	if !h.ExitOnCancel(operation) || !h.ExitOnCancel("shared-account-reset-redeem") {
		t.Fatal("interrupted reset can retain its native service")
	}
}

type resetQueueProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p resetQueueProbe) AccountResetTargetsSupported(context.Context) (bool, error) {
	p.t.Fatal("unmanaged reset queue queried PostgreSQL")
	return false, nil
}

func (p resetQueueProbe) ReadAccountResetTargets(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID) (sharedpg.AccountResetTargets, error) {
	p.t.Fatal("unmanaged reset queue requested account metadata")
	return sharedpg.AccountResetTargets{}, nil
}

func (p resetQueueProbe) MarkAccountResetHandover(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, uuid.UUID, uuid.UUID) (string, error) {
	p.t.Fatal("unmanaged workspace acknowledged handover")
	return "", nil
}

func TestSharedResetQueueRequiresTrustedOwnerAndBoundedRequests(t *testing.T) {
	const targets = "shared-account-reset-targets"
	const mark = "shared-account-reset-mark-handover"
	ctx := context.Background()
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = resetQueueProbe{credentialReleaseProbe: probe, t: t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	bad := [][]byte{[]byte(`{"after":""}`), []byte(`{"after":null}`), []byte(`{"avoid":true}`), make([]byte, 1025)}
	for _, payload := range bad {
		if raw, err := h.Handle(ctx, targets, payload); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("malformed reset queue request reached the workspace", err)
		}
		if raw, err := h.Handle(ctx, mark, payload); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("malformed handover reached the workspace", err)
		}
	}
	if raw, err := h.sharedAccountResetQueue(ctx, "other", nil); raw != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("unknown action reached queue operations", err)
	}
	for _, payload := range [][]byte{nil, []byte("{}"), vaultInput(t, map[string]any{"after": uuid.NewString()})} {
		if raw, err := h.Handle(ctx, targets, payload); err != nil || string(raw) != `{"status":"unavailable"}` {
			t.Fatal("unmanaged queue should return no account metadata", err)
		}
	}
	identity := vaultInput(t, map[string]any{"userId": uuid.NewString(), "offerId": uuid.NewString()})
	if raw, err := h.Handle(ctx, mark, identity); err != nil || string(raw) != `{"status":"unavailable"}` {
		t.Fatal("unmanaged queue should not accept a handover", err)
	}
	locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if _, err := locked.Handle(ctx, targets, nil); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("locked workspace could request its queue", err)
	}
	controller.session = probe
	if _, err := h.Handle(ctx, targets, nil); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("an incomplete owner did not retire", err)
	}
}
