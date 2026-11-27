package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAdminInventorySession interface {
	AdminInventorySupported(context.Context, string) (bool, error)
	AdminInventory(context.Context, sharedpg.AdminInventoryRequest) (*sharedpg.AdminInventoryPage, error)
}

type sharedAdminInventoryReply struct {
	Status string                       `json:"status"`
	Page   *sharedpg.AdminInventoryPage `json:"page,omitempty"`
}

func decodeSharedAdminInventory(raw []byte) (request sharedpg.AdminInventoryRequest, err error) {
	var cursor json.RawMessage
	if len(raw) > 512 || decodeVaultObject(raw, map[string]any{"kind": &request.Kind, "next": &cursor}, "kind") != nil {
		return request, vaultwire.ErrProtocol
	}
	if len(cursor) != 0 {
		var id, at string
		fields := map[string]any{"id": &id}
		if request.Kind == "sessions" || request.Kind == "audit" {
			fields["at"] = &at
		}
		if decodeVaultObject(cursor, fields, "id") != nil || !vaultCredentialID(id) {
			return request, vaultwire.ErrProtocol
		}
		request.Next = &sharedpg.AdminInventoryCursor{ID: uuid.MustParse(id), At: at}
	}
	if !request.Valid() {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func (h *vaultFoundationHandler) sharedAdminInventory(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, err := decodeSharedAdminInventory(raw)
	if err != nil {
		return nil, err
	}
	reply := sharedAdminInventoryReply{Status: "unavailable"}
	err = h.withVerifiedSharedRuntime(ctx, func(ctx context.Context, native sharedAdmissionSession, _ sharedpg.TrustState, runtime sharedRuntimeSnapshot) error {
		if request.Kind != "my-devices" && !runtime.Administrator {
			return nil
		}
		session, ok := native.(sharedAdminInventorySession)
		if !ok {
			return sharedpg.ErrConfiguration
		}
		supported, err := session.AdminInventorySupported(ctx, request.Kind)
		if err != nil {
			return err
		}
		if !supported {
			reply.Status = "unsupported"
			return nil
		}
		page, err := session.AdminInventory(ctx, request)
		if page != nil {
			reply = sharedAdminInventoryReply{Status: "ready", Page: page}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}

func (h *vaultFoundationHandler) withSharedAdministration(ctx context.Context, use func(context.Context, sharedAdmissionSession, sharedpg.TrustState) error) error {
	return h.withVerifiedSharedRuntime(ctx, func(ctx context.Context, native sharedAdmissionSession, trust sharedpg.TrustState, runtime sharedRuntimeSnapshot) error {
		if !runtime.Administrator {
			return nil
		}
		return use(ctx, native, trust)
	})
}

func (h *vaultFoundationHandler) withVerifiedSharedRuntime(ctx context.Context, use func(context.Context, sharedAdmissionSession, sharedpg.TrustState, sharedRuntimeSnapshot) error) error {
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return err
	}
	session, ok := controller.session.(sharedRuntimeStateSession)
	if !ok {
		return h.retire(sharedpg.ErrConfiguration)
	}
	var runtime sharedRuntimeSnapshot
	err = controller.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		var err error
		runtime, err = controller.observeRuntime(ctx, session, current, pending)
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		if runtime.TLS != sharedpg.TLSVerified {
			return nil
		}
		return use(ctx, controller.session, trust, runtime)
	}, false)
	if err != nil {
		return h.retire(err)
	}
	return nil
}
