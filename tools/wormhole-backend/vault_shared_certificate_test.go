package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type certificateRenewalProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p certificateRenewalProbe) RenewServerCertificate(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte, time.Time) ([]byte, error) {
	p.t.Fatal("borrowed certificate material on an unmanaged transport")
	return nil, sharedpg.ErrConfiguration
}

func TestVaultCertificateRenewalRejectsMalformedOrUnownedRequests(t *testing.T) {
	ctx := context.Background()
	const operation = "shared-renew-server-certificate"
	payload := []byte(`{"csr":"public"}`)
	controller, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	for _, input := range [][]byte{
		nil, []byte(`{"csr":""}`), []byte(`{"csr":null}`), []byte(`{"csr":"a","csr":"b"}`),
		[]byte(`{"csr":"public","workspaceId":"foreign"}`),
		append(append([]byte(`{"csr":"`), bytes.Repeat([]byte{'A'}, sharedpg.MaxServerCSRBytes+1)...), []byte(`"}`)...),
		bytes.Repeat([]byte{' '}, 2*sharedpg.MaxServerCSRBytes+1),
	} {
		if _, err := h.Handle(ctx, operation, input); !errors.Is(err, vaultwire.ErrProtocol) || h.closed {
			t.Fatal("invalid input reached the admitted certificate owner", err)
		}
	}
	for _, controller := range []*sharedAdmissionController{nil, {}} {
		h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
		if controller != nil {
			h.closed = true
		}
		if _, err := h.Handle(ctx, operation, payload); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("locked or absent controller accepted a renewal", err)
		}
	}
}

func TestVaultCertificateRenewalChecksTransportAndSession(t *testing.T) {
	ctx := context.Background()
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	controller.session = certificateRenewalProbe{credentialReleaseProbe: probe, t: t}
	raw, err := h.Handle(ctx, "shared-renew-server-certificate", []byte(`{"csr":"public"}`))
	var result sharedServerCertificateResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Status != "unavailable" || result.ServerPEM != "" || !controller.Unlocked() {
		t.Fatal("unmanaged certificate request affected the shared owner", err)
	}
	controller.session = probe
	if _, err := h.Handle(ctx, "shared-renew-server-certificate", []byte(`{"csr":"public"}`)); !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, sharedpg.ErrConfiguration) {
		t.Fatal("missing renewal support did not retire the service", err)
	}
}
