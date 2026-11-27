package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedSetupTLSProducesOnlyPublicCertificatesAndRetiresStage(t *testing.T) {
	h, _ := sharedSetupTestHandler(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, key)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"host": "127.0.0.1", "port": 5432, "database": "vault", "approvedHosts": []string{"127.0.0.1"},
		"csr":             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"accountPassword": []byte("synthetic-stage-password"), "ask": bytes.Repeat([]byte{77}, 32),
	}
	ctx := context.Background()
	for _, malformed := range []map[string]any{
		{"path": "unexpected"}, {"ask": []byte("too short")}, {"accountPassword": []byte{}}, {"csr": ""}, {"port": -1},
	} {
		data := make(map[string]any)
		for k, v := range request {
			data[k] = v
		}
		for k, v := range malformed {
			data[k] = v
		}
		if _, err := h.Handle(ctx, "shared-setup-prepare-tls", vaultInput(t, data)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("unsafe TLS setup request accepted", err)
		}
	}
	out := setupTestCall(t, h, "prepare-tls", request)
	if out.Plan == nil || out.TLS == nil || out.Plan.Hosting != "self-hosted" {
		t.Fatal("prepared TLS plan unavailable")
	}
	path := sharedSetupPlanPath(h.databasePath)
	protection := h.startupProtection()
	sealed, err := os.ReadFile(path)
	if err != nil || bytes.Contains(sealed, []byte("synthetic-stage-password")) {
		t.Fatal("password appeared in the native plan", err)
	}
	plan, err := readSharedSetupPlan(path, protection)
	if err != nil || plan.TLS == nil || plan.TLS.Protection == nil || !bytes.Equal(plan.CAPEM, []byte(out.TLS.CAPEM)) {
		t.Fatal("protected authority did not survive the Save", err)
	}
	if _, err := h.Handle(ctx, "shared-setup-prepare-tls", vaultInput(t, request)); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("repeated request replaced prepared authority", err)
	}
	want, err := sharedAdminCheckpointScope(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := retireWorkspaceTLSDraft(path, plan, sharedStartupProtection{}); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("retirement reported success without durable storage", err)
	}
	if err := retireWorkspaceTLSDraft(path, plan, protection); err != nil {
		t.Fatal(err)
	}
	retired, err := readSharedSetupPlan(path, protection)
	if err != nil || retired.TLS == nil || retired.TLS.Protection != nil || *retired.tlsOutput() != *out.TLS {
		t.Fatal("retirement lost public certificates or retained temporary keys", err)
	}
	if after, err := sharedAdminCheckpointScope(retired); err != nil || after != want {
		t.Fatal("retirement invalidated the administrator checkpoint", err)
	}
	if err := retireWorkspaceTLSDraft(path, retired, protection); err != nil {
		t.Fatal("retirement was not idempotent", err)
	}
}
