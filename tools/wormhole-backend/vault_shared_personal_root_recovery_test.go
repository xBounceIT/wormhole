package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type personalRootRecoveryProbe struct {
	*credentialReleaseProbe
	sharedPersonalRootRecoverySession
	supported          bool
	prepared           int
	denied             bool
	needsEnrollment    bool
	canReenroll        bool
	reenrollmentChecks int
}

func (p *personalRootRecoveryProbe) PersonalRootRecoverySupported(context.Context) (bool, error) {
	return p.supported, nil
}

func (p *personalRootRecoveryProbe) AccountReenrollmentSupported(context.Context) (bool, error) {
	p.reenrollmentChecks++
	return p.canReenroll, nil
}

func (p *personalRootRecoveryProbe) PreparePersonalRootRecovery(_ context.Context, trust sharedpg.TrustState, _ *sharedpg.VerifiedTLSBundle,
	request sharedpg.PersonalRootRecoveryRequest) (sharedpg.TrustState, sharedpg.PersonalRootRecoveryReply, *sharedpg.PersonalRootRecoveryPreparation, error) {
	p.prepared++
	if p.denied {
		return trust, sharedpg.PersonalRootRecoveryReply{}, nil, sharedpg.ErrServerCertificateAuthority
	}
	if request.Review != nil {
		return trust, sharedpg.PersonalRootRecoveryReply{}, nil, vault.ErrAuthentication
	}
	if p.needsEnrollment {
		return trust, sharedpg.PersonalRootRecoveryReply{Status: "enrollment-required"}, nil, nil
	}
	return trust, sharedpg.PersonalRootRecoveryReply{Status: "review"}, nil, nil
}

func (p personalRootRecoveryProbe) RuntimeState(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
	return p.credentialReleaseProbe.RuntimeState(ctx)
}

func TestSharedPersonalRootRecoveryNeedsReviewAndFreshFactors(t *testing.T) {
	account := uuid.NewString()
	base := `{"accountId":"` + account + `","suspension":"9"`
	review := `,"review":"` + strings.Repeat("ab", 32) + `"`
	password := "fixture-password"
	vault, slot := uuid.NewString(), uuid.NewString()
	factor := base64.StdEncoding.EncodeToString([]byte(`{"vaultId":"` + vault + `","slotId":"` + slot + `","password":"` +
		base64.StdEncoding.EncodeToString([]byte(password)) + `"}`))
	authentication := `,"authentication":"` + factor + `"`
	request, auth, err := decodeSharedPersonalRootRecovery([]byte(base + review + authentication + "}"))
	defer auth.wipe()
	if err != nil || request.AccountID.String() != account || request.Suspension != 9 || request.Review == nil ||
		auth.VaultID != vault || auth.SlotID != slot || string(auth.Password) != password {
		t.Fatal("confirmed recovery did not decode only its native scope and factors", err)
	}
	h := &vaultFoundationHandler{}
	for _, invalid := range []string{
		`{}`, strings.Replace(base, account, "invalid", 1) + "}", strings.Replace(base, `"9"`, `"09"`, 1) + "}",
		base + authentication + "}", base + review + "}", base + `,"review":null` + authentication + "}",
		base + review + `,"authentication":null}`, base + strings.ToUpper(review) + authentication + "}",
		base + `,"review":"` + strings.Repeat("zq", 32) + `"` + authentication + "}",
	} {
		if _, err := h.sharedPersonalRootRecovery(context.Background(), []byte(invalid)); err != vaultwire.ErrProtocol {
			t.Fatal("unexpected recovery payload reached the owner", err)
		}
	}
	if _, err := h.sharedPersonalRootRecovery(context.Background(), []byte(base+"}")); err != vaultwire.ErrProtocol {
		t.Fatal("closed owner accepted a recovery review", err)
	}
	controller, fixture, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = &personalRootRecoveryProbe{credentialReleaseProbe: fixture}
	controller.runtimeTLS = sharedpg.TLSEncrypted
	h.shared = &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}
	out, err := h.Handle(context.Background(), "shared-personal-root-recovery", []byte(base+"}"))
	var reply sharedpg.PersonalRootRecoveryReply
	if err != nil || json.Unmarshal(out, &reply) != nil || reply.Status != "unavailable" || !controller.Unlocked() {
		t.Fatal("unverified TLS reached personal root custody", reply.Status, err)
	}
}

func TestSharedPersonalRootRecoveryVerifiesFactorsBeforeCustody(t *testing.T) {
	controller, fixture, options, root, _, organisation, _, _ := credentialControllerFixture(t)
	state, err := readSharedTrustFile(options.TrustPath, root, options.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle := sharedTLSFixture(t, &options, state, organisation, 3)
	next, err := state.AdvanceTLS(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(options.TrustPath, root, options.Binding, next, state.Revision); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(options.TrustPath, bundle); err != nil {
		t.Fatal(err)
	}
	controller.trustRevision, controller.tlsManaged, controller.runtimeTLS = next.Revision, true, sharedpg.TLSVerified
	fixture.tlsBundle = bundle
	probe := &personalRootRecoveryProbe{credentialReleaseProbe: fixture}
	controller.session = probe
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller, selected: &sharedSelectedDevice{}, vaultID: uuid.NewString()}}
	fields := map[string]any{"accountId": uuid.NewString(), "suspension": "9"}
	query := func(expected string) sharedpg.PersonalRootRecoveryReply {
		t.Helper()
		out, err := h.Handle(context.Background(), "shared-personal-root-recovery", vaultInput(t, fields))
		var reply sharedpg.PersonalRootRecoveryReply
		if err != nil || json.Unmarshal(out, &reply) != nil || reply.Status != expected || !controller.Unlocked() {
			t.Fatalf("recovery %q, want %q: %v", reply.Status, expected, err)
		}
		return reply
	}
	query("unsupported")
	probe.supported = true
	query("review")
	fields["review"] = strings.Repeat("ab", 32)
	fields["authentication"] = []byte(vaultInput(t, map[string]any{"vaultId": uuid.NewString(), "slotId": uuid.NewString(), "password": []byte("fixture-password")}))
	query("invalid-authentication")
	if probe.prepared != 1 {
		t.Fatal("unsupported or unauthenticated recovery reached custody", probe.prepared)
	}
	delete(fields, "review")
	delete(fields, "authentication")
	probe.needsEnrollment = true
	if reply := query("enrollment-required"); reply.CanReenroll {
		t.Fatal("the older schema advertised recipient registration")
	}
	probe.canReenroll = true
	if reply := query("enrollment-required"); !reply.CanReenroll || probe.reenrollmentChecks != 2 {
		t.Fatal("eligible suspension did not offer re-enrollment after upgrade")
	}
	probe.denied = true
	query("unavailable")
}
