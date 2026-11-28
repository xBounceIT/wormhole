package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestAccountResetOfferRequiresSignedPolicyAndTransport(t *testing.T) {
	bundle, pin, signer := tlsTrustFixture(t)
	defer vault.Wipe(signer)
	rawBundle, err := EncodeTLSTrustBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	policy := vault.Policy{FormatVersion: 1, WorkspaceID: pin.WorkspaceID.String(), Sequence: 1,
		Profile: vault.Default, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	certify := func(p vault.Policy) []byte {
		t.Helper()
		signed, err := vault.SignPolicy(p, pin.Signer.ID.String(), pin.Signer.Version, signer)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.EncodeSignedPolicy(signed)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	keys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{46}, 32), SigningSeed: bytes.Repeat([]byte{29}, 32)}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	o := accountResetOffer{Version: 1, ID: uuid.New(), WorkspaceID: pin.WorkspaceID,
		Subject: accountResetSubject{UserID: uuid.New(), LoginName: "reset-test",
			Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1},
			WrapRevision: 1, MinimumKDF: vault.KDFV1, StateDigest: make([]byte, 32), CertificateDigest: make([]byte, 32)},
		RoleTag: "testscope", Database: "workspace", Endpoints: []Endpoint{{Host: "db.example.test", Port: 5432}},
		Organisation: pin.Organisation, Signer: pin.Signer, TLSBundle: rawBundle, SignedPolicy: certify(policy),
		UserPublic: public, ExpiresAt: now.Add(accountResetLifetime).Unix()}
	sign := func(offer *accountResetOffer) {
		t.Helper()
		body, err := offer.signingBytes()
		if err != nil {
			t.Fatal(err)
		}
		offer.Signature = ed25519.Sign(signer, body)
	}
	sign(&o)
	if settings, profile, err := o.transport(now); err != nil || settings.TLS != TLSVerified || profile != policy {
		t.Fatal("valid reset offer was rejected", err)
	}
	policyV3 := policy
	policyV3.Profile, policyV3.KDF, policyV3.ASKRequired, policyV3.OrgEscrow = vault.Paranoid, vault.KDFV3, true, false
	for name, change := range map[string]func(*accountResetOffer){
		"unsupported profile": func(o *accountResetOffer) { o.SignedPolicy = certify(policyV3) },
		"wrong policy signer": func(o *accountResetOffer) { o.Signer.ID = uuid.New() },
		"broken policy":       func(o *accountResetOffer) { o.SignedPolicy = json.RawMessage("{}") },
		"broken TLS":          func(o *accountResetOffer) { o.TLSBundle = json.RawMessage("{}") },
		"wrong host":          func(o *accountResetOffer) { o.Endpoints = []Endpoint{{Host: "other.example.test", Port: 5432}} },
		"wrong database":      func(o *accountResetOffer) { o.Database = "" },
		"expired":             func(o *accountResetOffer) { o.ExpiresAt = now.Unix() },
		"bad login":           func(o *accountResetOffer) { o.Subject.LoginName = "" },
		"unknown KDF":         func(o *accountResetOffer) { o.Subject.MinimumKDF = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := o
			change(&changed)
			sign(&changed)
			if _, _, err := changed.transport(now); err == nil {
				t.Fatal("signed but invalid reset offer was accepted")
			}
		})
	}
	seed := signer.Seed()
	defer vault.Wipe(seed)
	bad := o
	bad.Subject.WrapRevision = 0
	if p, err := prepareResetOffer(bad, o.Subject.UserID, seed, keys, now); p != nil || err == nil {
		t.Fatal("invalid wrapping revision could be published")
	}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := OpenAccountReset(context.Background(), append([]byte{' '}, raw...), nil, nil); keys != nil || !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("noncanonical document reached reset transport", err)
	}
	if keys, err := OpenAccountReset(context.Background(), []byte("{"), nil, nil); keys != nil || !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("malformed document reached reset transport", err)
	}
	t.Run("certified suspended replacement", func(t *testing.T) {
		replacement := o
		replacement.Version, replacement.Subject.Suspension, replacement.Subject.AccountSequence = 2, 9, 2
		issuer := uuid.New()
		prepared, err := createAccountReenrollmentOffer(context.Background(), replacement, issuer, seed, now)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		for name, change := range map[string]func(*accountResetOffer){
			"missing bootstrap":              func(offer *accountResetOffer) { offer.Replacement = nil },
			"missing suspension":             func(offer *accountResetOffer) { offer.Subject.Suspension = 0 },
			"stale sequence":                 func(offer *accountResetOffer) { offer.Replacement.State.Sequence-- },
			"known key":                      func(offer *accountResetOffer) { offer.Replacement.State.Encryption = offer.Subject.Encryption },
			"different public key":           func(offer *accountResetOffer) { offer.Replacement.Encryption.PublicKey = public.Encryption },
			"wrong workspace manifest":       func(offer *accountResetOffer) { offer.Replacement.Manifest.Context.WorkspaceID = uuid.New() },
			"invalid state signature":        func(offer *accountResetOffer) { offer.Replacement.State.Signature = make([]byte, 64) },
			"invalid encryption certificate": func(offer *accountResetOffer) { offer.Replacement.Encryption.Signature = make([]byte, 64) },
			"invalid signing certificate":    func(offer *accountResetOffer) { offer.Replacement.Signing.Signature = make([]byte, 64) },
		} {
			t.Run(name, func(t *testing.T) {
				changed := prepared.offer
				inner := *changed.Replacement
				changed.Replacement = &inner
				change(&changed)
				sign(&changed)
				if _, _, err := changed.transport(now); err == nil {
					t.Fatal("signed offer accepted a replacement outside its certified scope")
				}
			})
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if p, err := createAccountReenrollmentOffer(canceled, replacement, issuer, seed, now); p != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled offer issued bootstrap material", err)
		}
		if p, err := createAccountReenrollmentOffer(context.Background(), replacement, issuer, nil, now); p != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid custodian signing material reached issuance", err)
		}
		if opened, err := OpenAccountReenrollment(context.Background(), raw, nil, nil); opened != nil || !errors.Is(err, ErrAccountRecovery) {
			t.Fatal("an ordinary reset was accepted as a replacement", err)
		}
	})
}
