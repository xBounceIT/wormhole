package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func setInvitationTLS(t *testing.T, i *Invitation, signer vault.KeyRef, org ed25519.PrivateKey, ca []byte) {
	t.Helper()
	bundle := TLSTrustBundle{FormatVersion: 1, WorkspaceID: i.WorkspaceID, Signer: signer, Sequence: 1, CAs: [][]byte{ca}, Hosts: []string{"db.example.test"}, Revoked: []TLSRevocation{}}
	signed, err := SignTLSTrustBundle(bundle, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeTLSTrustBundle(signed)
	if err != nil {
		t.Fatal(err)
	}
	i.FormatVersion, i.TLS, i.CAPEM = 3, TLSVerified, nil
	i.Endpoints = []Endpoint{{Host: "db.example.test", Port: 5432}}
	i.TLSIdentity = &InvitationTLSIdentity{Organisation: org.Public().(ed25519.PublicKey), Bundle: raw}
	fingerprint := sha256.Sum256(i.TLSIdentity.Organisation)
	i.OrganisationFingerprint = fingerprint[:]
}

func signedInvitationFixture(t *testing.T) (Invitation, ed25519.PrivateKey, time.Time) {
	t.Helper()
	i, now := enrollmentInvitationFixture(t)
	org := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ca, _ := serverIssuer(t, nil)
	setInvitationTLS(t, &i, vault.KeyRef{ID: uuid.New(), Version: 1}, org, ca)
	return i, org, now
}

func tlsInvitationToken(raw []byte) string {
	payload := tlsEnrollmentInvitationPrefix + base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(payload))
	return payload + "." + hex.EncodeToString(digest[:])
}

func TestSignedTLSInvitationRoundTripAndAuthority(t *testing.T) {
	i, org, now := signedInvitationFixture(t)
	defer vault.Wipe(org)
	// Offline discovery must not consult ambient driver/service-file choices.
	t.Setenv("PGSERVICE", "must-not-be-read")
	token, err := EncodeInvitation(i, now)
	if err != nil || !strings.HasPrefix(token, tlsEnrollmentInvitationPrefix) {
		t.Fatal(err)
	}
	decoded, err := DecodeInvitation(token, now)
	if err != nil || !reflect.DeepEqual(i, decoded) {
		t.Fatal("round trip", err)
	}
	hint, err := i.invitationTLSHint()
	if err != nil {
		t.Fatal(err)
	}
	pin := hint.Pin()
	authenticated, err := decoded.AuthenticatedTLSBundle(org.Public().(ed25519.PublicKey), pin.Signer)
	if err != nil || !bytes.Equal(authenticated.Encode(), hint.Encode()) {
		t.Fatal("promotion", err)
	}
	for _, wrong := range []struct {
		org    ed25519.PublicKey
		signer vault.KeyRef
	}{
		{make([]byte, 32), pin.Signer}, {pin.Organisation, vault.KeyRef{ID: uuid.New(), Version: 1}}, {pin.Organisation, vault.KeyRef{ID: pin.Signer.ID, Version: 2}},
	} {
		if result, err := i.AuthenticatedTLSBundle(wrong.org, wrong.signer); result != nil || !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("untrusted authority promoted", err)
		}
	}
	legacy, _ := enrollmentInvitationFixture(t)
	if v, err := legacy.AuthenticatedTLSBundle(nil, vault.KeyRef{}); v != nil || err != nil {
		t.Fatal("legacy", err)
	}
	i.TLSIdentity.Bundle[0] ^= 1
	if !bytes.Equal(hint.Encode(), authenticated.Encode()) {
		t.Fatal("snapshot aliased")
	}
}

func TestSignedTLSInvitationRejectsMalformedProofs(t *testing.T) {
	for _, mode := range []string{"missing", "short-key", "fingerprint", "empty", "oversize", "malformed", "signature", "workspace", "host", "ca-mix", "off", "encrypted", "legacy", "unknown", "enrollment"} {
		t.Run(mode, func(t *testing.T) {
			i, org, now := signedInvitationFixture(t)
			defer vault.Wipe(org)
			switch mode {
			case "missing":
				i.TLSIdentity = nil
			case "short-key":
				i.TLSIdentity.Organisation = []byte{1}
			case "fingerprint":
				i.OrganisationFingerprint[0] ^= 1
			case "empty":
				i.TLSIdentity.Bundle = nil
			case "oversize":
				i.TLSIdentity.Bundle = make([]byte, MaxTLSTrustBundleBytes+1)
			case "malformed":
				i.TLSIdentity.Bundle = json.RawMessage(`{}`)
			case "signature", "workspace":
				b, err := DecodeTLSTrustBundle(i.TLSIdentity.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "signature" {
					b.Signature[0] ^= 1
				} else {
					b.WorkspaceID = uuid.New()
					b, err = SignTLSTrustBundle(b, org)
					if err != nil {
						t.Fatal(err)
					}
				}
				i.TLSIdentity.Bundle, err = EncodeTLSTrustBundle(b)
				if err != nil {
					t.Fatal(err)
				}
			case "host":
				i.Endpoints[0].Host = "other.example.test"
			case "ca-mix":
				i.CAPEM = []byte("historical CA")
			case "off":
				i.TLS = TLSOff
			case "encrypted":
				i.TLS = TLSEncrypted
			case "legacy":
				i.FormatVersion = 2
			case "unknown":
				i.FormatVersion = 4
			case "enrollment":
				i.Enrollment = nil
			}
			if _, err := EncodeInvitation(i, now); err == nil {
				t.Fatal("invalid invitation encoded")
			}
			raw, err := json.Marshal(i)
			if err == nil {
				if _, err := DecodeInvitation(tlsInvitationToken(raw), now); err == nil {
					t.Fatal("recomputed checksum accepted invalid proof")
				}
			}
			if v, err := i.AuthenticatedTLSBundle(nil, vault.KeyRef{}); v != nil || err == nil {
				t.Fatal("invalid authority promoted")
			}
		})
	}
}

func TestSignedTLSInvitationLargeBundleAndPrefixBinding(t *testing.T) {
	i, org, now := signedInvitationFixture(t)
	defer vault.Wipe(org)
	b, err := DecodeTLSTrustBundle(i.TLSIdentity.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 4096; n++ {
		b.Revoked = append(b.Revoked, TLSRevocation{IssuerSPKI: strings.Repeat("1", 64), Serial: strings.Repeat("a", 32) + fmt.Sprintf("%08x", n)})
	}
	b, err = SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	i.TLSIdentity.Bundle, err = EncodeTLSTrustBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	token, err := EncodeInvitation(i, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(i.TLSIdentity.Bundle) <= 384*1024 {
		t.Fatal("large bundle fixture is too small")
	}
	if _, err := DecodeInvitation(token, now); err != nil {
		t.Fatal("large signed bundle rejected", err)
	}
	raw, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInvitation(invitationToken(raw), now); err == nil {
		t.Fatal("v3 accepted under v1 prefix")
	}
}

func TestSignedTLSInvitationInitialLoginUsesOnlyBundle(t *testing.T) {
	i, org, _ := signedInvitationFixture(t)
	defer vault.Wipe(org)
	settings, login, err := initialInvitationLogin(i, bytes.Repeat([]byte{1}, 16), vault.Standard, vault.Default, false)
	defer vault.Wipe(login)
	if err != nil || settings.TLSBundle == nil || len(settings.CAPEM) != 0 {
		t.Fatal("signed initial transport", err)
	}
	config, err := Config(settings)
	if err != nil || config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.VerifyConnection == nil || config.ChannelBinding != "require" {
		t.Fatal("TLS authority missing", err)
	}
	settings.Endpoints[0].Host = "other.example.test"
	if _, err := Config(settings); err == nil {
		t.Fatal("unpermitted endpoint connected")
	}
}

func TestSignedTLSInvitationCannotStripProofAtBootstrap(t *testing.T) {
	i, org, now := signedInvitationFixture(t)
	defer vault.Wipe(org)
	code := bytes.Repeat([]byte{12}, 16)
	bootstrap := invitationBootstrapFixture(t, i, code)
	opened, err := bootstrap.Authenticate(i, code, 1, now)
	if err != nil {
		t.Fatal("original proof", err)
	}
	opened.Wipe()
	legacy := i
	legacy.FormatVersion, legacy.TLSIdentity, legacy.TLS, legacy.CAPEM = 2, nil, TLSOff, nil
	if opened, err := bootstrap.Authenticate(legacy, code, 1, now); err == nil {
		opened.Wipe()
		t.Fatal("stripping signed TLS proof authenticated the same bootstrap")
	}
	b, err := DecodeTLSTrustBundle(i.TLSIdentity.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	b.Sequence++
	b, err = SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	i.TLSIdentity.Bundle, err = EncodeTLSTrustBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := bootstrap.Authenticate(i, code, 1, now); err == nil {
		opened.Wipe()
		t.Fatal("replaced signed TLS proof opened old bootstrap")
	}
}

func TestSignedTLSInvitationProvisioningRefusesInvalidIssuance(t *testing.T) {
	i, org, now := signedInvitationFixture(t)
	defer vault.Wipe(org)
	bootstrap, err := vault.NewInviteBootstrap(org.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	code := bytes.Repeat([]byte{12}, 16)
	for _, mode := range []string{"expired", "missing-context", "missing-proof", "invalid-code", "missing-bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			candidate := i
			factors, secret := code, bootstrap
			switch mode {
			case "expired":
				candidate.ExpiresAt = now.Unix()
			case "missing-context":
				candidate.Enrollment = nil
			case "missing-proof":
				candidate.TLSIdentity = nil
			case "invalid-code":
				factors = nil
			case "missing-bootstrap":
				secret = nil
			}
			if envelope, err := candidate.SealBootstrap(factors, secret, now); err == nil || len(envelope.Ciphertext) != 0 {
				t.Fatal("invalid issuance encrypted", err)
			}
		})
	}
	i.TLSIdentity = nil
	if digest, err := i.tlsBootstrapDigest(); err == nil || len(digest) != 0 {
		t.Fatal("missing proof has a bootstrap digest")
	}
}
