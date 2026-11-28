package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceCAOrganisationProjectionChecksBothCopyKinds(t *testing.T) {
	_, ca, org, _ := workspaceRotationFixture(t, serverCertNow)
	wire, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	encoded := func(size int) []byte { return hex.AppendEncode(nil, bytes.Repeat([]byte{4}, size)) }
	encryption := [][]byte{[]byte("org-enc"), []byte(org.Encryption.ID.String()), []byte("1"), encoded(32), encoded(48), encoded(64), wire}
	signing := [][]byte{[]byte("org-sign"), []byte(org.Signing.ID.String()), []byte("1"), encoded(32), encoded(48), encoded(64), nil}
	copy, id, signingCopy, err := parseWorkspaceCAOrganisation([][][]byte{encryption, signing})
	if err != nil || copy.ca.Key != ca.Key || copy.organisation != org.Encryption || id != org.Signing || len(signingCopy.Signature) != 64 {
		t.Fatal("organisation copies changed", err)
	}
	for _, rows := range [][][][]byte{
		nil, {encryption}, {signing, encryption},
		{encryption[:6], signing}, {encryption, signing[:6]},
		{append(encryption[:6:6], []byte("{}")), signing},
		{encryption, append(signing[:6:6], wire)},
	} {
		if _, _, _, err := parseWorkspaceCAOrganisation(rows); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("malformed organisation copies were accepted", err)
		}
	}
}

func TestWorkspaceCAPublicationRejectsInvalidContextBeforeRelease(t *testing.T) {
	_, _, trust, cert, signer, _, _ := enrollmentTrustFixture(t)
	var err error
	trust, err = trust.AdvanceEnrollment(cert, trust.WrappingRevision)
	if err != nil {
		t.Fatal(err)
	}
	current := trustedTLSFixture(t, trust, signer, trust.TLSSequence+1)
	trust, err = trust.AdvanceTLS(current)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var session Session
	user := bytes.Repeat([]byte{7}, 32)
	if _, err := session.PublishWorkspaceCAOverlap(ctx, trust, current, user, nil, nil, serverCertNow); !errors.Is(err, ErrConfiguration) {
		t.Fatal("incomplete owner key accepted", err)
	}
	if _, err := session.PublishWorkspaceCARetirement(ctx, trust, current, Settings{}, nil, user); !errors.Is(err, ErrConfiguration) {
		t.Fatal("incomplete retirement owner key accepted", err)
	}
	for _, wrong := range []*VerifiedTLSBundle{nil, trustedTLSFixture(t, trust, signer, trust.TLSSequence+1)} {
		if _, err := session.PublishWorkspaceCAOverlap(ctx, trust, wrong, user, user, nil, serverCertNow); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("uncommitted or unverified TLS state was accepted", err)
		}
		if _, err := session.PublishWorkspaceCARetirement(ctx, trust, wrong, Settings{}, user, user); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("uncommitted or unverified retirement TLS state was accepted", err)
		}
	}
	if _, err := session.PublishWorkspaceCAOverlap(ctx, trust, current, user, user, []byte("invalid CSR"), serverCertNow); !errors.Is(err, ErrServerCertificate) {
		t.Fatal("invalid CSR reached the encrypted key query", err)
	}
	if _, err := session.PublishWorkspaceCARetirement(ctx, trust, current, Settings{}, user, user); !errors.Is(err, ErrWorkspaceCARotation) {
		t.Fatal("stable bundle allowed retirement", err)
	}
	other := trust
	other.Enrollment = nil
	if _, err := session.PublishWorkspaceCAOverlap(ctx, other, current, user, user, nil, serverCertNow); !errors.Is(err, ErrServerCertificateAuthority) {
		t.Fatal("no enrolled final key accepted", err)
	}
	badID := trust
	badID.UserID = uuid.New()
	if _, err := authenticatedServerCAContext(badID, current); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("foreign workspace account accepted", err)
	}
}
