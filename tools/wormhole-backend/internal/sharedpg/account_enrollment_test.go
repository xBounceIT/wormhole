package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func accountEnrollmentRows(t *testing.T) ([][][]byte, vault.UserKeyTrust, []byte) {
	return accountEnrollmentRowsWithBootstrap(t, nil)
}

func accountEnrollmentRowsWithBootstrap(t *testing.T, observe func(vault.InviteContext, *vault.InviteBootstrap)) ([][][]byte, vault.UserKeyTrust, []byte) {
	t.Helper()
	i, now := enrollmentInvitationFixture(t)
	r := admissionRequest()
	i.WorkspaceID, i.Enrollment.Context.WorkspaceID = r.WorkspaceID, r.WorkspaceID
	i.Enrollment.Context.UserID = r.UserID
	code := bytes.Repeat([]byte{81}, 16)
	b := invitationBootstrapFixture(t, i, code)
	bootstrap, err := b.Authenticate(i, code, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	if observe != nil {
		observe(i.Enrollment.Context, bootstrap)
	}
	keys, proof, err := vault.PrepareInviteRekey(i.Enrollment.Context, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	root := vault.KeyRef{ID: uuid.New(), Version: 1}
	enc := vault.KeyRef{ID: i.Enrollment.Context.KeyID, Version: i.Enrollment.Context.KeyVersion}
	sign := vault.KeyRef{ID: uuid.New(), Version: 1}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: 1, WorkspaceID: r.WorkspaceID, UserID: r.UserID, Sequence: 1, Active: true, Encryption: enc, Signing: sign, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: r.WorkspaceID, UserID: r.UserID, Key: enc, Kind: "user-enc", Suite: 2, PublicKey: b.Manifest.Bootstrap.Encryption, Revision: 1, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: r.WorkspaceID, UserID: r.UserID, Key: sign, Kind: "user-sign", Suite: 1, PublicKey: b.Manifest.Bootstrap.Signing, Revision: 1, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	certificate := vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: b.Manifest, BootstrapEncryption: ec, BootstrapSigning: sc, Rekey: proof}
	certRaw, err := vault.EncodeUserEnrollmentCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	stateRaw, err := vault.EncodeUserKeyState(state)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{91}, 32)
	t.Cleanup(func() { vault.Wipe(master) })
	binding := vault.UserKeyBinding{WorkspaceID: r.WorkspaceID, UserID: r.UserID, Encryption: vault.KeyRef{ID: proof.EncryptionKeyID, Version: 1}, Signing: vault.KeyRef{ID: proof.SigningKeyID, Version: 1}, Revision: 1}
	envelope, err := vault.SealUserKeys(master, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	rows := accountKeyRows()
	rows[0][2], rows[0][4] = []byte(proof.EncryptionKeyID.String()), []byte(proof.SigningKeyID.String())
	rows[0][9], rows[0][10] = hex.AppendEncode(nil, envelope.Nonce), hex.AppendEncode(nil, envelope.Ciphertext)
	rows[0] = append(rows[0], hex.AppendEncode(nil, stateRaw), []byte("1"), hex.AppendEncode(nil, certRaw))
	return rows, vault.UserKeyTrust{WorkspaceID: r.WorkspaceID, UserID: r.UserID, Signer: root, Organisation: bytes.Clone(bootstrap.OrganisationPublic), MinimumSequence: 1, MinimumWrappingRevision: 1}, master
}

func TestAccountEnrollmentParsing(t *testing.T) {
	rows, trust, master := accountEnrollmentRows(t)
	got, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	certificate := *got.EnrollmentCertificate
	for _, bad := range [][][][]byte{nil, {rows[0][:14]}, {rows[0], rows[0]}} {
		if _, err := parseAccountEnrollmentMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatal(err)
		}
	}
	for n := range rows[0] {
		bad := [][][]byte{append([][]byte(nil), rows[0]...)}
		bad[0][n] = []byte("bad")
		if _, err := parseAccountEnrollmentMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatalf("column %d: %v", n, err)
		}
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'0'}, 2*vault.MaxUserEnrollmentCertificateBytes+1), []byte("00")} {
		bad := [][][]byte{append([][]byte(nil), rows[0]...)}
		bad[0][14] = raw
		if _, err := parseAccountEnrollmentMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*vault.UserEnrollmentCertificate){
		func(c *vault.UserEnrollmentCertificate) { c.Manifest.Context.UserID = uuid.New() },
		func(c *vault.UserEnrollmentCertificate) { c.Manifest.Context.WorkspaceID = uuid.New() },
		func(c *vault.UserEnrollmentCertificate) { c.BootstrapSigning.Key.ID = uuid.New() },
		func(c *vault.UserEnrollmentCertificate) { c.BootstrapEncryption.Signer.ID = uuid.New() },
		func(c *vault.UserEnrollmentCertificate) { c.Rekey.EncryptionKeyID = uuid.New() },
		func(c *vault.UserEnrollmentCertificate) { c.Rekey.SigningKeyID = uuid.New() },
	} {
		c := certificate
		mutate(&c)
		raw, err := vault.EncodeUserEnrollmentCertificate(c)
		if err != nil {
			t.Fatal(err)
		}
		bad := [][][]byte{append([][]byte(nil), rows[0]...)}
		bad[0][14] = hex.AppendEncode(nil, raw)
		if _, err := parseAccountEnrollmentMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatal("mixed enrollment", err)
		}
	}
	wipeQueryRows(rows)
	keys, err := vault.OpenEnrolledUserKeys(master, got.Binding, got.Envelope, *got.EnrollmentCertificate, *got.State, trust, 1)
	if err != nil {
		t.Fatal("decoded data aliases wire buffers", err)
	}
	keys.Wipe()
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.AccountEnrollmentMaterial(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.AccountEnrollmentMaterial(context.Background()); err != ErrAuthentication {
		t.Fatal(err)
	}
}
