package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

func TestTLSInviteBootstrapBinding(t *testing.T) {
	context := InviteContext{WorkspaceID: uuid.New(), UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: "alice"}
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer Wipe(org)
	bootstrap, err := NewInviteBootstrap(org.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	fingerprint := sha256.Sum256(bootstrap.OrganisationPublic)
	code, digest := bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{11}, 32)
	envelope, err := SealTLSInviteBootstrap(code, context, bootstrap, digest)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTLSInviteBootstrap(code, context, envelope, fingerprint[:], digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.SigningSeed, bootstrap.SigningSeed) || !bytes.Equal(opened.EncryptionPrivate, bootstrap.EncryptionPrivate) {
		t.Fatal("wrong bootstrap")
	}
	opened.Wipe()
	if b, err := OpenInviteBootstrap(code, context, envelope, fingerprint[:]); err == nil {
		b.Wipe()
		t.Fatal("legacy downgrade opened TLS-bound bootstrap")
	}
	wrong := bytes.Repeat([]byte{12}, 32)
	if b, err := OpenTLSInviteBootstrap(code, context, envelope, fingerprint[:], wrong); err == nil {
		b.Wipe()
		t.Fatal("replaced proof opened bootstrap")
	}
	legacy, err := SealInviteBootstrap(code, context, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := OpenTLSInviteBootstrap(code, context, legacy, fingerprint[:], digest); err == nil {
		b.Wipe()
		t.Fatal("legacy envelope accepted as TLS-bound")
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := SealTLSInviteBootstrap(code, context, bootstrap, bad); err != ErrFormat {
			t.Fatal("bad seal digest", err)
		}
		if b, err := OpenTLSInviteBootstrap(code, context, envelope, fingerprint[:], bad); err != ErrFormat || b != nil {
			t.Fatal("bad open digest", err)
		}
	}
}
