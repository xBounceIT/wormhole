package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestMemberInviteDisplayBindsDocumentAndRecipient(t *testing.T) {
	invite := InviteContext{WorkspaceID: uuid.New(), UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: "operator"}
	request := uuid.New()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, InviteCodeBytes)
	rand.Read(code)
	defer Wipe(code)
	const document = "public invitation fixture"
	bundle, err := SealInviteDisplay(recipient.PublicKey().Bytes(), request, invite, document, code)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(document))
	fields := [][]byte{[]byte(request.String()), []byte(invite.LoginName), []byte(invite.WorkspaceID.String()), []byte(invite.InviteID.String()), hex.AppendEncode(nil, digest[:])}
	for modified := -1; modified < len(fields); modified++ {
		contextFields := append([][]byte(nil), fields...)
		if modified >= 0 {
			contextFields[modified] = []byte("different")
		}
		plain, err := openBundlePayload(recipient.Bytes(), canonical("wormhole/v1/member-invitation-display", contextFields...), bundle)
		if modified < 0 && (err != nil || !bytes.Equal(plain, code)) || modified >= 0 && (err == nil || plain != nil) {
			t.Fatal("incorrect binding for field", modified, err)
		}
		Wipe(plain)
	}
	if _, err := SealInviteDisplay(make([]byte, 32), request, invite, document, code); err == nil {
		t.Fatal("unusable display key accepted")
	}
	if _, err := SealInviteDisplay(recipient.PublicKey().Bytes(), request, invite, document, code[1:]); err == nil {
		t.Fatal("truncated code accepted")
	}
}

func TestMemberInvitationClipboardSealsLifetimeAndScope(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := [4]uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	value := bytes.Repeat([]byte("ab"), InviteCodeBytes)
	for _, ttl := range []int{20, 30} {
		bundle, err := SealMemberInvitationClipboard(key.PublicKey().Bytes(), scope[0], scope[1], scope[2], scope[3], ttl, value)
		if err != nil {
			t.Fatal(err)
		}
		for mismatch := -1; mismatch < len(scope); mismatch++ {
			fields := make([][]byte, len(scope))
			for i, id := range scope {
				fields[i] = []byte(id.String())
			}
			if mismatch >= 0 {
				fields[mismatch] = []byte(uuid.NewString())
			}
			plain, err := openBundlePayload(key.Bytes(), canonical("wormhole/v1/member-invitation-clipboard", fields...), bundle)
			if mismatch < 0 && (err != nil || !bytes.Equal(plain, append([]byte{1, byte(ttl)}, value...))) || mismatch >= 0 && err == nil {
				t.Fatal("clipboard context", mismatch, err)
			}
			Wipe(plain)
		}
	}
	if _, err := SealMemberInvitationClipboard(key.PublicKey().Bytes(), scope[0], scope[1], scope[2], scope[3], 60, value); err == nil {
		t.Fatal("unsupported lifetime")
	}
}
