package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
)

func TestSealAccountResetDisplayBindsWorkspaceRequestAndLogin(t *testing.T) {
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workspace, request := uuid.New(), uuid.New()
	factors := bytes.Repeat([]byte{42}, InviteCodeBytes+32)
	defer Wipe(factors)
	bundle, err := SealAccountResetDisplay(recipient.PublicKey().Bytes(), workspace, request, "test-user", factors)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		workspace, request uuid.UUID
		login              string
		valid              bool
	}{
		{workspace, request, "test-user", true},
		{workspace, uuid.New(), "test-user", false},
		{uuid.New(), request, "test-user", false},
		{workspace, request, "other-user", false},
	} {
		info := canonical("wormhole/v1/account-reset-display", []byte(tt.workspace.String()), []byte(tt.request.String()), []byte(tt.login))
		raw, err := openBundlePayload(recipient.Bytes(), info, bundle)
		if tt.valid {
			if err != nil || !bytes.Equal(raw, factors) {
				t.Fatal("protected reset handover did not open", err)
			}
		} else if err == nil || raw != nil {
			t.Fatal("reset factors opened outside their protected display")
		}
		Wipe(raw)
	}
	if _, err := SealAccountResetDisplay(recipient.PublicKey().Bytes(), workspace, request, "BadLogin", factors); err == nil {
		t.Fatal("noncanonical login accepted")
	}
	if _, err := SealAccountResetDisplay(recipient.PublicKey().Bytes(), workspace, request, "test-user", factors[:16]); err == nil {
		t.Fatal("truncated handover accepted")
	}
}
