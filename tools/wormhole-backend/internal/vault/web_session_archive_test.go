package vault

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/google/uuid"
)

func TestWebSessionArchiveUsesDedicatedOneUseRecipientBinding(t *testing.T) {
	key, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	workspace, node, request := uuid.NewString(), uuid.NewString(), uuid.NewString()
	plain := []byte("synthetic web archive")
	sealed, err := SealWebSessionArchive(key.PublicKey().Bytes(), workspace, node, request, 12, plain)
	if err != nil {
		t.Fatal(err)
	}
	info := func(domain, nonce, revision string) []byte {
		return canonical(domain, []byte(workspace), []byte(node), []byte(nonce), []byte(revision))
	}
	opened, err := openBundlePayload(key.Bytes(), info("wormhole/v1/web-session-archive", request, "12"), sealed)
	defer Wipe(opened)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("browser archive failed to open: %v", err)
	}
	for _, confused := range [][]byte{
		info("wormhole/v1/notes-display", request, "12"),
		info("wormhole/v1/web-session-archive", uuid.NewString(), "12"),
		info("wormhole/v1/web-session-archive", request, "13"),
	} {
		if _, err := openBundlePayload(key.Bytes(), confused, sealed); err == nil {
			t.Fatal("archive accepted a different operation or revision")
		}
	}
	if _, err := SealWebSessionArchive(key.PublicKey().Bytes(), workspace, node, request, 12, nil); err != ErrFormat {
		t.Fatal("empty archive sealed")
	}
}
