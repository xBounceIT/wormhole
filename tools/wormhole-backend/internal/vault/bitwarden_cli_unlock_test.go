package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBitwardenCLIUnlockBinding(t *testing.T) {
	worker, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := BitwardenCLIUnlockBinding{
		WorkspaceID: uuid.NewString(), RequestID: uuid.NewString(), Configuration: strings.Repeat("ab", 32),
		VaultKey: owner.PublicKey().Bytes(), ExpiresAt: now.Add(time.Minute).UnixMilli(),
	}
	fixture := []byte("  synthetic rénewal  ")
	workerPublic := worker.PublicKey().Bytes()
	password, err := SealBitwardenCLIPassword(workerPublic, b, fixture, now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := SealBitwardenCLISession(b, fixture, now)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := OpenBitwardenCLIPassword(worker.Bytes(), b, password, now); err != nil || !bytes.Equal(out, fixture) {
		t.Fatal("password did not round trip", err)
	}
	if out, err := OpenBitwardenCLISession(owner.Bytes(), b, session, now); err != nil || !bytes.Equal(out, fixture) {
		t.Fatal("session did not round trip", err)
	}
	if _, err := OpenBitwardenCLISession(worker.Bytes(), b, password, now); err == nil {
		t.Fatal("password opened as a session")
	}
	if _, err := OpenBitwardenCLIPassword(owner.Bytes(), b, session, now); err == nil {
		t.Fatal("session opened as a password")
	}
	for _, mutate := range []func(*BitwardenCLIUnlockBinding){
		func(b *BitwardenCLIUnlockBinding) { b.WorkspaceID = uuid.NewString() },
		func(b *BitwardenCLIUnlockBinding) { b.RequestID = uuid.NewString() },
		func(b *BitwardenCLIUnlockBinding) { b.Configuration = strings.Repeat("00", 32) },
		func(b *BitwardenCLIUnlockBinding) { b.VaultKey = workerPublic },
		func(b *BitwardenCLIUnlockBinding) { b.ExpiresAt++ },
	} {
		changed := b
		mutate(&changed)
		if _, err := OpenBitwardenCLIPassword(worker.Bytes(), changed, password, now); err == nil {
			t.Fatal("password opened with changed binding")
		}
		if _, err := OpenBitwardenCLISession(owner.Bytes(), changed, session, now); err == nil {
			t.Fatal("session opened with changed binding")
		}
	}
	for _, mutate := range []func(*BitwardenCLIUnlockBinding){
		func(b *BitwardenCLIUnlockBinding) { b.WorkspaceID = "" },
		func(b *BitwardenCLIUnlockBinding) { b.RequestID = uuid.Nil.String() },
		func(b *BitwardenCLIUnlockBinding) { b.Configuration = strings.ToUpper(b.Configuration) },
		func(b *BitwardenCLIUnlockBinding) { b.VaultKey = make([]byte, 32) },
		func(b *BitwardenCLIUnlockBinding) { b.ExpiresAt = now.UnixMilli() },
		func(b *BitwardenCLIUnlockBinding) { b.ExpiresAt = now.Add(6 * time.Minute).UnixMilli() },
	} {
		changed := b
		mutate(&changed)
		if changed.Validate(now) == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	for _, invalid := range [][]byte{nil, {0}, {0xff}, {'\n'}, {'\r'}, make([]byte, MaxBitwardenCLIPassword+1)} {
		if _, err := SealBitwardenCLIPassword(workerPublic, b, invalid, now); err == nil {
			t.Fatal("invalid password sealed")
		}
		forged, err := sealBundlePayload(workerPublic, b.info("wormhole/v1/bitwarden-cli-password"), invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenBitwardenCLIPassword(worker.Bytes(), b, forged, now); err == nil {
			t.Fatal("invalid password accepted by worker")
		}
	}
	if _, err := SealBitwardenCLIPassword(b.VaultKey, b, fixture, now); err == nil {
		t.Fatal("owner recipient reused for password")
	}
	if _, err := SealBitwardenCLISession(b, make([]byte, MaxBitwardenSession+1), now); err == nil {
		t.Fatal("oversized session sealed")
	}
	if _, err := OpenBitwardenCLISession(owner.Bytes(), b, session, now.Add(time.Minute)); err == nil {
		t.Fatal("expired session opened")
	}
}
