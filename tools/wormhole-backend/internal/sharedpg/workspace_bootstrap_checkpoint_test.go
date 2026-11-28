package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceBootstrapCheckpointPreservesIssuanceAndOfflineCustody(t *testing.T) {
	ctx := context.Background()
	scope := WorkspaceBootstrapScope{WorkspaceID: uuid.New(), RoleTag: "testscope", PlanDigest: sha256.Sum256([]byte("canonical deployment plan"))}
	ca, _ := pem.Decode(testCA(t))
	draft, factors, err := prepareWorkspaceBootstrap(scope.WorkspaceID, scope.RoleTag, Settings{Database: "vault", Endpoints: []Endpoint{{Host: "db.example.org", Port: 5432}}, Profile: vault.Standard}, [][]byte{ca.Bytes}, "first-admin", true, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer factors.wipe()
	password := []byte("synthetic-admin-unlock")
	ask := bytes.Repeat([]byte{34}, 32)
	defer vault.Wipe(password)
	defer vault.Wipe(ask)
	checkpoint, err := newWorkspaceBootstrapCheckpoint(ctx, scope, draft, factors, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer checkpoint.Close()
	seal := func(c *WorkspaceBootstrapCheckpoint) []byte {
		t.Helper()
		raw, err := c.Seal()
		if err != nil || bytes.Contains(raw, password) || bytes.Contains(raw, factors.invitationCode[:]) || bytes.Contains(raw, factors.recoveryKey[:]) || bytes.Contains(raw, []byte("first-admin")) {
			t.Fatal("checkpoint did not hide its protected contents", err)
		}
		return raw
	}
	open := func(raw []byte) *WorkspaceBootstrapCheckpoint {
		t.Helper()
		c, err := OpenWorkspaceBootstrapCheckpoint(ctx, scope, raw, password, ask)
		if err != nil || !bytes.Equal(c.code, factors.invitationCode[:]) {
			t.Fatal("checkpoint lost the initial invitation", err)
		}
		t.Cleanup(c.Close)
		return c
	}
	initial := seal(checkpoint)
	checkpoint.Close()
	if _, err := checkpoint.Seal(); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("a retired checkpoint could still seal data")
	}
	other := scope
	other.PlanDigest = sha256.Sum256([]byte("different path or CA"))
	for _, variant := range []struct {
		scope    WorkspaceBootstrapScope
		raw      []byte
		password []byte
		ask      []byte
		want     error
	}{
		{other, initial, password, ask, vault.ErrAuthentication},
		{scope, initial, []byte("wrong"), ask, vault.ErrAuthentication},
		{scope, initial, password, nil, vault.ErrFormat},
		{scope, append(bytes.Clone(initial), '\n'), password, ask, vault.ErrFormat},
		{scope, nil, password, ask, ErrConfiguration},
	} {
		if c, err := OpenWorkspaceBootstrapCheckpoint(ctx, variant.scope, variant.raw, variant.password, variant.ask); c != nil || !errors.Is(err, variant.want) {
			t.Fatal("untrusted or invalid checkpoint was accepted", err)
		}
	}
	raw := open(initial)
	if err := raw.Publish(ctx, "dba", nil); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("publication permitted before offline custody confirmation", err)
	}
	if err := raw.BorrowJoin(nil); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("join permitted before publication", err)
	}
	if err := raw.ConfirmRecoveryCustody(make([]byte, 10)); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("confirmation was allowed without an offline kit export", err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kit, groups, display, err := raw.PrepareRecovery(recipient.PublicKey().Bytes())
	if err != nil || len(display.Ciphertext) != 92 || groups[0] == groups[1] || bytes.Contains(kit, factors.recoveryKey[:]) {
		t.Fatal("could not deliver the protected recovery materials", err)
	}
	if err := raw.MarkRecoveryExported(); err != nil {
		t.Fatal(err)
	}
	resumed := open(seal(raw))
	if resumed.Status().Stage != "recovery-exported" || resumed.Status().EnrollmentID != draft.invitation.Enrollment.Context.InviteID.String() {
		t.Fatal("restart did not preserve the recovery export stage")
	}
	if err := resumed.ConfirmRecoveryCustody(make([]byte, 10)); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("bad recovery group contents were accepted", err)
	}
	if err := resumed.ConfirmRecoveryCustody([]byte("bad")); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("bad recovery group length was accepted", err)
	}
	code, err := vault.FormatRecoveryKey(factors.recoveryKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	confirmation := make([]byte, 0, 10)
	defer vault.Wipe(confirmation[:10])
	for _, group := range groups {
		begin := 7 + (group-1)*6
		confirmation = append(confirmation, code[begin:begin+5]...)
	}
	if err := resumed.ConfirmRecoveryCustody(confirmation); err != nil {
		t.Fatal("correct offline custody confirmation failed", err)
	}
	confirmed := open(seal(resumed))
	if confirmed.Status().Stage != "recovery-confirmed" || len(confirmed.recoveryKey) != 0 {
		t.Fatal("confirmed checkpoint retained the offline recovery key")
	}
	if _, _, _, err := confirmed.PrepareRecovery(recipient.PublicKey().Bytes()); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("confirmed checkpoint allowed the recovery key to be displayed again", err)
	}
	recovered, err := OpenWorkspaceRecoveryKit(scope.WorkspaceID, kit, code)
	if err != nil {
		t.Fatal("offline kit could not recover the organisation keys", err)
	}
	defer recovered.Wipe()
	public, err := recovered.Public()
	if err != nil || !bytes.Equal(public.Encryption, draft.organisation.Encryption) || !bytes.Equal(public.Signing, draft.organisation.Signing) {
		t.Fatal("offline kit opened unrelated organisation keys", err)
	}
	for _, invalid := range [][]byte{nil, append(bytes.Clone(kit), '\n')} {
		if keys, err := OpenWorkspaceRecoveryKit(scope.WorkspaceID, invalid, code); keys != nil || !errors.Is(err, vault.ErrFormat) {
			t.Fatal("untrusted kit was accepted", err)
		}
	}
	var file workspaceBootstrapCheckpointFile
	if json.Unmarshal(initial, &file) != nil {
		t.Fatal("invalid checkpoint test fixture")
	}
	file.Payload.Ciphertext[0] ^= 1
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := OpenWorkspaceBootstrapCheckpoint(ctx, scope, tampered, password, ask); c != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("tampered checkpoint was accepted", err)
	}
}
