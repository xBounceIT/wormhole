package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultInput(t *testing.T, fields map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func vaultTestUnlockReceipt(t *testing.T, raw []byte) bool {
	t.Helper()
	var result struct {
		Unlocked     bool  `json:"unlocked"`
		LockedMemory *bool `json:"lockedMemory"`
	}
	if json.Unmarshal(raw, &result) != nil || !result.Unlocked || result.LockedMemory == nil {
		t.Fatalf("invalid unlock receipt: %s", raw)
	}
	return *result.LockedMemory
}

func TestVaultUnlockFormattedRecoveryCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	doc, key := pendingVault(t, path)
	defer vault.Wipe(key)
	code, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	for _, mode := range []string{"short", "checksum", "wrong-key", "mixed-raw", "password", "ask"} {
		fields := map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code}
		switch mode {
		case "short":
			fields["recoveryCode"] = code[:75]
		case "checksum":
			wrong := append([]byte(nil), code...)
			wrong[7] = 'A'
			if wrong[7] == code[7] {
				wrong[7] = 'B'
			}
			fields["recoveryCode"] = wrong
		case "mixed-raw":
			fields["recoveryKey"] = bytes.Repeat([]byte{0x32}, 32)
		case "wrong-key":
			wrong, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{0x33}, 32))
			if err != nil {
				t.Fatal(err)
			}
			fields["recoveryCode"] = wrong
		case "password":
			fields["password"] = []byte("wrong")
		case "ask":
			fields["ask"] = bytes.Repeat([]byte{1}, 32)
		}
		if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, fields)); err == nil {
			t.Fatal("invalid recovery code accepted", mode)
		}
		if h.owner != nil {
			t.Fatal("failed code retained owner")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed code opened database")
		}
	}
	input, err := decodeVaultUnlock(vaultInput(t, map[string]any{"recoveryCode": code}))
	if err != nil {
		t.Fatal(err)
	}
	borrowed := input.RecoveryCode
	input.wipe()
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("code not erased")
	}
	if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code})); err != nil {
		t.Fatal(err)
	}
	if h.owner == nil {
		t.Fatal("code did not unlock")
	}
}

func TestVaultUnlockWholeFileEncryption(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace #%.db")
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	doc.Initializing, doc.Encrypted = true, true
	if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stage := vaultStagingPath(path, doc)
	const interrupted = "interrupted staging ciphertext"
	if err := os.WriteFile(stage, []byte(interrupted), 0600); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{0xFF}, 32)
	if o, err := openVaultFiles(ctx, path, doc, wrong); o != nil || !errors.Is(err, vault.ErrKeyCheck) {
		t.Fatalf("invalid KCV touched the database path: %v", err)
	}
	if raw, err := os.ReadFile(stage); err != nil || string(raw) != interrupted {
		t.Fatalf("invalid KCV changed the stage: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid KCV published a database")
	}
	missingParent := filepath.Join(t.TempDir(), "removed-workspace-directory", "vault.db")
	if o, err := openVaultFiles(ctx, missingParent, doc, key); o != nil || err != vaultstore.ErrStorage {
		t.Fatalf("unexpected encrypted stage error: %v", err)
	}

	// The new ciphertext file reached the destination but the slot marker
	// still says initializing. The next unlock must authenticate this file.
	syncDirectory := privateFileDirectorySync
	func() {
		defer func() { privateFileDirectorySync = syncDirectory }()
		privateFileDirectorySync = func(string) error { return errors.New("interrupted directory sync") }
		if o, err := openVaultFiles(ctx, path, doc, key); o != nil || !errors.Is(err, errVaultSlotCommitUncertain) {
			t.Fatalf("publication interruption did not leave a resumable marker: %v", err)
		}
	}()
	if raw, err := os.ReadFile(path); err != nil || len(raw) == 0 || bytes.Contains(raw, []byte("SQLite format 3")) {
		t.Fatalf("interrupted publication did not leave a ciphertext database: %v", err)
	}

	open := func(t *testing.T) *vaultFoundationHandler {
		t.Helper()
		h := &vaultFoundationHandler{databasePath: path}
		t.Cleanup(func() { _ = h.Close() })
		input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
		if _, err := h.Handle(ctx, "unlock", input); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := open(t)
	const metadata = "metadata-that-must-be-encrypted-on-disk"
	node := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: metadata, Kind: 0}
	if _, err := h.owner.PutNode(ctx, node, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	doc, err = readVaultSlotFile(path)
	if err != nil || doc.Initializing || !doc.Encrypted || doc.Sequence != 2 {
		t.Fatalf("encrypted initialization did not finish: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("staging file was retained")
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(metadata)) || bytes.Contains(ciphertext, []byte("SQLite format 3")) {
		t.Fatal("database contains plaintext metadata")
	}
	if s, err := vaultstore.OpenSQLite(ctx, path, localVaultOptions(doc).Identity, false); s != nil || err != vaultstore.ErrStorage {
		t.Fatalf("plaintext driver opened ciphertext: %v", err)
	}
	h = open(t)
	if got, err := h.owner.ReadNode(ctx, node.ID, 1); err != nil || got.Name != metadata {
		t.Fatalf("encrypted node failed to reopen: %v", err)
	}
}

func TestVaultUnlockHandlerOwnsDatabaseAndKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	ctx := context.Background()
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	password, recovery := []byte("native-password-fixture"), bytes.Repeat([]byte{0x23}, 32)
	response, err := h.Handle(ctx, "initialize", vaultInput(t, map[string]any{"password": password, "recoveryKey": recovery}))
	if err != nil {
		t.Fatal(err)
	}
	if h.owner == nil {
		t.Fatal("no database owner")
	}
	if vaultTestUnlockReceipt(t, response) != h.owner.LockedMemory() {
		t.Fatal("receipt does not match the native owner")
	}
	if _, err := h.Handle(ctx, "unlock", json.RawMessage(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: uuid.NewString(), Field: "password"}
	if _, err := h.owner.Put(ctx, ref, []byte("saved-secret"), 0); err != nil {
		t.Fatal(err)
	}
	status, err := h.Handle(ctx, "status", nil)
	if err != nil || !bytes.Contains(status, []byte(`"unlocked":true`)) || !bytes.Contains(status, []byte(`"protectionAvailable":false`)) {
		t.Fatalf("status: %s %v", status, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "status", nil); err != vaultwire.ErrProtocol {
		t.Fatal("closed handler reused")
	}
	doc, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range doc.Slots {
		opened := &vaultFoundationHandler{databasePath: path}
		input := map[string]any{"vaultId": doc.VaultID, "slotId": slot.ID}
		if slot.Kind == vault.SlotPassword {
			input["password"] = password
		} else {
			input["recoveryKey"] = recovery
		}
		if _, err := opened.Handle(ctx, "unlock", vaultInput(t, input)); err != nil {
			t.Fatal(err)
		}
		if err := opened.owner.WithSecret(ctx, ref, 1, func(value []byte) error {
			if string(value) != "saved-secret" {
				t.Error("secret mismatch")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultUnlockRejectsInvalidFactorsAndKeepsDatabaseClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	doc, key := pendingVault(t, path)
	defer vault.Wipe(key)
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	good := map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["vaultId"] = uuid.NewString() },
		func(m map[string]any) { m["slotId"] = uuid.NewString() },
		func(m map[string]any) { m["recoveryKey"] = bytes.Repeat([]byte{1}, 32) },
		func(m map[string]any) { m["password"] = []byte("wrong factor") },
		func(m map[string]any) { m["ask"] = bytes.Repeat([]byte{1}, 32) },
		func(m map[string]any) { delete(m, "recoveryKey") },
	} {
		input := make(map[string]any)
		for k, v := range good {
			input[k] = v
		}
		change(input)
		if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, input)); err == nil {
			t.Fatal("bad factors accepted")
		}
		if h.owner != nil {
			t.Fatal("failed unlock retained owner")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("bad factors touched SQLite")
		}
	}
	if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, good)); err != nil {
		t.Fatal(err)
	}
}

func TestVaultUnlockStrictInputAndWiping(t *testing.T) {
	h := &vaultFoundationHandler{}
	if !h.ExitOnCancel("initialize") || !h.ExitOnCancel("unlock") || h.ExitOnCancel("status") {
		t.Fatal("authentication cancellation policy")
	}
	secret := []byte("sensitive-input")
	valid := vaultInput(t, map[string]any{"vaultId": uuid.NewString(), "slotId": uuid.NewString(), "password": secret, "ask": bytes.Repeat([]byte{1}, 32)})
	input, err := decodeVaultUnlock(valid)
	if err != nil || !bytes.Equal(input.Password, secret) {
		t.Fatal(err)
	}
	borrowed := input.Password
	input.wipe()
	if !bytes.Equal(borrowed, make([]byte, len(secret))) {
		t.Fatal("factor not wiped")
	}
	for _, raw := range [][]byte{
		nil, bytes.Repeat([]byte("x"), 8193), []byte(`null`), []byte(`[]`), []byte(`{`), []byte(`{"password":`),
		[]byte(`{"password":null}`), []byte(`{"password":[]}`), []byte(`{"password":"???"}`), []byte(`{"Password":"eA=="}`),
		[]byte(`{"password":"eA==","password":"eQ=="}`), []byte(`{"password":"eA==","pass\u0077ord":"eQ=="}`),
		[]byte(`{"password":"eA==","unknown":1}`), []byte(`{} {}`), []byte(`{"vaultId":1}`), []byte(`{"slotId":[]}`),
		vaultInput(t, map[string]any{"password": bytes.Repeat([]byte{1}, 1025)}),
		vaultInput(t, map[string]any{"recoveryKey": bytes.Repeat([]byte{1}, 31)}),
		vaultInput(t, map[string]any{"ask": bytes.Repeat([]byte{1}, 33)}),
	} {
		input, err := decodeVaultUnlock(raw)
		input.wipe()
		if err == nil {
			t.Fatal("malformed secret request accepted")
		}
		if len(input.Password) > 0 && !bytes.Equal(input.Password, make([]byte, len(input.Password))) {
			t.Fatal("partial decode retained password")
		}
	}
}

func TestVaultInitializeRefusesInvalidInputsAndExistingWorkspace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	for _, fields := range []map[string]any{
		{"password": []byte("password"), "recoveryKey": bytes.Repeat([]byte{1}, 32), "recoveryCode": bytes.Repeat([]byte{1}, 76)},
		{}, {"password": []byte("x")}, {"recoveryKey": bytes.Repeat([]byte{1}, 32)},
		{"password": []byte("x"), "recoveryKey": bytes.Repeat([]byte{1}, 32), "vaultId": uuid.NewString()},
		{"password": []byte("x"), "recoveryKey": bytes.Repeat([]byte{1}, 32), "ask": bytes.Repeat([]byte{1}, 32)},
	} {
		if _, err := h.Handle(context.Background(), "initialize", vaultInput(t, fields)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("legacy data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(context.Background(), "initialize", vaultInput(t, map[string]any{"password": []byte("x"), "recoveryKey": bytes.Repeat([]byte{1}, 32)})); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if h.owner != nil {
		t.Fatal("existing workspace overwritten")
	}
	missing := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "missing")}
	if _, err := missing.Handle(context.Background(), "unlock", json.RawMessage(`{}`)); err != errVaultSlotMissing {
		t.Fatal(err)
	}
}

func TestVaultUnlockPasswordPolicyAndWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	for _, preset := range []vault.KDFPreset{vault.KDFLow, vault.KDFV1} {
		slot, err := vault.CreatePasswordSlot(context.Background(), doc.VaultID, uuid.NewString(), 1, key, []byte("correct"), nil, preset)
		if err != nil {
			t.Fatal(err)
		}
		doc.Slots = []vault.Slot{slot}
		doc.Sequence = 1
		raw, err := vault.EncodeSlotFile(key, doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vaultSlotPath(path), raw, 0600); err != nil {
			t.Fatal(err)
		}
		h := &vaultFoundationHandler{databasePath: path}
		fields := map[string]any{"vaultId": doc.VaultID, "slotId": slot.ID, "password": []byte("wrong")}
		want := vault.ErrAuthentication
		if preset == vault.KDFLow {
			want = vault.ErrPolicy
		}
		if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, fields)); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if preset == vault.KDFV1 {
			fields["recoveryKey"] = bytes.Repeat([]byte{1}, 32)
			if _, err := h.Handle(context.Background(), "unlock", vaultInput(t, fields)); err != vaultwire.ErrProtocol {
				t.Fatal(err)
			}
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("wrong password opened DB")
		}
	}
}

func TestVaultUnlockCLIProcessOwnsAndClosesDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	recovery := bytes.Repeat([]byte{0x47}, 32)
	for _, operation := range []string{"initialize", "unlock"} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultCLIProcess$")
		cmd.Env = append(os.Environ(), "WORMHOLE_TEST_VAULT_CHILD=1", "WORMHOLE_TEST_VAULT_DATABASE="+path)
		var diagnostics strings.Builder
		cmd.Stderr = &diagnostics
		in, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		fields := map[string]any{"password": []byte("process-password"), "recoveryKey": recovery}
		if operation == "unlock" {
			doc, err := readVaultSlotFile(path)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			fields = map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[1].ID, "recoveryKey": recovery}
		}
		if err := json.NewEncoder(in).Encode(vaultwire.Request{Version: 1, ID: 1, Operation: operation, Payload: vaultInput(t, fields)}); err != nil {
			cancel()
			t.Fatal(err)
		}
		decoder := json.NewDecoder(out)
		var result vaultwire.Response
		if err := decoder.Decode(&result); err != nil {
			cancel()
			t.Fatal(err)
		}
		if result.Error != "" {
			cancel()
			t.Fatalf("unlock result: %+v", result)
		}
		vaultTestUnlockReceipt(t, result.Result)
		doc, err := readVaultSlotFile(path)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if second, err := vaultstore.OpenSQLite(context.Background(), path, localVaultOptions(doc).Identity, false); err != vaultstore.ErrBusy {
			if second != nil {
				second.Close()
			}
			cancel()
			t.Fatalf("process did not own database: %v", err)
		}
		if err := json.NewEncoder(in).Encode(vaultwire.Request{Version: 1, ID: 2, Operation: "lock"}); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			cancel()
			t.Fatalf("vault process failed: %v %s", err, diagnostics.String())
		}
		cancel()
		if diagnostics.Len() != 0 {
			t.Fatal("unlock wrote diagnostics")
		}
		reopened, err := vaultstore.OpenSQLite(context.Background(), path, localVaultOptions(doc).Identity, false)
		if err != nil {
			t.Fatal(err)
		}
		reopened.Close()
	}
}

func TestVaultUnlockStorageFailureRetiresAuthenticatedSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lost.db")
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path}
	defer h.Close()
	input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
	if _, err := h.Handle(context.Background(), "unlock", input); !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, vaultstore.ErrMissing) {
		t.Fatal(err)
	}
	if !h.closed || h.owner != nil {
		t.Fatal("authenticated failure left reusable session")
	}
	if _, err := h.Handle(context.Background(), "status", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestVaultUnlockCancellationAfterDatabaseOpenClosesOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	doc, key := pendingVault(t, path)
	defer vault.Wipe(key)
	h := &vaultFoundationHandler{databasePath: path}
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	originalSync := privateFileDirectorySync
	defer func() { privateFileDirectorySync = originalSync }()
	calls := 0
	privateFileDirectorySync = func(directory string) error {
		calls++
		if calls == 2 {
			close(entered)
			<-release
		}
		return originalSync(directory)
	}
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() { serveErr = vaultwire.Serve(ctx, ir, ow, h, 5*time.Second); close(done) }()
	defer func() {
		cancel()
		unblock()
		iw.Close()
		or.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("vault cleanup did not finish")
		}
	}()
	input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
	if err := json.NewEncoder(iw).Encode(vaultwire.Request{Version: 1, ID: 1, Operation: "unlock", Payload: input}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("did not reach finalization")
	}
	if err := json.NewEncoder(iw).Encode(vaultwire.Request{Version: 1, ID: 2, Operation: "cancel", TargetID: 1}); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case <-done:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled unlock did not exit")
	}
	if !h.closed {
		t.Fatal("cancelled authentication kept handler alive")
	}
	if h.owner != nil && h.owner.LockedMemory() {
		t.Fatal("cancelled authentication retained key")
	}
	reopened, err := vaultstore.OpenSQLite(context.Background(), path, localVaultOptions(doc).Identity, false)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
