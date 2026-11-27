package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func enableBitwardenCLIUnlock(t *testing.T, path string) bitwardenCliSettings {
	t.Helper()
	settings := defaultBitwardenCliSettings()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings.Enabled, settings.Path = true, executable
	if err := writeBitwardenCliSettings(path, settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func beginBitwardenCLIUnlockFixture(t *testing.T, h *vaultFoundationHandler, ctx context.Context) vault.BitwardenCLIUnlockBinding {
	t.Helper()
	raw, err := h.Handle(ctx, "bitwarden-cli-unlock-begin", nil)
	var binding vault.BitwardenCLIUnlockBinding
	if err != nil || json.Unmarshal(raw, &binding) != nil || binding.Validate(time.Now()) != nil {
		t.Fatal("could not begin native Bitwarden unlock", err)
	}
	return binding
}

func buildBitwardenUnlockCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "main.go"), filepath.Join(dir, "bw.exe")
	program := `package main
import ("bufio"; "fmt"; "os"; "slices")
func main() {
	if len(os.Args) != 6 || !slices.Equal(os.Args[1:3], []string{"unlock", "--passwordfile"}) ||
		!slices.Equal(os.Args[4:], []string{"--raw", "--nointeraction"}) ||
		os.Getenv("WORMHOLE_BW_PASSWORD") != "" || os.Getenv("BW_SESSION") != "" {
		os.Exit(1)
	}
	f, err := os.Open(os.Args[3])
	if err != nil { os.Exit(2) }
	got, err := bufio.NewReader(f).ReadString('\n')
	f.Close()
	if err != nil || got != "  synthetic rénewal 🔒  \n" { os.Exit(3) }
	fmt.Print("fixture-cli-interoperable")
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("go", "build", "-o", executable, source).CombinedOutput(); err != nil {
		t.Fatalf("could not build CLI fixture: %v\n%s", err, output)
	}
	return executable
}

func TestVaultBitwardenCLIUnlockExternalPasswordPipe(t *testing.T) {
	settings := defaultBitwardenCliSettings()
	settings.Path = buildBitwardenUnlockCLI(t)
	t.Setenv(bitwardenCliPasswordEnvVar, "must-not-be-inherited")
	t.Setenv("BW_SESSION", "must-not-be-inherited")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := unlockVaultBitwardenCLI(ctx, settings, []byte("  synthetic rénewal 🔒  "))
	if err != nil || session != "fixture-cli-interoperable" {
		t.Fatal("password was not delivered over the protected pipe", err)
	}
	if _, err := unlockVaultBitwardenCLI(ctx, settings, []byte("invalid\nsecond line")); err == nil {
		t.Fatal("multiline input accepted")
	}
	if _, err := unlockVaultBitwardenCLI(ctx, settings, []byte("wrong password")); err == nil {
		t.Fatal("failed CLI was accepted")
	}
}

func TestVaultBitwardenCLIUnlockSenderInteropFixture(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_BITWARDEN_UNLOCK_INTEROP") != "1" {
		t.Skip("requires a protected document sender")
	}
	h := vaultCredentialFixture(t)
	settings := enableBitwardenCLIUnlock(t, h.databasePath)
	settings.Path = buildBitwardenUnlockCLI(t)
	if err := writeBitwardenCliSettings(h.databasePath, settings); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	binding := beginBitwardenCLIUnlockFixture(t, h, ctx)
	if err := json.NewEncoder(os.Stdout).Encode(binding); err != nil {
		t.Fatal(err)
	}
	var reply bytes.Buffer
	output := io.MultiWriter(&reply, os.Stdout)
	err := serveVaultBitwardenCLIUnlock(ctx, os.Stdin, output, h.databasePath, unlockVaultBitwardenCLI)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&reply)
	if !scanner.Scan() || !scanner.Scan() {
		t.Fatal("missing sealed result")
	}
	req := vaultInput(t, map[string]any{"requestId": binding.RequestID, "session": json.RawMessage(scanner.Bytes())})
	ack, err := h.Handle(ctx, "bitwarden-cli-unlock-commit", req)
	if err != nil || string(ack) != "{\"unlocked\":true}" {
		t.Fatal("renewal refused", err)
	}
	if _, err := os.Stdout.Write(append(ack, '\n')); err != nil {
		t.Fatal(err)
	}
}

func TestVaultBitwardenCLIUnlockRejectsInvalidWorkerExchange(t *testing.T) {
	for _, mode := range []string{"binding", "authentication", "CLI failure", "CLI invalid response", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			h := vaultCredentialFixture(t)
			enableBitwardenCLIUnlock(t, h.databasePath)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			binding := beginBitwardenCLIUnlockFixture(t, h, ctx)
			input, sender := io.Pipe()
			receiver, output := io.Pipe()
			defer sender.Close()
			defer receiver.Close()
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				defer output.Close()
				done <- serveVaultBitwardenCLIUnlock(ctx, input, output, h.databasePath, func(ctx context.Context, _ bitwardenCliSettings, _ []byte) (string, error) {
					close(entered)
					switch mode {
					case "CLI failure":
						return "", vault.ErrAuthentication
					case "CLI invalid response":
						return "embedded\x00nul", nil
					case "cancel":
						<-ctx.Done()
						return "must-not-be-sealed-after-cancel", nil
					default:
						t.Error("invalid input reached the CLI")
						return "", vault.ErrAuthentication
					}
				})
			}()
			rd := bufio.NewReader(receiver)
			line, err := rd.ReadBytes('\n')
			var recipient struct{ PublicKey []byte }
			if err != nil || json.Unmarshal(line, &recipient) != nil {
				t.Fatal("worker key unavailable", err)
			}
			sealed, err := vault.SealBitwardenCLIPassword(recipient.PublicKey, binding, []byte("fixture"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "binding" {
				binding.Configuration = "not-the-configuration"
			}
			if mode == "authentication" {
				sealed.Ciphertext[0] ^= 0x80
			}
			data := vaultInput(t, map[string]any{"binding": binding, "password": sealed})
			if _, err := sender.Write(append(data, '\n')); err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("worker did not begin")
				}
				_ = sender.Close()
			}
			if line, err := rd.ReadBytes('\n'); len(line) != 0 || err != io.EOF {
				t.Fatal("worker returned a grant after failure", err)
			}
			if err := <-done; err == nil {
				t.Fatal("worker accepted a failed request")
			}
		})
	}
	t.Run("relative path is rejected with a fixed diagnostic", func(t *testing.T) {
		for _, options := range [][]string{{"--sealed-bitwarden-unlock"}, {"--sealed-bitwarden-unlock", "--sealed-ssh-bitwarden"}} {
			input, writer := io.Pipe()
			var output, diagnostic bytes.Buffer
			args := append([]string{"--operation", "serve", "--database", "relative"}, options...)
			code := runBackendCLI(args, input, &output, &diagnostic)
			_ = input.Close()
			_ = writer.Close()
			if code != 1 || output.Len() != 0 || diagnostic.String() != "vault_bitwarden_unavailable\n" {
				t.Fatal("unexpected native diagnostic")
			}
		}
	})
}

func TestVaultBitwardenCLIUnlockRoundTrip(t *testing.T) {
	h := vaultCredentialFixture(t)
	settings := enableBitwardenCLIUnlock(t, h.databasePath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	binding := beginBitwardenCLIUnlockFixture(t, h, ctx)
	if _, err := h.Handle(ctx, "bitwarden-cli-unlock-begin", nil); err == nil {
		t.Fatal("second owner could replace the pending unlock")
	}
	input, sender := io.Pipe()
	receiver, output := io.Pipe()
	defer sender.Close()
	defer receiver.Close()
	password := []byte("  synthetic master password ")
	session := "synthetic-cli-session"
	stopped := make(chan error, 1)
	go func() {
		defer output.Close()
		stopped <- serveVaultBitwardenCLIUnlock(ctx, input, output, h.databasePath, func(_ context.Context, cli bitwardenCliSettings, input []byte) (string, error) {
			if cli.Path != settings.Path || !bytes.Equal(input, password) {
				t.Error("native CLI received the wrong request")
				return "", vault.ErrAuthentication
			}
			return session, nil
		})
	}()
	reader := bufio.NewReader(receiver)
	line, err := reader.ReadBytes('\n')
	var recipient struct{ PublicKey []byte }
	if err != nil || json.Unmarshal(line, &recipient) != nil || len(recipient.PublicKey) != 32 {
		t.Fatal("resolver recipient unavailable", err)
	}
	sealed, err := vault.SealBitwardenCLIPassword(recipient.PublicKey, binding, password, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := vaultInput(t, map[string]any{"binding": binding, "password": sealed})
	if bytes.Contains(request, password) || bytes.Contains(request, []byte(base64.StdEncoding.EncodeToString(password))) {
		t.Fatal("password crossed the relay unsealed")
	}
	if _, err := sender.Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadBytes('\n')
	if err != nil || bytes.Contains(line, []byte(session)) ||
		bytes.Contains(line, []byte(base64.StdEncoding.EncodeToString([]byte(session)))) {
		t.Fatal("CLI session crossed the relay unsealed", err)
	}
	var sessionEnvelope vault.SealedBundle
	if err := json.Unmarshal(line, &sessionEnvelope); err != nil {
		t.Fatal(err)
	}
	commit := vaultInput(t, map[string]any{"requestId": binding.RequestID, "session": sessionEnvelope})
	if got, err := h.Handle(ctx, "bitwarden-cli-unlock-commit", commit); err != nil || string(got) != "{\"unlocked\":true}" {
		t.Fatal("could not commit authenticated session", err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	err = h.owner.WithLocalState(ctx, "bitwarden-cli", binding.WorkspaceID, 1, func(payload []byte) error {
		var stored bitwardenSavedSession
		if json.Unmarshal(payload, &stored) != nil || stored.Path != settings.Path || stored.Region != settings.ServerRegion || stored.Key != session {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		t.Fatal("protected storage did not hold the session", err)
	}
	if _, err := h.Handle(ctx, "bitwarden-cli-unlock-commit", commit); err == nil {
		t.Fatal("replayed session")
	}
}

func TestVaultBitwardenCLIUnlockRejectsStaleState(t *testing.T) {
	for _, mode := range []string{"path", "version", "cancel", "malformed", "unknown-request"} {
		t.Run(mode, func(t *testing.T) {
			h := vaultCredentialFixture(t)
			settings := enableBitwardenCLIUnlock(t, h.databasePath)
			ctx := context.Background()
			binding := beginBitwardenCLIUnlockFixture(t, h, ctx)
			now := time.Now()
			session, err := vault.SealBitwardenCLISession(binding, vaultInput(t, map[string]any{
				"path": settings.Path, "region": settings.ServerRegion, "key": "synthetic-session",
			}), now)
			if err != nil {
				t.Fatal(err)
			}
			request := map[string]any{"requestId": binding.RequestID, "session": session}
			switch mode {
			case "path":
				settings.ServerRegion = (settings.ServerRegion + 1) % 3
				if err := writeBitwardenCliSettings(h.databasePath, settings); err != nil {
					t.Fatal(err)
				}
			case "version":
				if _, err := h.owner.PutLocalState(ctx, "bitwarden-cli", binding.WorkspaceID, []byte("newer"), 0); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				for range 2 {
					if _, err := h.Handle(ctx, "bitwarden-cli-unlock-cancel", vaultInput(t, map[string]any{"requestId": binding.RequestID})); err != nil {
						t.Fatal(err)
					}
				}
			case "malformed":
				request["session"] = map[string]any{}
			case "unknown-request":
				request["requestId"] = binding.WorkspaceID
			}
			if _, err := h.Handle(ctx, "bitwarden-cli-unlock-commit", vaultInput(t, request)); err == nil {
				t.Fatal("stale session was published")
			}
			if mode != "unknown-request" && h.bitwardenCLIUnlock != nil {
				t.Fatal("consumed session kept its recipient")
			}
		})
	}
}
