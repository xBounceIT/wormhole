package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func sealedRDPFixtureBinding() vault.BundleBinding {
	return vault.BundleBinding{WorkspaceID: uuid.NewString(), NodeID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), Protocol: "rdp", Host: "rdp.example", Port: 3389, Epoch: 1}
}
func sealedRDPFixtureOpening(t *testing.T, b vault.BundleBinding) map[string]any {
	t.Helper()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	raw, _ := vault.EncodeRDPBundle(vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings()})
	defer vault.Wipe(raw)
	bundle, _ := vault.SealBundle(key.PublicKey().Bytes(), b, raw)
	return map[string]any{"binding": b, "bundle": bundle, "ownerWindow": "1", "bounds": map[string]any{"x": 0, "y": 0, "width": 800, "height": 600}}
}
func TestSealedRDPOpeningRejectsSubstitutionAndUnboundedSurface(t *testing.T) {
	b := sealedRDPFixtureBinding()
	good := sealedRDPFixtureOpening(t, b)
	if opening, err := decodeSealedRDPOpening(vaultInput(t, good)); err != nil || opening.requireContentProtection {
		t.Fatal(err)
	}
	protected := sealedRDPFixtureOpening(t, b)
	protected["requireContentProtection"] = true
	opening, err := decodeSealedRDPOpening(vaultInput(t, protected))
	if runtime.GOOS == "windows" {
		if err != nil || !opening.requireContentProtection {
			t.Fatal("capture requirement lost", err)
		}
	} else if err != vaultwire.ErrProtocol {
		t.Fatal("unsupported platform accepted Windows capture requirement", err)
	}
	for _, bad := range []any{false, "true", nil, 1} {
		protected["requireContentProtection"] = bad
		if _, err := decodeSealedRDPOpening(vaultInput(t, protected)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid capture requirement accepted", bad, err)
		}
	}
	for _, visible := range []bool{false, true} {
		q := sealedRDPFixtureOpening(t, b)
		q["visible"] = visible
		value, err := decodeSealedRDPOpening(vaultInput(t, q))
		if err != nil || value.visible == nil || *value.visible != visible {
			t.Fatal("visibility intent lost", err)
		}
	}
	for _, mode := range []string{"visible-null", "visible-string", "extra", "bounds-extra", "bounds-missing", "bounds-large", "owner", "binding", "cipher-shape", "endpoint", "route-protocol"} {
		q := sealedRDPFixtureOpening(t, b)
		switch mode {
		case "visible-null":
			q["visible"] = nil
		case "visible-string":
			q["visible"] = "false"
		case "extra":
			q["password"] = "forbidden"
		case "bounds-extra":
			q["bounds"].(map[string]any)["secret"] = true
		case "bounds-missing":
			delete(q["bounds"].(map[string]any), "width")
		case "bounds-large":
			q["bounds"].(map[string]any)["width"] = 16385
		case "owner":
			q["ownerWindow"] = "01"
		case "binding":
			bad := b
			bad.WorkspaceID = "bad"
			q["binding"] = bad
		case "cipher-shape":
			q["bundle"] = map[string]any{"password": "no"}
		case "endpoint":
			q["endpoint"] = "remote:1"
		case "route-protocol":
			bad := b
			bad.Protocol = "ssh"
			bad.TunnelConfigID = uuid.NewString()
			q["binding"] = vault.TunnelBundleBinding{BundleBinding: bad, FileID: uuid.NewString(), RowVersion: 1, ConfigurationVersion: 1}
			q["endpoint"] = "127.0.0.1:1080"
		}
		if _, err := decodeSealedRDPOpening(vaultInput(t, q)); err == nil {
			t.Fatal(mode)
		}
	}
	routeBinding := b
	routeBinding.TunnelConfigID = uuid.NewString()
	route := vault.TunnelBundleBinding{BundleBinding: routeBinding, FileID: uuid.NewString(), RowVersion: 1, ConfigurationVersion: 1}
	q := sealedRDPFixtureOpening(t, b)
	q["binding"] = route
	q["endpoint"] = "127.0.0.1:1080"
	if _, err := decodeSealedRDPOpening(vaultInput(t, q)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*vault.BundleBinding){func(b *vault.BundleBinding) { b.Protocol = "ssh" }, func(b *vault.BundleBinding) { b.UseExternalClient = true }, func(b *vault.BundleBinding) { b.Epoch = 0 }, func(b *vault.BundleBinding) { b.Epoch = 1 << 53 }, func(b *vault.BundleBinding) { b.Port = 0 }, func(b *vault.BundleBinding) { b.Host = "bad host" }, func(b *vault.BundleBinding) { b.TunnelConfigID = uuid.NewString() }} {
		bad := b
		mutate(&bad)
		if validRDPConnectionBinding(bad, false) {
			t.Fatal("invalid RDP binding accepted")
		}
	}
}

func TestRDPContentProtectionRejectsExternalClientBeforeLaunch(t *testing.T) {
	var events []rdpEvent
	controller := rdpController{output: func(event rdpEvent) { events = append(events, event) }}
	for _, profile := range []rdpProfile{
		{UseExternalClient: true},
		{Username: "AzureAD\\person"},
	} {
		controller.start(rdpCommand{SessionID: "rdp", RequestID: "request", Profile: profile, requireContentProtection: true})
	}
	if len(events) != 2 {
		t.Fatal(events)
	}
	for _, event := range events {
		if event.Type != "error" || event.Message != "RDP content protection is unavailable" || event.RequestID != "request" {
			t.Fatal(event)
		}
	}
}
func TestSealedRDPCommandsAcceptOnlySessionScopedPublicControls(t *testing.T) {
	session := uuid.NewString()
	for _, op := range []string{"resize", "show", "hide", "focus", "disconnect", "app-lock", "input", "certificate"} {
		q := map[string]any{"op": op, "sessionId": session, "requestId": uuid.NewString()}
		if op == "resize" || op == "show" {
			q["bounds"] = map[string]any{"x": 0, "y": 0, "width": 800, "height": 600}
		}
		if op == "input" {
			q["input"] = map[string]any{"kind": "key", "code": 30, "down": true}
		}
		if op == "certificate" {
			q["certificateAccepted"] = true
		}
		if _, err := decodeSealedRDPCommand(vaultInput(t, q), session); err != nil {
			t.Fatal(op, err)
		}
		for _, mutation := range []string{"owner", "extra", "id", "bounds", "input"} {
			bad := cloneSFTPPacket(q)
			switch mutation {
			case "owner":
				bad["sessionId"] = uuid.NewString()
			case "extra":
				bad["password"] = "forbidden"
			case "id":
				bad["requestId"] = "bad"
			case "bounds":
				if op != "resize" && op != "show" {
					continue
				}
				bad["bounds"] = map[string]any{"x": 0, "y": 0, "width": 800, "height": 600, "secret": true}
			case "input":
				if op != "input" {
					continue
				}
				bad["input"] = map[string]any{"kind": "key", "code": 0}
			}
			if _, err := decodeSealedRDPCommand(vaultInput(t, bad), session); err == nil {
				t.Fatal("command substitution", op, mutation)
			}
		}
	}
	for _, raw := range [][]byte{[]byte("{"), []byte(strings.Repeat("x", 8193)), []byte(`{"op":"connect"}`), []byte(`{"op":"input"}`)} {
		if _, err := decodeSealedRDPCommand(raw, session); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	p := vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings(), GatewayUsername: "user", GatewayDomain: "EDGE"}
	profile := rdpProfileFromBundle(sealedRDPFixtureBinding(), p)
	if profile.GatewayUsername != "EDGE\\user" || profile.ServerAuthentication == nil || *profile.ServerAuthentication != 2 || profile.Password != "" {
		t.Fatal("public RDP profile")
	}
}
func TestSealedRDPProcessRejectsCiphertextBeforeLaunching(t *testing.T) {
	for _, mode := range []string{
		"tamper", "binding", "payload", "valid-missing-adapter", "early-eof", "manual-saved",
		"manual-inner", "manual-outer", "manual-valid", "manual-eof", "bitwarden-valid", "bitwarden-missing",
		"bitwarden-foreign", "manual-bitwarden", "manual-gateway-bitwarden-valid", "manual-gateway-bitwarden-missing",
		"manual-gateway-bitwarden-foreign", "manual-gateway-bitwarden-document", "saved-gateway-bitwarden",
	} {
		t.Run(mode, func(t *testing.T) {
			input, writer := io.Pipe()
			events, output := io.Pipe()
			defer writer.Close()
			defer events.Close()
			c := &rdpController{nativeHostPath: filepath.Join(t.TempDir(), "missing.exe"), freerdpPath: filepath.Join(t.TempDir(), "missing")}
			done := make(chan error, 1)
			go func() {
				err := serveSealedRDPMode(input, output, c, strings.HasPrefix(mode, "manual-"))
				_ = output.Close()
				done <- err
			}()
			scanner := bufio.NewScanner(events)
			if !scanner.Scan() {
				t.Fatal("recipient missing")
			}
			var recipient struct {
				Type      string
				PublicKey []byte
			}
			if json.Unmarshal(scanner.Bytes(), &recipient) != nil || recipient.Type != "recipient" {
				t.Fatal("recipient schema")
			}
			lines := make(chan []byte, 16)
			go func() {
				for scanner.Scan() {
					lines <- bytes.Clone(scanner.Bytes())
				}
				close(lines)
			}()
			if mode == "early-eof" || mode == "manual-eof" {
				_ = writer.Close()
			} else {
				b := sealedRDPFixtureBinding()
				p := vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings(), Password: []byte("native-fixture-password"), PasswordProvided: true}
				plain, _ := vault.EncodeRDPBundle(p)
				var accounts *vault.SealedBundle
				if strings.Contains(mode, "gateway-bitwarden") {
					settings := vault.DefaultRDPSettings()
					settings.GatewayHostname, settings.GatewayUsageMethod = "gateway.example", 1
					lookup := vault.RDPBitwardenLookup{GatewayItemID: uuid.NewString(), Link: bytes.Repeat([]byte{1}, 32)}
					documentBinding := b
					if mode == "manual-gateway-bitwarden-document" {
						documentBinding.RequestID = uuid.NewString()
					}
					inner, e := vault.SealManualRDPCredentials(recipient.PublicKey, documentBinding, nil, "",
						vault.RDPManualCredentials{Username: "temporary", Password: []byte("native-fixture-password")})
					if e != nil {
						t.Fatal(e)
					}
					vault.Wipe(plain)
					plain, e = vault.EncodeManualRDPBitwardenBase(vault.RDPBundlePayload{Settings: settings}, inner, lookup.Link)
					if e != nil {
						t.Fatal(e)
					}
					if mode != "manual-gateway-bitwarden-missing" {
						if mode == "manual-gateway-bitwarden-foreign" {
							lookup.Link[0] = 42
						}
						sealed, e := vault.SealRDPBitwardenAccounts(recipient.PublicKey, b, nil, "", lookup,
							vault.RDPBitwardenAccounts{GatewayUsername: "edge", GatewayPassword: []byte("gateway-fixture-password")})
						if e != nil {
							t.Fatal(e)
						}
						accounts = &sealed
					}
				} else if strings.Contains(mode, "bitwarden") {
					lookup := vault.RDPBitwardenLookup{PrimaryItemID: uuid.NewString(), Link: bytes.Repeat([]byte{1}, 32)}
					vault.Wipe(plain)
					var e error
					plain, e = vault.EncodeRDPBitwardenBase(vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings()}, lookup.Slots(), lookup.Link)
					if e != nil {
						t.Fatal(e)
					}
					if mode != "bitwarden-missing" {
						if mode == "bitwarden-foreign" {
							lookup.Link[0] = 42
						}
						sealed, e := vault.SealRDPBitwardenAccounts(recipient.PublicKey, b, nil, "", lookup, vault.RDPBitwardenAccounts{
							Username: "resolved", Password: []byte("native-fixture-password"),
						})
						if e != nil {
							t.Fatal(e)
						}
						accounts = &sealed
					}
				} else if strings.HasPrefix(mode, "manual-") && mode != "manual-saved" {
					inner, e := vault.SealManualRDPCredentials(recipient.PublicKey, b, nil, "", vault.RDPManualCredentials{Username: "manual", Password: []byte("native-fixture-password")})
					if e != nil {
						t.Fatal(e)
					}
					if mode == "manual-inner" {
						inner.Ciphertext[0] ^= 1
					}
					vault.Wipe(plain)
					plain, e = vault.EncodeRDPManualAuthorization(vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings()}, inner)
					if e != nil {
						t.Fatal(e)
					}
					if mode == "manual-outer" {
						plain[0] = 1
					}
				}
				if mode == "payload" {
					plain[0] = 2
				}
				bundle, err := vault.SealBundle(recipient.PublicKey, b, plain)
				vault.Wipe(plain)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "tamper" {
					bundle.Ciphertext[0] ^= 1
				}
				if mode == "binding" {
					b.Port++
				}
				q := map[string]any{"binding": b, "bundle": bundle, "ownerWindow": "1", "bounds": rdpBounds{Width: 800, Height: 600}}
				if accounts != nil {
					q["bitwarden"] = *accounts
				}
				if err := json.NewEncoder(writer).Encode(q); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for {
				select {
				case err := <-done:
					if (mode == "bitwarden-valid" || mode == "manual-gateway-bitwarden-valid") && err != nil {
						t.Fatal("native process refused authorized Bitwarden accounts", err)
					}
					if !strings.HasSuffix(mode, "-valid") && mode != "valid-missing-adapter" && err == nil {
						t.Fatal("invalid session succeeded")
					}
					return
				case raw := <-lines:
					if bytes.Contains(raw, []byte("native-fixture-password")) || bytes.Contains(raw, []byte("gateway-fixture-password")) || bytes.Contains(raw, []byte("nativeControl")) {
						t.Fatal("secret/capability leaked")
					}
				case <-ctx.Done():
					t.Fatal("native rejection did not close")
				}
			}
		})
	}
}
func TestSealedRDPCLIBypassesDatabaseStartup(t *testing.T) {
	for _, operation := range []string{"rdp-sealed", "rdp-manual-sealed"} {
		t.Run(operation, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			database := filepath.Join(t.TempDir(), "must-not-exist", "vault.sqlite")
			code := runBackendCLI([]string{"--operation", operation, "--database", database}, strings.NewReader("invalid\n"), &output, &diagnostics)
			if _, err := os.Stat(filepath.Dir(database)); !os.IsNotExist(err) {
				t.Fatal("protocol process touched database startup", err)
			}
			if code != 1 || !bytes.Contains(output.Bytes(), []byte(`"type":"recipient"`)) || !strings.Contains(diagnostics.String(), "sealed_rdp_stopped") {
				t.Fatal("sealed RDP CLI did not isolate startup")
			}

		})
	}
}

func TestSealedRDPForwardsEveryAuthenticatedPublicOption(t *testing.T) {
	settings := vault.DefaultRDPSettings()
	settings.Domain = "DOMAIN"
	settings.ScreenSize = "1280x720"
	settings.RedirectDrives = "C"
	settings.GatewayHostname = "gateway.example"
	settings.GatewayUsageMethod = 1
	values := reflect.ValueOf(&settings).Elem()
	for i := 0; i < values.NumField(); i++ {
		field := values.Field(i)
		if field.Kind() == reflect.Bool && values.Type().Field(i).Name != "UseExternalClient" {
			field.SetBool(true)
		}
	}
	p := vault.RDPBundlePayload{Settings: settings, Username: "remote-user", GatewayUsername: "gateway-user", GatewayDomain: "EDGE"}
	profile := rdpProfileFromBundle(sealedRDPFixtureBinding(), p)
	native := reflect.ValueOf(profile)
	for i := 0; i < values.NumField(); i++ {
		name := values.Type().Field(i).Name
		if name == "GatewayCredentialID" {
			continue
		}
		field := native.FieldByName(name)
		if field.Kind() == reflect.Pointer {
			field = field.Elem()
		}
		if !field.IsValid() || !reflect.DeepEqual(field.Interface(), values.Field(i).Interface()) {
			t.Fatal("native RDP lost authenticated option", name)
		}
	}
	if profile.Username != "remote-user" || profile.GatewayUsername != "EDGE\\gateway-user" || profile.Password != "" || profile.GatewayPassword != "" {
		t.Fatal("native public identity projection")
	}
}

type rdpFixtureWriter func([]byte) (int, error)

func (f rdpFixtureWriter) Write(raw []byte) (int, error) { return f(raw) }
func TestSealedRDPOutputLossStopsOwnedProcess(t *testing.T) {
	// An existing metadata-only subprocess fixture exercises the same native
	// supervisor. It does not touch a real desktop, server or account.
	t.Setenv("WORMHOLE_RDP_TEST_HELPER", "1")
	input, commands := io.Pipe()
	defer commands.Close()
	recipient := make(chan []byte, 1)
	first := true
	output := rdpFixtureWriter(func(raw []byte) (int, error) {
		if first {
			first = false
			var message struct{ PublicKey []byte }
			if json.Unmarshal(raw, &message) != nil {
				return 0, io.ErrClosedPipe
			}
			recipient <- message.PublicKey
			return len(raw), nil
		}
		return 0, io.ErrClosedPipe
	})
	controller := &rdpController{nativeHostPath: os.Args[0], freerdpPath: os.Args[0]}
	done := make(chan error, 1)
	go func() { done <- serveSealedRDP(input, output, controller) }()
	var public []byte
	select {
	case public = <-recipient:
	case err := <-done:
		t.Fatal("recipient creation failed", err)
	case <-time.After(5 * time.Second):
		t.Fatal("recipient timeout")
	}
	binding := sealedRDPFixtureBinding()
	raw, _ := vault.EncodeRDPBundle(vault.RDPBundlePayload{Settings: vault.DefaultRDPSettings()})
	bundle, err := vault.SealBundle(public, binding, raw)
	vault.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(commands).Encode(map[string]any{"binding": binding, "bundle": bundle, "ownerWindow": "1", "bounds": rdpBounds{Width: 800, Height: 600}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("output loss retained native process")
	}
	controller.mu.Lock()
	remaining := len(controller.processes)
	controller.mu.Unlock()
	if remaining != 0 {
		t.Fatal("output loss retained process ownership")
	}
	if err := serveSealedRDP(io.NopCloser(strings.NewReader("")), rdpFixtureWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe }), nil); err != vaultwire.ErrProtocol {
		t.Fatal("recipient output loss", err)
	}
}
