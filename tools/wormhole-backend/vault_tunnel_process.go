package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sealedTunnelStart func(context.Context, vault.TunnelBundleBinding, []byte) (*tunnelProcess, error)
type sealedTunnelOpen func(packet, private []byte) (vault.TunnelBundleBinding, []byte, error)

func openSealedTunnelConfiguration(packet, private []byte) (vault.TunnelBundleBinding, []byte, error) {
	binding, bundle, err := decodeSealedTunnelOpen(packet)
	if err != nil {
		return vault.TunnelBundleBinding{}, nil, err
	}
	configuration, err := vault.OpenTunnelBundle(private, binding, bundle)
	return binding, configuration, err
}

func decodeSealedTunnelOpen(raw []byte) (vault.TunnelBundleBinding, vault.SealedBundle, error) {
	var binding, bundle json.RawMessage
	if decodeVaultObject(raw, map[string]any{"binding": &binding, "bundle": &bundle}, "binding", "bundle") != nil {
		return vault.TunnelBundleBinding{}, vault.SealedBundle{}, vaultwire.ErrProtocol
	}
	return decodeSealedTunnelFields(binding, bundle)
}

func decodeSealedTunnelFields(binding, bundle json.RawMessage) (vault.TunnelBundleBinding, vault.SealedBundle, error) {
	b, err := decodeTunnelBundleBinding(binding)
	var sealed vault.SealedBundle
	if err == nil {
		sealed, err = decodeSealedTunnelEnvelope(bundle)
	}
	if err != nil {
		return vault.TunnelBundleBinding{}, vault.SealedBundle{}, vaultwire.ErrProtocol
	}
	return b, sealed, nil
}

func decodeSealedTunnelEnvelope(raw []byte) (sealed vault.SealedBundle, err error) {
	if decodeVaultObject(raw, map[string]any{"formatVersion": &sealed.FormatVersion, "suiteId": &sealed.SuiteID, "enc": &sealed.Enc, "ciphertext": &sealed.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return vault.SealedBundle{}, vaultwire.ErrProtocol
	}
	return sealed, nil
}
func decodeTunnelBundleBinding(raw []byte) (vault.TunnelBundleBinding, error) {
	var b vault.TunnelBundleBinding
	var row, configuration string
	fields := map[string]any{
		"workspaceId": &b.WorkspaceID, "fileId": &b.FileID, "nodeId": &b.NodeID, "sessionId": &b.SessionID, "requestId": &b.RequestID, "protocol": &b.Protocol,
		"host": &b.Host, "port": &b.Port, "tunnelConfigId": &b.TunnelConfigID, "useExternalClient": &b.UseExternalClient, "epoch": &b.Epoch, "kind": &b.Kind,
		"rowVersion": &row, "configurationVersion": &configuration,
	}
	required := make([]string, 0, len(fields))
	for name := range fields {
		required = append(required, name)
	}
	err := decodeVaultObject(raw, fields, required...)
	if err == nil {
		b.RowVersion, err = vaultCredentialRevision(row, false)
	}
	if err == nil {
		b.ConfigurationVersion, err = vaultCredentialRevision(configuration, false)
	}
	if err != nil {
		return vault.TunnelBundleBinding{}, vaultwire.ErrProtocol
	}
	return b, nil
}

// One recipient and one route per child. Only the native parent receives the
// loopback endpoint. EOF, lock, replay or sidecar exit retires the entire route.
// The starter borrows configuration only until it returns; it must not retain it.
func serveSealedTunnel(input io.ReadCloser, output io.Writer, start sealedTunnelStart) (result error) {
	return serveSealedTunnelWithOpener(input, output, start, openSealedTunnelConfiguration)
}

func serveSealedTunnelWithOpener(input io.ReadCloser, output io.Writer, start sealedTunnelStart, open sealedTunnelOpen) (result error) {
	return serveSealedTunnelActor(input, output, start, open, false)
}

func serveSealedTunnelActor(input io.ReadCloser, output io.Writer, start sealedTunnelStart, open sealedTunnelOpen, primary bool) (result error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer input.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopClosing()
	key, err := securemem.New(32, false)
	if err != nil {
		return err
	}
	defer key.Close()
	var public []byte
	err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return err
		}
		public = private.PublicKey().Bytes()
		return nil
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(sealedSSHOutput{writer: output, cancel: cancel})
	if err := encoder.Encode(struct {
		Type      string `json:"type"`
		PublicKey []byte `json:"publicKey"`
	}{"recipient", public}); err != nil {
		return vaultwire.ErrProtocol
	}
	deadline := time.AfterFunc(30*time.Second, cancel)
	defer deadline.Stop()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), vaultwire.MaxFrameBytes)
	if !scanner.Scan() {
		return vaultwire.ErrProtocol
	}
	var binding vault.TunnelBundleBinding
	var configuration []byte
	err = key.With(func(raw []byte) error {
		var e error
		binding, configuration, e = open(scanner.Bytes(), raw)
		return e
	})
	closeErr := key.Close()
	if err != nil {
		return err
	}
	defer vault.Wipe(configuration)
	if closeErr != nil {
		return closeErr
	}
	var fallbackEligible bool
	if primary {
		replacement, eligible, err := prepareSealedPrimaryTunnel(binding, configuration)
		if err != nil {
			return err
		}
		fallbackEligible = eligible
		if eligible {
			vault.Wipe(configuration)
			configuration = replacement
			defer vault.Wipe(configuration)
		}
	}
	authentication, err := newSealedTunnelAuthentication(binding, configuration)
	if err != nil {
		return err
	}
	if authentication != nil {
		defer authentication.key.Close()
	}
	var interactive sealedTunnelBrowserFlow
	browser, err := newSealedTunnelBrowser(binding, configuration)
	if err != nil {
		return err
	}
	if browser != nil {
		interactive = browser
	}
	cookie, err := newSealedTunnelCookie(binding, configuration)
	if err != nil {
		return err
	}
	if cookie != nil {
		interactive = cookie
	}
	if interactive != nil {
		defer interactive.close()
	}
	var recipient *sealedTunnelControlRecipient
	if authentication != nil {
		recipient = &sealedTunnelControlRecipient{"authentication", authentication.binding.ChallengeID, authentication.response, 16384}
	}
	if interactive != nil {
		recipient = interactive.recipient()
	}
	deadline.Stop()
	deadline = time.AfterFunc(tunnelStartTimeout, cancel)
	defer deadline.Stop()
	// The same reader handles sealed authentication and cancellation through
	// native startup. It never accepts plaintext factors or legacy prompt replies.
	commands := make(chan error, 1)
	go func() { commands <- readSealedTunnelControls(ctx, cancel, scanner, binding, recipient) }()
	defer func() {
		cancel()
		_ = input.Close()
		if commandErr := <-commands; commandErr != nil {
			result = commandErr
		}
	}()
	primaryFailed := false
	defer func() {
		// A provider may fail before creating a sidecar (for example SAML
		// discovery or an unavailable binary). Any owned process retires first
		// through the later defer. Cancelled/declined authentication never opts in.
		if fallbackEligible && primaryFailed && ctx.Err() == nil {
			if err := writeSealedFallbackRequired(encoder, binding); err != nil {
				result = err
			}
		}
	}()
	if authentication != nil {
		replacement, e := authentication.complete(ctx, encoder, configuration)
		if e != nil {
			return e
		}
		vault.Wipe(configuration)
		configuration = replacement
		defer vault.Wipe(configuration)
	}
	launchContext := ctx
	if interactive != nil {
		replacement, e := interactive.complete(ctx, encoder, configuration)
		if e != nil {
			if browser, ok := interactive.(*sealedTunnelBrowser); ok {
				primaryFailed = browser.negotiationFailed
			}
			return e
		}
		vault.Wipe(configuration)
		configuration = replacement
		defer vault.Wipe(configuration)
		launchContext = context.WithValue(ctx, sealedTunnelBrowserKey{}, sealedTunnelBrowserPermit{binding, sha256.Sum256(configuration)})
	}
	process, err := start(launchContext, binding, configuration)
	vault.Wipe(configuration)
	primaryFailed = err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, vault.ErrFormat) && !errors.Is(err, vault.ErrAuthentication) && !errors.Is(err, vaultwire.ErrProtocol)
	if process != nil {
		defer retireSealedTunnel(process)
	}
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if process == nil || !process.alive() || !isLoopbackSocksEndpoint(process.socks) {
		return vaultwire.ErrProtocol
	}
	deadline.Stop()
	if err := encoder.Encode(struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
		Endpoint  string `json:"endpoint"`
	}{"ready", binding.SessionID, process.socks}); err != nil {
		return vaultwire.ErrProtocol
	}
	select {
	case <-ctx.Done():
		// The deferred join owns the command result. Invalid commands and ordinary
		// shutdown both retire this single-use process without publishing details.
		return nil
	case <-process.exited:
		return vault.ErrPolicy
	}
}

// Only noninteractive providers are enabled until their native authentication
// and encrypted cache adapters are available. Never call the legacy launcher.
func sealedTunnelSidecarConfig(kind uint16, raw []byte) (string, []byte, error) {
	settings, err := decodeVaultTunnelSettings(raw)
	if err != nil {
		return "", nil, vault.ErrFormat
	}
	defer clearTunnelSettingsMap(settings)
	switch kind {
	case 0, 1, 6:
	case 9:
		// Interactive factors and SSL fallback require their own sealed native
		// authorization flow. Never call the legacy prompt/cache launcher.
		if (fortinetUserAuth(settings) != 0 && fortinetUserAuth(settings) != 2) || strings.TrimSpace(tunnelSettingString(settings, "FallbackTunnelId")) != "" {
			return "", nil, vault.ErrPolicy
		}
	case 2:
		if tunnelSettingBool(settings, "UseSingleSignOn") || strings.TrimSpace(tunnelSettingString(settings, "SamlAuthId")) != "" || strings.TrimSpace(tunnelSettingString(settings, "SvpnCookie")) != "" {
			return "", nil, vault.ErrPolicy
		}
	default:
		return "", nil, vault.ErrPolicy
	}
	if validateTunnelSettings(int64(kind), settings) != nil {
		return "", nil, vault.ErrFormat
	}
	return tunnelSidecarCommand(int64(kind), raw)
}

func startSealedTunnel(ctx context.Context, binding vault.TunnelBundleBinding, configuration []byte) (*tunnelProcess, error) {
	executable, config, err := sealedTunnelSidecarConfig(binding.Kind, configuration)
	if ctx.Value(sealedTunnelBrowserKey{}) != nil {
		executable, config, err = sealedTunnelBrowserConfig(ctx, binding, configuration)
	}
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(config)
	var path string
	if tunnelRequiresOpenVPN(int64(binding.Kind)) {
		path, err = requireOpenVPN(ctx)
	} else {
		path, err = findTunnelSidecar(executable)
	}
	if err != nil {
		return nil, err
	}
	return launchSealedTunnel(ctx, exec.Command(path), config)
}

// Configuration travels only through stdin. Diagnostics are discarded even if
// WORMHOLE_TUNNEL_DEBUG is set; this path cannot touch a legacy cache or database.
// Once Start succeeds, the caller owns the returned process even on error and
// must retire it after wiping its borrowed configuration.
func launchSealedTunnel(ctx context.Context, command *exec.Cmd, config []byte) (*tunnelProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = stdin.Close()
		}
	}()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	if err = startOwnedHelper(command); err != nil {
		return nil, err
	}
	process := &tunnelProcess{stdin: stdin, command: command, exited: make(chan struct{})}
	go waitSealedTunnel(process)
	stop := context.AfterFunc(ctx, func() { _ = command.Process.Kill() })
	defer stop()
	configured := make(chan error, 1)
	go func() {
		_, e := stdin.Write(config)
		if e == nil {
			_, e = stdin.Write([]byte("\n"))
		}
		configured <- e
	}()
	select {
	case err = <-configured:
	case <-ctx.Done():
		_ = command.Process.Kill()
		_ = stdin.Close()
		<-configured
		err = ctx.Err()
	}
	if err != nil {
		// Preserve ownership on startup failure. The controller wipes its
		// borrowed configuration before joining this original process's exit.
		return process, err
	}
	ready, failed := make(chan string, 1), make(chan error, 1)
	go func() {
		reader := bufio.NewReaderSize(stdout, 1024)
		readTunnelReady(reader, ready, failed)
		_, _ = io.Copy(io.Discard, reader)
	}()
	select {
	case port := <-ready:
		if ctx.Err() == nil && process.alive() {
			process.socks = net.JoinHostPort("127.0.0.1", port)
			return process, nil
		}
	case <-failed:
	case <-ctx.Done():
	case <-process.exited:
	}
	return process, vault.ErrPolicy
}

func runSealedTunnelCLI(input io.Reader, output, errorOutput io.Writer) int {
	return runSealedTunnelModeCLI(input, output, errorOutput, false)
}

func runSealedTunnelModeCLI(input io.Reader, output, errorOutput io.Writer, fallback bool) int {
	open := openSealedTunnelConfiguration
	if fallback {
		open = openSealedTunnelFallbackConfiguration
	}
	return runSealedTunnelActorCLI(input, output, errorOutput, open, false)
}

func runSealedTunnelActorCLI(input io.Reader, output, errorOutput io.Writer, open sealedTunnelOpen, primary bool) int {
	if securemem.DisableProcessDumps() != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	if serveSealedTunnelActor(reader, output, startSealedTunnel, open, primary) != nil {
		writeErrorTo(errorOutput, "sealed_tunnel_stopped")
		return 1
	}
	return 0
}
