package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const sealedRDPFrameLimit = 128 * 1024

type sealedRDPOpening struct {
	requireContentProtection bool
	visible                  *bool
	binding                  vault.BundleBinding
	route                    *vault.TunnelBundleBinding
	endpoint                 string
	bundle                   vault.SealedBundle
	bitwarden                *vault.SealedBundle
	owner                    string
	bounds                   rdpBounds
}

func validRDPConnectionBinding(b vault.BundleBinding, routed bool) bool {
	for _, id := range []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return false
		}
	}
	return b.Protocol == "rdp" && !b.UseExternalClient && b.Epoch > 0 && b.Epoch <= 9007199254740991 && b.Port > 0 && b.Host != "" && vault.ValidRDPHost(b.Host) && (routed || b.TunnelConfigID == "")
}
func decodeRDPConnectionBinding(raw []byte) (vault.BundleBinding, error) {
	var b vault.BundleBinding
	if decodeVaultObject(raw, map[string]any{"workspaceId": &b.WorkspaceID, "sessionId": &b.SessionID, "requestId": &b.RequestID, "nodeId": &b.NodeID, "protocol": &b.Protocol, "host": &b.Host, "port": &b.Port, "tunnelConfigId": &b.TunnelConfigID, "useExternalClient": &b.UseExternalClient, "epoch": &b.Epoch}, "workspaceId", "sessionId", "requestId", "nodeId", "protocol", "host", "port", "tunnelConfigId", "useExternalClient", "epoch") != nil || !validRDPConnectionBinding(b, false) {
		return b, vaultwire.ErrProtocol
	}
	return b, nil
}
func decodeSealedRDPBounds(raw []byte) (rdpBounds, error) {
	var b rdpBounds
	if decodeVaultObject(raw, map[string]any{"x": &b.X, "y": &b.Y, "width": &b.Width, "height": &b.Height}, "x", "y", "width", "height") != nil || !b.valid() {
		return b, vaultwire.ErrProtocol
	}
	return b, nil
}
func decodeSealedRDPOpening(raw []byte) (sealedRDPOpening, error) {
	var o sealedRDPOpening
	var binding, bundle, bounds, bitwarden json.RawMessage
	var endpoint *string
	var requireContentProtection *bool
	if decodeVaultObject(raw, map[string]any{
		"binding": &binding, "bundle": &bundle, "endpoint": &endpoint, "ownerWindow": &o.owner,
		"bounds": &bounds, "visible": &o.visible, "requireContentProtection": &requireContentProtection, "bitwarden": &bitwarden,
	}, "binding", "bundle", "ownerWindow", "bounds") != nil {
		return o, vaultwire.ErrProtocol
	}
	if requireContentProtection != nil {
		if !*requireContentProtection || runtime.GOOS != "windows" {
			return o, vaultwire.ErrProtocol
		}
		o.requireContentProtection = true
	}
	var err error
	o.bounds, err = decodeSealedRDPBounds(bounds)
	if err != nil {
		return o, err
	}
	if o.owner != "" {
		handle, err := strconv.ParseUint(o.owner, 10, 64)
		if err != nil || handle == 0 || strconv.FormatUint(handle, 10) != o.owner {
			return o, vaultwire.ErrProtocol
		}
	}
	if runtime.GOOS == "windows" && o.owner == "" {
		return o, vaultwire.ErrProtocol
	}
	if decodeVaultObject(bundle, map[string]any{"formatVersion": &o.bundle.FormatVersion, "suiteId": &o.bundle.SuiteID, "enc": &o.bundle.Enc, "ciphertext": &o.bundle.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return o, vaultwire.ErrProtocol
	}
	if len(bitwarden) != 0 {
		var accounts vault.SealedBundle
		if decodeBitwardenExchangeBundle(bitwarden, &accounts) != nil {
			return o, vaultwire.ErrProtocol
		}
		o.bitwarden = &accounts
	}
	if endpoint != nil {
		route, err := decodeTunnelBundleBinding(binding)
		if err != nil || route.Protocol != "rdp" || !vault.ValidRouteEndpoint(*endpoint) {
			return o, vaultwire.ErrProtocol
		}
		o.binding, o.route, o.endpoint = route.BundleBinding, &route, *endpoint
	} else {
		var err error
		o.binding, err = decodeRDPConnectionBinding(binding)
		if err != nil {
			return o, err
		}
	}
	if !validRDPConnectionBinding(o.binding, o.route != nil) {
		return o, vaultwire.ErrProtocol
	}
	return o, nil
}
func decodeSealedRDPCommand(raw []byte, session string) (rdpCommand, error) {
	var command rdpCommand
	var input, bounds json.RawMessage
	fields := map[string]any{"op": &command.Op, "sessionId": &command.SessionID, "requestId": &command.RequestID}
	var envelope struct {
		Op string `json:"op"`
	}
	if len(raw) > 8192 || json.Unmarshal(raw, &envelope) != nil {
		return command, vaultwire.ErrProtocol
	}
	switch envelope.Op {
	case "resize", "show":
		fields["bounds"] = &bounds
	case "input":
		fields["input"] = &input
	case "certificate":
		fields["certificateAccepted"] = &command.CertificateAccepted
	case "focus", "hide", "disconnect", "app-lock":
	default:
		return command, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, "op", "sessionId", "requestId") != nil || command.SessionID != session {
		return command, vaultwire.ErrProtocol
	}
	id, err := uuid.Parse(command.RequestID)
	if err != nil || id == uuid.Nil || id.String() != command.RequestID {
		return command, vaultwire.ErrProtocol
	}
	if command.Op == "resize" || command.Op == "show" {
		command.Bounds, err = decodeSealedRDPBounds(bounds)
		if err != nil {
			return command, err
		}
	}
	if command.Op == "input" {
		var value rdpInput
		if decodeVaultObject(input, map[string]any{"kind": &value.Kind, "x": &value.X, "y": &value.Y, "flags": &value.Flags, "code": &value.Code, "down": &value.Down}, "kind") != nil {
			return command, vaultwire.ErrProtocol
		}
		command.Input = &value
	}
	if command.Op == "input" && (command.Input == nil || !command.Input.valid()) {
		return command, vaultwire.ErrProtocol
	}
	command.LifecycleID = session
	return command, nil
}

func rdpProfileFromBundle(b vault.BundleBinding, p vault.RDPBundlePayload) rdpProfile {
	// Settings and identities come only from the authenticated native frame.
	var profile rdpProfile
	public, _ := json.Marshal(p.Settings)
	_ = json.Unmarshal(public, &profile)
	profile.Host, profile.Port, profile.Username = b.Host, int(b.Port), p.Username
	profile.GatewayUsername = p.GatewayUsername
	if p.GatewayDomain != "" && !strings.Contains(profile.GatewayUsername, "\\") {
		profile.GatewayUsername = p.GatewayDomain + "\\" + profile.GatewayUsername
	}
	policy := p.Settings.ServerAuthentication
	profile.ServerAuthentication = &policy
	disabled := false
	profile.TunnelEnabled = &disabled
	return profile
}

func serveSealedRDP(input io.ReadCloser, output io.Writer, controller *rdpController) error {
	return serveSealedRDPMode(input, output, controller, false)
}
func serveSealedRDPMode(input io.ReadCloser, output io.Writer, controller *rdpController, manual bool) error {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer input.Close()
	output = sealedSSHOutput{writer: output, cancel: cancel}
	stop := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stop()
	key, err := securemem.New(32, false)
	if err != nil {
		return err
	}
	defer key.Close()
	var public []byte
	if err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err == nil {
			public = private.PublicKey().Bytes()
		}
		return err
	}); err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(struct {
		Type      string `json:"type"`
		PublicKey []byte `json:"publicKey"`
	}{"recipient", public}) != nil {
		return vaultwire.ErrProtocol
	}
	openingTimeout := 30 * time.Second
	if manual {
		openingTimeout = 5 * time.Minute
	}
	timer := time.AfterFunc(openingTimeout, cancel)
	defer timer.Stop()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), sealedRDPFrameLimit+2)
	if !scanner.Scan() || len(scanner.Bytes()) > sealedRDPFrameLimit {
		return vaultwire.ErrProtocol
	}
	opening, err := decodeSealedRDPOpening(scanner.Bytes())
	if err != nil {
		return err
	}
	var authorization, plaintext, manualFrame []byte
	var payload vault.RDPBundlePayload
	defer func() { vault.Wipe(authorization); vault.Wipe(plaintext); vault.Wipe(manualFrame) }()
	err = key.With(func(raw []byte) error {
		var err error
		if opening.route == nil {
			authorization, err = vault.OpenBundle(raw, opening.binding, opening.bundle)
		} else {
			authorization, err = vault.OpenRoutedBundle(raw, *opening.route, opening.endpoint, opening.bundle)
		}
		if err != nil {
			return err
		}
		if !manual {
			if opening.bitwarden != nil {
				payload, plaintext, err = vault.OpenRDPBitwardenAccounts(raw, opening.binding, opening.route, opening.endpoint, authorization, *opening.bitwarden)
			} else {
				payload, err = vault.DecodeRDPBundle(authorization)
			}
			return err
		}
		var inner vault.SealedBundle
		if opening.bitwarden != nil {
			if opening.route != nil {
				return vault.ErrPolicy
			}
			payload, inner, plaintext, err = vault.OpenManualRDPBitwardenAccounts(raw, opening.binding, authorization, *opening.bitwarden)
		} else {
			payload, inner, err = vault.DecodeRDPManualAuthorization(authorization)
		}
		if err != nil {
			return err
		}
		manualFrame, err = vault.OpenManualRDPCredentials(raw, opening.binding, opening.route, opening.endpoint, inner)
		if err != nil {
			return err
		}
		credentials, err := vault.DecodeRDPManualCredentials(manualFrame)
		if err != nil {
			return err
		}
		payload.Username, payload.Settings.Domain = credentials.Username, credentials.Domain
		payload.Password, payload.PasswordProvided = credentials.Password, true
		return nil
	})
	closeErr := key.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = vault.ValidateRDPRoute(payload.Settings, opening.route != nil); err != nil {
		return err
	}
	if resolverExternalRDP(payload) {
		return vault.ErrPolicy
	}
	profile := rdpProfileFromBundle(opening.binding, payload)
	credentials := newRdpProtocolHandoff(&profile, bytes.Clone(payload.Password), bytes.Clone(payload.GatewayPassword), payload.PasswordProvided, payload.GatewayPasswordProvided)
	defer credentials.close()
	profile.SocksEndpoint = opening.endpoint
	if opening.route != nil {
		enabled := true
		profile.TunnelEnabled = &enabled
		profile.TunnelConfigID = opening.binding.TunnelConfigID
	}
	if runtime.GOOS != "windows" {
		profile.Password = string(credentials.password)
		profile.GatewayPassword = string(credentials.gateway)
	}
	vault.Wipe(plaintext)
	vault.Wipe(authorization)
	vault.Wipe(manualFrame)
	authorization = nil
	plaintext = nil
	manualFrame = nil
	if controller == nil {
		controller = &rdpController{}
	}
	controller.processes = make(map[string]*rdpProcess)
	var outputMu sync.Mutex
	finished := false
	controller.output = func(event rdpEvent) {
		outputMu.Lock()
		defer outputMu.Unlock()
		if finished {
			return
		}
		if event.Type == "ready" || event.Type == "started" || event.Type == "connected" {
			timer.Stop()
		}
		if event.Type == "error" || event.Type == "fatalError" {
			event.Message = "RDP connection failed"
		}
		_ = json.NewEncoder(output).Encode(event)
		if event.Type == "exited" || (event.Type == "error" && event.RequestID == opening.binding.RequestID) {
			cancel()
		}
	}
	defer func() {
		controller.closeAll()
		controller.workers.Wait()
		outputMu.Lock()
		finished = true
		outputMu.Unlock()
	}()
	controller.start(rdpCommand{
		Op: "start", RequestID: opening.binding.RequestID, SessionID: opening.binding.SessionID,
		LifecycleID: opening.binding.SessionID, OwnerWindow: opening.owner, Bounds: opening.bounds,
		Visible: opening.visible, Profile: profile, credentials: credentials,
		requireContentProtection: opening.requireContentProtection,
	})
	profile.Password, profile.GatewayPassword = "", ""
	if runtime.GOOS != "windows" {
		credentials.close()
	}
	for scanner.Scan() {
		command, err := decodeSealedRDPCommand(scanner.Bytes(), opening.binding.SessionID)
		if err != nil {
			return err
		}
		if command.Op == "app-lock" {
			return nil
		}
		controller.handle(command)
	}
	if scanner.Err() != nil && ctx.Err() == nil {
		return vaultwire.ErrProtocol
	}
	return nil
}
func resolverExternalRDP(p vault.RDPBundlePayload) bool {
	return runtime.GOOS == "windows" && isAzureAdRdpIdentity(p.Username, p.Settings.Domain)
}
func runSealedRDPCLI(input io.Reader, output, errorOutput io.Writer) int {
	return runSealedRDPModeCLI(input, output, errorOutput, false)
}
func runSealedRDPModeCLI(input io.Reader, output, errorOutput io.Writer, manual bool) int {
	if securemem.DisableProcessDumps() != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	if serveSealedRDPMode(reader, output, nil, manual) != nil {
		writeErrorTo(errorOutput, "sealed_rdp_stopped")
		return 1
	}
	return 0
}
