package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultSerialOwnerAndRecipient(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	root, node := uuid.NewString(), uuid.NewString()
	protocol, baud, bits, stop, parity := 5, 115200, 7, 3, 0
	port := "COM42"
	if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: root, Name: "Folder", Protocol: &protocol,
		Host: &port, SerialBaudRate: &baud, SerialDataBits: &bits, SerialStopBits: &stop}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: node, ParentID: &root, Name: "Serial", Kind: 1, SerialParity: &parity}, nil, 0); err != nil {
		t.Fatal(err)
	}
	oldOpen := openNativeSerialForOpen
	t.Cleanup(func() { openNativeSerialForOpen = oldOpen })
	var opened atomic.Int32
	var fixture *blockingSerialPort
	openNativeSerialForOpen = func(ctx context.Context, target serialTarget, columns, rows uint32) (*serialNativeSession, error) {
		opened.Add(1)
		if target.PortName != port || target.BaudRate != baud || target.DataBits != bits || target.StopBits != stop || target.Parity != parity || columns != 80 || rows != 24 {
			t.Errorf("wrong resolved serial line: %+v", target)
		}
		return newSerialNativeSession(fixture, target, columns, rows), ctx.Err()
	}
	for _, mode := range []string{"changed target", "foreign control", "reopen", "close", "EOF"} {
		t.Run(mode, func(t *testing.T) {
			fixture = newBlockingSerialPort()
			initial := opened.Load()
			input, sender := io.Pipe()
			receiver, output := io.Pipe()
			defer sender.Close()
			defer receiver.Close()
			done := make(chan error, 1)
			go func() {
				err := serveSealedSerial(input, output)
				_ = output.Close()
				done <- err
			}()
			var recipient struct {
				Type      string
				PublicKey []byte
			}
			response := json.NewDecoder(receiver)
			if err := response.Decode(&recipient); err != nil || recipient.Type != "recipient" || len(recipient.PublicKey) != 32 {
				t.Fatal("serial process did not send its recipient", err)
			}
			session := uuid.NewString()
			request := map[string]any{"nodeId": node, "sessionId": session, "requestId": uuid.NewString(), "epoch": "1", "publicKey": recipient.PublicKey}
			raw, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request))
			var bundle vault.SerialConnectionBundle
			if err != nil || json.Unmarshal(raw, &bundle) != nil {
				t.Fatal("vault refused a saved serial line", err)
			}
			if mode == "changed target" {
				bundle.Binding.Host = "COM8"
			}
			control := json.NewEncoder(sender)
			if err := control.Encode(struct {
				vault.SerialConnectionBundle
				Columns int `json:"columns"`
				Rows    int `json:"rows"`
			}{bundle, 80, 24}); err != nil {
				t.Fatal(err)
			}
			if mode == "changed target" {
				if err := <-done; err == nil || opened.Load() != initial {
					t.Fatal("changed binding opened a serial device", err)
				}
				return
			}
			var event serialWireEvent
			if err := response.Decode(&event); err != nil || event.Type != "connected" || event.SessionID != session || event.PortName != port {
				t.Fatal("wrong serial connection event", event, err)
			}
			if mode == "close" {
				if err := control.Encode(serialWireCommand{Type: "resize", SessionID: session, Columns: 81, Rows: 25}); err != nil {
					t.Fatal(err)
				}
			}
			if err := response.Decode(&event); err != nil || event.Type != "screen" || event.Frame == nil ||
				event.Frame.Columns != 80 || event.Frame.Rows != 24 || !event.Frame.ViewportReset {
				t.Fatal("missing initial serial frame", err)
			}
			if mode == "EOF" {
				_ = sender.Close()
				if err := <-done; err != nil || !fixture.closedState() {
					t.Fatal("closing stdin retained the serial device", err)
				}
				return
			}
			cmd := serialWireCommand{Type: "open", SessionID: session, PortName: "COM8"}
			if mode == "foreign control" {
				cmd = serialWireCommand{Type: "input", SessionID: uuid.NewString(), Data: "YQ=="}
			} else if mode == "close" {
				if err := response.Decode(&event); err != nil || event.Frame == nil || event.Frame.Columns != 81 || event.Frame.Rows != 25 {
					t.Fatal("serial console did not resize", err)
				}
				cmd = serialWireCommand{Type: "close", SessionID: session}
			}
			if err := control.Encode(cmd); err != nil {
				t.Fatal(err)
			}
			for response.Decode(&event) == nil {
			}
			if err := <-done; (err != nil) != (mode != "close") || opened.Load() != initial+1 || !fixture.closedState() {
				t.Fatal("unexpected control outcome or serial device left open", err)
			}
		})
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"nodeId": uuid.NewString(), "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "2", "publicKey": key.PublicKey().Bytes()}
	if _, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request)); err == nil {
		t.Fatal("unknown saved connection accepted")
	}
	rdp, rdpProtocol := uuid.NewString(), 1
	if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: rdp, Name: "Remote", Kind: 1, Protocol: &rdpProtocol, Host: &port}, nil, 0); err != nil {
		t.Fatal(err)
	}
	request["nodeId"] = rdp
	if _, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request)); err != vault.ErrPolicy {
		t.Fatal("saved nonserial connection accepted", err)
	}
	request["nodeId"] = uuid.NewString()
	settings := vault.DefaultSerialSettings()
	request["quick"] = map[string]any{"portName": "/dev/ttyS0", "settings": settings}
	raw, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request))
	var bundle vault.SerialConnectionBundle
	if err != nil || json.Unmarshal(raw, &bundle) != nil || bundle.Binding.Host != "/dev/ttyS0" {
		t.Fatal("wrong Quick serial authorization", err)
	}
	if got, err := vault.OpenSerialConnection(key.Bytes(), bundle.Binding, bundle.Bundle); err != nil || got != settings {
		t.Fatal("wrong Quick serial settings", got, err)
	}
	settings.FlowControl = 4
	request["quick"] = map[string]any{"portName": "/dev/ttyS0", "settings": settings}
	if _, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request)); err == nil {
		t.Fatal("malformed Quick settings accepted")
	}
	request["epoch"] = "02"
	if _, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request)); err == nil {
		t.Fatal("noncanonical epoch accepted")
	}
}

func TestVaultSerialMalformedOpeningRejected(t *testing.T) {
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'{'}, 5000), []byte("{\"columns\":501,\"rows\":24}\n")} {
		if err := serveSealedSerial(io.NopCloser(bytes.NewReader(data)), io.Discard); err == nil {
			t.Fatal("unexpected serial opening accepted")
		}
	}
}

func TestVaultSerialSharedUsesAuthenticatedConnectionPlan(t *testing.T) {
	ctx := context.Background()
	c, probe, options, _, account, _, node, wire := credentialControllerFixture(t)
	var signer ed25519.PrivateKey
	if err := c.privateKeys.With(func(raw []byte) error { signer = ed25519.NewKeyFromSeed(raw[32:]); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(signer)
	editSharedConnectionFixture(t, options.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
		protocol, data, flow, host := 5, 6, 2, "/dev/ttyUSB0"
		n.Protocol, n.SerialDataBits, n.SerialFlowControl, n.Host = &protocol, &data, &flow, &host
		n.CredentialID, n.CredentialMode = nil, nil
	}, signer)
	wire["metadata"].(map[string]any)["credential"] = nil
	probe.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
		t.Fatal("serial metadata requested a secret ticket")
		return nil, nil
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	q, private := sharedSSHRequest(node)
	request := map[string]any{"nodeId": q.NodeID, "sessionId": q.SessionID, "requestId": q.RequestID, "epoch": "7", "publicKey": q.PublicKey,
		"quick": map[string]any{"portName": "COM7", "settings": vault.DefaultSerialSettings()}}
	if _, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request)); err == nil {
		t.Fatal("shared serial Quick target bypassed admission")
	}
	delete(request, "quick")
	raw, err := h.Handle(ctx, "serial-bundle", vaultInput(t, request))
	var release vault.SerialConnectionBundle
	if err != nil || json.Unmarshal(raw, &release) != nil || release.Binding.Host != "/dev/ttyUSB0" {
		t.Fatal("shared serial plan was not sealed", err)
	}
	want := vault.DefaultSerialSettings()
	want.DataBits, want.FlowControl = 6, 2
	if got, err := vault.OpenSerialConnection(private, release.Binding, release.Bundle); err != nil || got != want {
		t.Fatal("shared serial settings were not taken from the verified node", got, err)
	}
}

type serialPermissionProbe struct {
	*credentialReleaseProbe
	read func(context.Context, uuid.UUID) (permissions.Mask, error)
}

func (p serialPermissionProbe) NodePermissions(ctx context.Context, id uuid.UUID) (permissions.Mask, error) {
	return p.read(ctx, id)
}

func TestVaultSerialSharedUseChecksCurrentPermission(t *testing.T) {
	ctx := context.Background()
	c, probe, _, _, _, _, node, _ := credentialControllerFixture(t)
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	other := uuid.New()
	request := vaultInput(t, map[string]any{"nodeIds": []string{node.String(), other.String()}})
	if _, err := h.Handle(ctx, "serial-use-check", request); err == nil {
		t.Fatal("permission check ran without a capable database session")
	}
	allowed := permissions.View | permissions.Use
	var permissionErr error
	c.session = serialPermissionProbe{probe, func(_ context.Context, id uuid.UUID) (permissions.Mask, error) {
		if permissionErr != nil {
			return 0, permissionErr
		}
		switch id {
		case node:
			return allowed, nil
		case other:
			return permissions.Use, nil
		default:
			t.Fatal("unchecked permission coordinate")
			return 0, nil
		}
	}}
	for _, raw := range []json.RawMessage{nil, []byte(`{"nodeIds":[]}`), vaultInput(t, map[string]any{"nodeIds": []string{node.String(), node.String()}}), []byte(`{"nodeIds":["unknown"]}`)} {
		if _, err := h.Handle(ctx, "serial-use-check", raw); err == nil {
			t.Fatal("invalid permission list accepted")
		}
	}
	for i, want := range []string{`{"current":[true,true]}`, `{"current":[false,true]}`} {
		if i != 0 {
			allowed = permissions.View
		}
		if result, err := h.Handle(ctx, "serial-use-check", request); err != nil || string(result) != want || !c.Unlocked() {
			t.Fatal("wrong serial Use authorization", string(result), err)
		}
	}
	permissionErr = sharedpg.ErrQuery
	if result, err := h.Handle(ctx, "serial-use-check", request); err == nil || len(result) != 0 || c.Unlocked() {
		t.Fatal("unavailable permission transport retained admission or returned stale results", string(result), err)
	}
}
