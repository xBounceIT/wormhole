package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func serveSealedSerial(input io.ReadCloser, output io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer input.Close()
	stopRead := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopRead()
	output = sealedSSHOutput{writer: output, cancel: cancel}
	key, public, err := newSealedRecipientKey(false)
	if err != nil {
		return err
	}
	defer key.Close()
	writer := json.NewEncoder(output)
	if err := writer.Encode(struct {
		Type      string `json:"type"`
		PublicKey []byte `json:"publicKey"`
	}{"recipient", public}); err != nil {
		return err
	}
	timer := time.AfterFunc(30*time.Second, cancel)
	defer timer.Stop()
	reader := bufio.NewReaderSize(input, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || !timer.Stop() || ctx.Err() != nil {
		return vaultwire.ErrProtocol
	}
	var bindingRaw, bundleRaw json.RawMessage
	var command serialWireCommand
	var bundle vault.SealedBundle
	if decodeVaultObject(line, map[string]any{
		"binding": &bindingRaw, "bundle": &bundleRaw, "columns": &command.Columns, "rows": &command.Rows,
	}, "binding", "bundle", "columns", "rows") != nil || command.Columns > 500 || command.Rows > 500 ||
		decodeBitwardenExchangeBundle(bundleRaw, &bundle) != nil {
		return vaultwire.ErrProtocol
	}
	binding, err := decodeSSHBundleBinding(bindingRaw)
	if err != nil {
		return err
	}
	var settings vault.SerialSettings
	err = key.With(func(private []byte) error {
		var err error
		settings, err = vault.OpenSerialConnection(private, binding, bundle)
		return err
	})
	if err != nil {
		return err
	}
	if err := key.Close(); err != nil {
		return err
	}
	command.SessionID = binding.SessionID
	target := serialTarget{NodeID: binding.NodeID, PortName: binding.Host, BaudRate: settings.BaudRate,
		DataBits: settings.DataBits, StopBits: settings.StopBits, Parity: settings.Parity, FlowControl: settings.FlowControl}
	server := &serialServer{
		output: &serialEventWriter{encoder: writer}, protected: true,
		sessions: make(map[string]*serialNativeSession), pending: make(map[string]context.CancelFunc),
	}
	defer server.shutdown()
	server.openWithTarget(command, func(ctx context.Context) (serialTarget, error) { return target, ctx.Err() })
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	for scanner.Scan() {
		var control serialWireCommand
		if json.Unmarshal(scanner.Bytes(), &control) != nil || control.SessionID != binding.SessionID {
			return vaultwire.ErrProtocol
		}
		switch control.Type {
		case "close":
			server.close(control.SessionID)
			return nil
		case "input", "resize", "snapshot":
			server.handle(control)
		default:
			return vaultwire.ErrProtocol
		}
	}
	return scanner.Err()
}

func runSealedSerialCLI(input io.Reader, output, diagnostic io.Writer) int {
	reader, ok := input.(io.ReadCloser)
	if !ok || securemem.DisableProcessDumps() != nil || serveSealedSerial(reader, output) != nil {
		writeErrorTo(diagnostic, "sealed_serial_stopped")
		return 1
	}
	return 0
}
