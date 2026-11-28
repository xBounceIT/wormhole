package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const maxTouchIDRequest = 2 + 2*36

type touchIDBrokerContextKey struct{}

type touchIDBrokerClient struct {
	mu   sync.Mutex
	conn net.Conn
}

func platformVaultTouchID(ctx context.Context, operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
	broker, ok := ctx.Value(touchIDBrokerContextKey{}).(*touchIDBrokerClient)
	if !ok {
		return nil, errTouchIDUnavailable
	}
	return broker.request(ctx, operation, vaultID, slotID)
}

func (b *touchIDBrokerClient) request(ctx context.Context, operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
	request, err := encodeTouchIDRequest(operation, vaultID, slotID)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	deadline := time.Now().Add(95 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if b.conn.SetDeadline(deadline) != nil {
		return nil, errTouchIDUnavailable
	}
	// A canceled request may still have a reply in flight. Close the channel
	// so the next operation can never consume that reply.
	interrupt := context.AfterFunc(ctx, func() { _ = b.conn.Close() })
	defer interrupt()
	var frame [maxTouchIDReply]byte
	defer vault.Wipe(frame[:])
	var reply []byte
	if err = sendTouchIDFrame(b.conn, request); err == nil {
		reply, err = readTouchIDFrame(b.conn, frame[:])
	}
	if ctx.Err() != nil {
		_ = b.conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = b.conn.Close()
		return nil, errTouchIDUnavailable
	}
	factor, err := decodeTouchIDReply(operation, reply)
	if errors.Is(err, vaultwire.ErrProtocol) {
		_ = b.conn.Close()
		return nil, errTouchIDUnavailable
	}
	if ctx.Err() != nil {
		vault.Wipe(factor)
		return nil, ctx.Err()
	}
	return factor, err
}

func sendTouchIDFrame(output io.Writer, frame []byte) error {
	var message [1 + maxTouchIDRequest]byte
	defer vault.Wipe(message[:])
	if len(frame) < 2 || len(frame) > maxTouchIDRequest {
		return vaultwire.ErrProtocol
	}
	message[0] = byte(len(frame))
	copy(message[1:], frame)
	n, err := output.Write(message[:len(frame)+1])
	if err == nil && n != len(frame)+1 {
		return io.ErrShortWrite
	}
	return err
}

func readTouchIDFrame(input io.Reader, dest []byte) ([]byte, error) {
	var header [1]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return nil, err
	}
	n := int(header[0])
	if n < 2 || n > len(dest) {
		return nil, vaultwire.ErrProtocol
	}
	if _, err := io.ReadFull(input, dest[:n]); err != nil {
		return nil, err
	}
	return dest[:n], nil
}

type touchIDBrokerRequest struct {
	operation       touchIDOperation
	vaultID, slotID string
}

func readTouchIDBrokerRequests(ctx context.Context, conn net.Conn, requests chan<- touchIDBrokerRequest) error {
	var bytes [maxTouchIDRequest]byte
	for {
		frame, err := readTouchIDFrame(conn, bytes[:])
		if err != nil {
			return err
		}
		request := touchIDBrokerRequest{operation: touchIDOperation(frame[1])}
		if len(frame) == maxTouchIDRequest {
			request.vaultID, request.slotID = string(frame[2:38]), string(frame[38:])
		}
		if frame[0] != touchIDProtocolVersion ||
			(request.operation == touchIDProbe && len(frame) != 2) ||
			(request.operation != touchIDProbe && (len(frame) != maxTouchIDRequest ||
				request.operation < touchIDEnroll || request.operation > touchIDRemove ||
				!validTouchIDCoordinate(request.vaultID) || !validTouchIDCoordinate(request.slotID))) {
			return vaultwire.ErrProtocol
		}
		select {
		case requests <- request:
		case <-ctx.Done():
			return ctx.Err()
		default:
			return vaultwire.ErrProtocol
		}
	}
}

func serveTouchIDBroker(parent context.Context, channel net.Conn, provider touchIDProvider) error {
	ctx, cancel := context.WithCancel(parent)
	requests := make(chan touchIDBrokerRequest, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_ = readTouchIDBrokerRequests(ctx, channel, requests)
		cancel()
	}()
	defer func() {
		cancel()
		channel.Close()
		<-readDone
	}()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case request := <-requests:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			factor, err := provider(ctx, request.operation, request.vaultID, request.slotID)
			writeErr := sendTouchIDBrokerReply(ctx, channel, request.operation, factor, err)
			vault.Wipe(factor)
			if writeErr != nil {
				return writeErr
			}
		}
	}
	return ctx.Err()
}

func sendTouchIDBrokerReply(ctx context.Context, channel net.Conn, operation touchIDOperation, factor []byte, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := channel.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var data [maxTouchIDReply]byte
	defer vault.Wipe(data[:])
	data[0] = touchIDProtocolVersion
	reply := data[:2]
	switch {
	case errors.Is(err, errTouchIDCanceled):
		data[1] = 2
	case err != nil:
		data[1] = 1
	case operation == touchIDEnroll || operation == touchIDOpen:
		if len(factor) != 32 {
			data[1] = 1
		} else {
			copy(data[2:], factor)
			reply = data[:]
		}
	case len(factor) != 0:
		data[1] = 1
	}
	return sendTouchIDFrame(channel, reply)
}

func runVaultTouchIDBroker(errorOutput io.Writer) int {
	if err := securemem.DisableProcessDumps(); err != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	channel, err := openTouchIDChannel()
	if err != nil {
		writeErrorTo(errorOutput, "vault_touch_id_channel_unavailable")
		return 1
	}
	if err := serveTouchIDBroker(context.Background(), channel, runSignedTouchIDHelper); err != nil && !errors.Is(err, context.Canceled) {
		writeErrorTo(errorOutput, "vault_touch_id_broker_stopped")
		return 1
	}
	return 0
}
