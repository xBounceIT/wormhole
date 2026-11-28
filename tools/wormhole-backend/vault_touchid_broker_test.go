package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const brokerTestVault = "11111111-1111-4111-8111-111111111111"
const brokerTestSlot = "22222222-2222-4222-8222-222222222222"

func TestVaultTouchIDBrokerExchange(t *testing.T) {
	if _, err := platformVaultTouchID(context.Background(), touchIDProbe, "", ""); !errors.Is(err, errTouchIDUnavailable) {
		t.Fatal("device with no channel admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vault, broker := net.Pipe()
	defer vault.Close()
	factor := bytes.Repeat([]byte{13}, 32)
	want := bytes.Clone(factor)
	done := make(chan error, 1)
	go func() {
		done <- serveTouchIDBroker(ctx, broker, func(_ context.Context, op touchIDOperation, vid, sid string) ([]byte, error) {
			if op != touchIDProbe && (vid != brokerTestVault || sid != brokerTestSlot) {
				t.Error("wrong Touch ID coordinates")
			}
			switch op {
			case touchIDProbe:
				return nil, nil
			case touchIDOpen:
				return factor, nil
			case touchIDEnroll:
				return []byte{2}, nil
			case touchIDRemove:
				return nil, errTouchIDCanceled
			default:
				return nil, errors.New("unexpected operation")
			}
		})
	}()
	ownerContext := context.WithValue(ctx, touchIDBrokerContextKey{}, &touchIDBrokerClient{conn: vault})
	for _, tc := range []struct {
		op       touchIDOperation
		vid, sid string
		factor   []byte
		wantErr  error
	}{
		{op: touchIDProbe},
		{op: touchIDOpen, vid: brokerTestVault, sid: brokerTestSlot, factor: want},
		{op: touchIDEnroll, vid: brokerTestVault, sid: brokerTestSlot, wantErr: errTouchIDUnavailable},
		{op: touchIDRemove, vid: brokerTestVault, sid: brokerTestSlot, wantErr: errTouchIDCanceled},
		{op: touchIDOpen, vid: "bad", sid: brokerTestSlot, wantErr: vaultwire.ErrProtocol},
	} {
		got, err := platformVaultTouchID(ownerContext, tc.op, tc.vid, tc.sid)
		if !errors.Is(err, tc.wantErr) || !bytes.Equal(got, tc.factor) {
			t.Fatalf("operation %d lost its status or factor: %v", tc.op, err)
		}
		clearBytes(got)
	}
	vault.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !bytes.Equal(factor, make([]byte, len(factor))) {
			t.Fatal("broker failed to stop and wipe its factor", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestVaultTouchIDBrokerClosesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vault, broker := net.Pipe()
	defer vault.Close()
	started := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		closed <- serveTouchIDBroker(ctx, broker, func(ctx context.Context, _ touchIDOperation, _, _ string) ([]byte, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	client := &touchIDBrokerClient{conn: vault}
	op, abort := context.WithCancel(ctx)
	defer abort()
	outcome := make(chan error, 1)
	go func() {
		_, err := client.request(op, touchIDProbe, "", "")
		outcome <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	abort()
	if err := <-outcome; !errors.Is(err, context.Canceled) {
		t.Fatal("operation did not cancel", err)
	}
	if err := <-closed; !errors.Is(err, context.Canceled) {
		t.Fatal("broker did not stop on EOF", err)
	}
	if got, err := client.request(ctx, touchIDProbe, "", ""); got != nil || !errors.Is(err, errTouchIDUnavailable) {
		t.Fatal("retired channel accepted a subsequent request", err)
	}
}

type touchIDShortWriter struct{}

func (touchIDShortWriter) Write([]byte) (int, error) { return 0, nil }

func TestVaultTouchIDBrokerRejectsMalformedFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sendTouchIDFrame(touchIDShortWriter{}, []byte{1, 1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write accepted", err)
	}
	for _, bad := range [][]byte{
		{1}, make([]byte, maxTouchIDRequest+1),
	} {
		if err := sendTouchIDFrame(io.Discard, bad); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid length accepted", err)
		}
	}
	for _, frame := range [][]byte{
		{0}, {maxTouchIDRequest + 1}, {2, 1}, {2, 2, 1}, {2, 1, 3},
		{3, 1, 1, 'x'},
	} {
		vault, broker := net.Pipe()
		done := make(chan error, 1)
		go func() {
			defer vault.Close()
			_, _ = vault.Write(frame)
		}()
		go func() {
			done <- serveTouchIDBroker(ctx, broker, func(context.Context, touchIDOperation, string, string) ([]byte, error) {
				t.Error("invalid frame reached provider")
				return nil, nil
			})
		}()
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	vault, broker := net.Pipe()
	defer vault.Close()
	go func() {
		var scratch [maxTouchIDRequest]byte
		_, _ = readTouchIDFrame(broker, scratch[:])
		_ = sendTouchIDFrame(broker, []byte{2, 1})
		broker.Close()
	}()
	client := &touchIDBrokerClient{conn: vault}
	if data, err := client.request(ctx, touchIDProbe, "", ""); data != nil || !errors.Is(err, errTouchIDUnavailable) {
		t.Fatal("untrusted reply was accepted", err)
	}
}
