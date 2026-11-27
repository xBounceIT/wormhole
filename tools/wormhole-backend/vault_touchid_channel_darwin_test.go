package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVaultTouchIDInheritedDarwinChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if os.Getenv("WORMHOLE_TEST_TOUCH_ID_CHANNEL") == "broker" {
		channel, err := openTouchIDChannel()
		if err != nil {
			t.Fatal(err)
		}
		err = serveTouchIDBroker(ctx, channel, func(_ context.Context, op touchIDOperation, vault, slot string) ([]byte, error) {
			if op != touchIDOpen || vault != brokerTestVault || slot != brokerTestSlot {
				return nil, errTouchIDUnavailable
			}
			return bytes.Repeat([]byte{9}, 32), nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		return
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	left, right := os.NewFile(uintptr(fds[0]), "owner"), os.NewFile(uintptr(fds[1]), "broker")
	defer left.Close()
	defer right.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultTouchIDInheritedDarwinChannel$")
	cmd.Env = append(os.Environ(), "WORMHOLE_TEST_TOUCH_ID_CHANNEL=broker")
	cmd.ExtraFiles = []*os.File{right}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	right.Close()
	channel, err := net.FileConn(left)
	left.Close()
	if err != nil {
		cancel()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer channel.Close()
	broker := &touchIDBrokerClient{conn: channel}
	got, err := broker.request(ctx, touchIDOpen, brokerTestVault, brokerTestSlot)
	channel.Close()
	waitErr := cmd.Wait()
	defer clearBytes(got)
	if err != nil || waitErr != nil || !bytes.Equal(got, bytes.Repeat([]byte{9}, 32)) {
		t.Fatalf("descriptor handoff failed: %v %v %s", err, waitErr, diagnostic.String())
	}
}
