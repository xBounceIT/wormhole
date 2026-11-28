package main

import (
	"context"
	"errors"
	"unsafe"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

func openVaultBitwardenPasswordPipe(frame []byte) (bitwardenPasswordPipe, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return bitwardenPasswordPipe{}, err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GRGW;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return bitwardenPasswordPipe{}, err
	}
	path := `\\.\pipe\wormhole-bitwarden-` + uuid.NewString()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return bitwardenPasswordPipe{}, err
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, uint32(len(frame)), 0, 0, &attributes)
	if err != nil {
		return bitwardenPasswordPipe{}, err
	}
	return bitwardenPasswordPipe{
		path: path,
		deliver: func(ctx context.Context, pid int, data []byte) error {
			return deliverVaultBitwardenPassword(ctx, handle, uint32(pid), data)
		},
		close: func() { _ = windows.CloseHandle(handle) },
	}, nil
}

// Verify the reader's PID before writing any password bytes.
func deliverVaultBitwardenPassword(ctx context.Context, pipe windows.Handle, pid uint32, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	op := windows.Overlapped{HEvent: event}
	var written uint32
	err = windows.ConnectNamedPipe(pipe, &op)
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		if err = waitBitwardenPasswordPipe(ctx, pipe, &op, &written, err); err != nil {
			return err
		}
	}
	var client uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &client); err != nil || client != pid {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := windows.ResetEvent(event); err != nil {
		return err
	}
	op = windows.Overlapped{HEvent: event}
	err = windows.WriteFile(pipe, data, &written, &op)
	if err = waitBitwardenPasswordPipe(ctx, pipe, &op, &written, err); err != nil {
		return err
	}
	if int(written) != len(data) {
		return vault.ErrAuthentication
	}
	return nil
}

func waitBitwardenPasswordPipe(ctx context.Context, pipe windows.Handle, op *windows.Overlapped, transferred *uint32, err error) error {
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return err
	}
	done := make(chan struct{})
	cancel := context.AfterFunc(ctx, func() {
		_ = windows.CancelIoEx(pipe, op)
		close(done)
	})
	err = windows.GetOverlappedResult(pipe, op, transferred, true)
	if !cancel() {
		<-done
	}
	return err
}
