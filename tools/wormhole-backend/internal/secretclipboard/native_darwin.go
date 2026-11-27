//go:build darwin && cgo

package secretclipboard

/*
#cgo LDFLAGS: -framework AppKit
#include "api_darwin.h"
*/
import "C"

import "unsafe"

func NewNative() (Driver, error) { return newMacClipboard(false) }
func newMacClipboard(isolated bool) (Driver, error) {
	var private C.int
	if isolated {
		private = 1
	}
	handle := C.wh_clipboard_create(private)
	if handle == nil {
		return nil, ErrUnavailable
	}
	return &pasteboardDriver{ops: pasteboardOps{
		write: func(value []byte) (Ticket, error) {
			var ticket C.uint64_t
			result := C.wh_clipboard_write(handle, (*C.uchar)(unsafe.Pointer(&value[0])), C.size_t(len(value)), &ticket)
			return Ticket(ticket), pasteboardError(int(result))
		},
		erase: func(ticket Ticket) error {
			return pasteboardError(int(C.wh_clipboard_erase(handle, C.uint64_t(ticket))))
		},
		close: func() error { return pasteboardError(int(C.wh_clipboard_close(handle))) },
	}}, nil
}
