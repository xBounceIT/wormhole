//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include "../wormhole-touch-id/code_identity.h"

static int whTrustedTouchIDBundle(const char *bundle) {
	CFStringRef team = WHOwnDeveloperTeam(NULL);
	if (team == NULL) return false;
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
		(const UInt8 *)bundle, (CFIndex)strlen(bundle), true);
	SecStaticCodeRef code = NULL;
	CFStringRef helperTeam = NULL;
	if (url != NULL && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess) {
		helperTeam = WHDeveloperTeam(NULL, code, WH_TOUCH_ID_IDENTIFIER);
	}
	Boolean trusted = helperTeam != NULL && CFEqual(team, helperTeam);
	if (helperTeam != NULL) CFRelease(helperTeam);
	if (code != NULL) CFRelease(code);
	if (url != NULL) CFRelease(url);
	CFRelease(team);
	return trusted;
}

static int whTrustedTouchIDProcess(int pid) {
	CFStringRef team = WHOwnDeveloperTeam(NULL);
	if (team == NULL) return false;
	Boolean trusted = WHIsDeveloperProcess(pid, WH_TOUCH_ID_IDENTIFIER, team);
	CFRelease(team);
	return trusted;
}
*/
import "C"

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func runSignedTouchIDHelper(ctx context.Context, operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
	request, err := encodeTouchIDRequest(operation, vaultID, slotID)
	if err != nil {
		return nil, err
	}
	backend, err := os.Executable()
	if err != nil {
		return nil, errTouchIDUnavailable
	}
	backend, err = filepath.EvalSymlinks(backend)
	if err != nil || filepath.Base(backend) != "wormhole-backend-universal" {
		return nil, errTouchIDUnavailable
	}
	resources := filepath.Dir(backend)
	contents := filepath.Dir(resources)
	if filepath.Base(resources) != "Resources" || filepath.Base(contents) != "Contents" || filepath.Ext(filepath.Dir(contents)) != ".app" {
		return nil, errTouchIDUnavailable
	}
	bundle := filepath.Join(contents, "Helpers", "Wormhole Vault Touch ID.app")
	// A signature check at the path prevents starting an unsigned substitute.
	// Checking the running child again closes the gap between validation and exec.
	bundlePath := C.CString(bundle)
	trusted := C.whTrustedTouchIDBundle(bundlePath)
	C.free(unsafe.Pointer(bundlePath))
	if trusted == 0 {
		return nil, errTouchIDUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(bundle, "Contents", "MacOS", "WormholeVaultTouchID"))
	command.Env = []string{}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errTouchIDUnavailable
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errTouchIDUnavailable
	}
	defer stdout.Close()
	if err = command.Start(); err != nil {
		return nil, errTouchIDUnavailable
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	if C.whTrustedTouchIDProcess(C.int(command.Process.Pid)) == 0 {
		return nil, errTouchIDUnavailable
	}
	_, sendErr := stdin.Write(request)
	closeErr := stdin.Close()
	if sendErr != nil || closeErr != nil {
		return nil, errTouchIDUnavailable
	}
	var frame [maxTouchIDReply + 1]byte
	defer vault.Wipe(frame[:])
	size, err := io.ReadFull(stdout, frame[:])
	if size > maxTouchIDReply || (!errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF)) {
		return nil, errTouchIDUnavailable
	}
	waited = true
	if err := command.Wait(); err != nil {
		return nil, errTouchIDUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return decodeTouchIDReply(operation, frame[:size])
}
