// The release pipeline runs this on Windows and macOS before publishing the signed
// manifest. It uses the same native verification as the installed updater.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func verify(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: verify-update-publisher <publisher identity> <installer>")
	}
	ext := strings.ToLower(filepath.Ext(args[1]))
	if (runtime.GOOS == "windows" && ext != ".exe") || (runtime.GOOS == "darwin" && ext != ".dmg") {
		return errors.New("installer extension does not match the current platform")
	}
	if err := updateauth.ValidatePublisherIdentity(args[0]); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(args[1]))
	if err != nil {
		return err
	}
	defer root.Close()
	installer, err := updateauth.OpenArtifact(root, filepath.Base(args[1]))
	if err != nil {
		return err
	}
	defer installer.Close()
	if runtime.GOOS == "windows" {
		locked, err := updateauth.LockWindowsInstaller(installer)
		if err != nil {
			return err
		}
		defer locked.Close()
		installer = locked
	}
	return updateauth.VerifyPublisher(installer, args[0])
}

func main() {
	if err := verify(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
