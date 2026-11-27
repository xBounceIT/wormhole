//go:build windows

package ospolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

func TestWindowsInstallationBindsBundledProcesses(t *testing.T) {
	const app = `C:\Program Files\Wormhole\Wormhole.exe`
	const backend = `C:\Program Files\Wormhole\resources\app\dist-electron\wormhole-backend-x64.exe`
	for _, c := range []struct {
		app, backend string
		allowed      bool
	}{
		{app, backend, true},
		{`c:\PROGRAM FILES\Wormhole\Wormhole.EXE`, `C:\Program Files\Wormhole\Resources\app\dist-electron\wormhole-backend-arm64.exe`, true},
		{`D:\Wormhole\Wormhole.exe`, backend, false},
		{app, `C:\different\wormhole-backend-x64.exe`, false},
		{app, `C:\Program Files\Wormhole\resources\app\bin\wormhole-backend-x64.exe`, false},
		{app, `C:\Program Files\Wormhole\resources\app\dist-electron\wormhole-backend-x86.exe`, false},
		{`\\server\share\Wormhole.exe`, backend, false},
		{`\\?\C:\Program Files\Wormhole\Wormhole.exe`, backend, false},
		{`C:\Wormhole.exe`, backend, false},
		{`C:Wormhole.exe`, backend, false},
		{`C:\Program Files\Wormhole\..\Wormhole\Wormhole.exe`, backend, false},
		{`C:\Program Files\Wormhole\folder:stream\Wormhole.exe`, backend, false},
	} {
		root, err := windowsInstallationRoot(c.app, c.backend)
		if (err == nil) != c.allowed || (c.allowed && root != filepath.Dir(c.app)) {
			t.Fatalf("unexpected layout for %q and %q: %q %v", c.app, c.backend, root, err)
		}
	}
}

func TestWindowsInstallationACLRejectsUntrustedMutation(t *testing.T) {
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		t.Fatal(err)
	}
	const systemAndAdmins = "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	for _, tc := range []struct {
		name, sddl string
		volumeRoot bool
		allowed    bool
	}{
		{"ordinary app", "O:BA" + systemAndAdmins + "(A;OICI;FRFX;;;BU)", false, true},
		{"installer owner", "O:" + trustedInstallerSID + systemAndAdmins + "(A;;FA;;;" + trustedInstallerSID + ")", false, true},
		{"user owner", "O:BU" + systemAndAdmins, false, false},
		{"no ACL", "O:BA", false, false},
		{"empty ACL", "O:BAD:", false, false},
		{"user gets write", "O:BA" + systemAndAdmins + "(A;;GW;;;AU)", false, false},
		{"user gets full access", "O:BA" + systemAndAdmins + "(A;;GA;;;BU)", false, false},
		{"user gets ownership", "O:BA" + systemAndAdmins + "(A;;WO;;;WD)", false, false},
		{"user gets ACL write", "O:BA" + systemAndAdmins + "(A;;WD;;;BU)", false, false},
		{"user can delete children", "O:BA" + systemAndAdmins + "(A;;0x40;;;BU)", true, false},
		{"user can delete folder", "O:BA" + systemAndAdmins + "(A;;SD;;;BU)", false, false},
		{"user can write attributes", "O:BA" + systemAndAdmins + "(A;;0x100;;;BU)", false, false},
		{"user can create siblings at volume root", "O:BA" + systemAndAdmins + "(A;;0x4;;;AU)", true, true},
		{"user can add files at volume root", "O:BA" + systemAndAdmins + "(A;;0x2;;;AU)", true, false},
		{"user can create inside package", "O:BA" + systemAndAdmins + "(A;;0x4;;;AU)", false, false},
		{"inherit-only checked on child", "O:SY" + systemAndAdmins + "(A;OICIIO;GW;;;AU)", false, true},
		{"user deny cannot add rights", "O:SYD:(D;;GW;;;BU)(A;;FA;;;BA)", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateWindowsInstallationACL(descriptor, tc.volumeRoot, installer); (err == nil) != tc.allowed {
				t.Fatal(err)
			}
		})
	}
}

func TestWindowsInstallationChecksWholeTreeFromVolumeRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Wormhole")
	app := filepath.Join(root, "Wormhole.exe")
	backend := filepath.Join(root, "resources", "app", "dist-electron", "wormhole-backend-x64.exe")
	asset := filepath.Join(root, "resources", "runtime.dll")
	if err := os.MkdirAll(filepath.Dir(backend), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{app, asset, backend} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var ancestors []string
	for path := filepath.Dir(root); ; path = filepath.Dir(path) {
		ancestors = append([]string{path}, ancestors...)
		if filepath.Dir(path) == path {
			break
		}
	}
	var seen []string
	inspect := func(path string, dir, volumeRoot bool) error {
		if volumeRoot != (len(seen) == 0) || (path == backend || path == app || path == asset) == dir {
			t.Fatalf("wrong node type for %s", path)
		}
		seen = append(seen, path)
		return nil
	}
	ctx := context.Background()
	if _, err := checkWindowsInstallation(ctx, app, backend); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("user-writable installation did not block", err)
	}
	if err := checkInstallationTree(ctx, root, app, backend, inspect); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen[:len(ancestors)], ancestors) || len(seen) != len(ancestors)+7 {
		t.Fatalf("unexpected walk order or size: %v", seen)
	}
	if !isInstalledExecutable(backend, strings.ToUpper(backend)) || isInstalledExecutable(app, backend) {
		t.Fatal("process image identity did not match its exact installation file")
	}
	if err := checkInstallationTree(ctx, root, app, backend, func(path string, _, _ bool) error {
		if path == asset {
			return ErrInstallationLocation
		}
		return nil
	}); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("unsafe dependency did not block", err)
	}
	if err := os.Remove(backend); err != nil {
		t.Fatal(err)
	}
	accept := func(string, bool, bool) error { return nil }
	if err := checkInstallationTree(ctx, root, app, backend, accept); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("missing executable did not block", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := checkInstallationTree(canceled, root, app, backend, accept); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMachineInstallationCheckRejectsUnbundledProcesses(t *testing.T) {
	for _, floor := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
		err := CheckInstallationFloor(context.Background(), floor, "")
		if (floor == vault.Hardened || floor == vault.Paranoid) != errors.Is(err, ErrInstallationLocation) {
			t.Fatalf("unexpected result for %s: %v", floor, err)
		}
	}
	if err := CheckInstallationFloor(context.Background(), vault.Profile("future"), ""); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("unknown installation policy was accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckInstallationFloor(ctx, vault.Default, ""); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preflight was accepted", err)
	}
}
