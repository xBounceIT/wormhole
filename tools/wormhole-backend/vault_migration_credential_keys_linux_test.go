//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type migrationBusFixture struct {
	mu        sync.Mutex
	present   bool
	value     []byte
	attribute string
}

func (f *migrationBusFixture) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if attributes["service"] != "Wormhole" || attributes[f.attribute] != "credential:11111111-1111-4111-8111-111111111111" || len(attributes) != 2 {
		return nil, nil, dbus.MakeFailedError(io.ErrUnexpectedEOF)
	}
	if !f.present {
		return []dbus.ObjectPath{}, []dbus.ObjectPath{}, nil
	}
	return []dbus.ObjectPath{migrationTestItem}, []dbus.ObjectPath{}, nil
}
func (f *migrationBusFixture) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != "plain" || input.Value() != "" {
		return dbus.MakeVariant(""), "/", dbus.MakeFailedError(io.ErrUnexpectedEOF)
	}
	return dbus.MakeVariant(""), migrationTestSession, nil
}
func (f *migrationBusFixture) GetSecret(session dbus.ObjectPath) (migrationDBusSecret, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if session != migrationTestSession || !f.present {
		return migrationDBusSecret{}, dbus.MakeFailedError(io.ErrUnexpectedEOF)
	}
	return migrationDBusSecret{Session: session, Parameters: []byte{}, Value: bytes.Clone(f.value), ContentType: "application/octet-stream"}, nil
}
func (f *migrationBusFixture) Delete() (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.present = false
	return "/", nil
}
func (f *migrationBusFixture) Close() *dbus.Error { return nil }

func startPrivateLinuxTestBus(t *testing.T, ctx context.Context, cancel context.CancelFunc) string {
	t.Helper()
	daemon := exec.CommandContext(ctx, "dbus-daemon", "--session", "--nofork", "--print-address=1")
	daemon.Stderr = io.Discard
	stdout, err := daemon.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Start(); err != nil {
		t.Fatal("private test dbus-daemon required", err)
	}
	t.Cleanup(func() { cancel(); _ = daemon.Wait() })
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 4096)
	if !scanner.Scan() {
		t.Fatal("private D-Bus did not return an address", scanner.Err())
	}
	return scanner.Text()
}

// A private bus and in-process Secret Service exercise the actual Linux adapter
// and godbus marshalling. They cannot resolve or change a desktop user's items.
func TestVaultMigrationCredentialKeysNativeLinux(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	address := startPrivateLinuxTestBus(t, ctx, cancel)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	server, err := dbus.Connect(address, dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	fixture := &migrationBusFixture{}
	for path, iface := range map[dbus.ObjectPath]string{"/org/freedesktop/secrets": "org.freedesktop.Secret.Service", migrationTestItem: "org.freedesktop.Secret.Item", migrationTestSession: "org.freedesktop.Secret.Session"} {
		if err := server.Export(fixture, path, iface); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := server.RequestName("org.freedesktop.secrets", dbus.NameFlagDoNotQueue); err != nil || result != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("private service name unavailable", err)
	}
	t.Setenv("PATH", t.TempDir())
	id := "11111111-1111-4111-8111-111111111111"
	for _, encoding := range []string{linuxLegacySecretServiceEncoding, linuxSecretServiceEncoding} {
		fixture.mu.Lock()
		fixture.present = true
		fixture.value = []byte(" \x00native secret\n ")
		fixture.attribute = "username"
		if encoding == linuxLegacySecretServiceEncoding {
			fixture.attribute = "account"
		}
		fixture.mu.Unlock()
		if encoding == linuxLegacySecretServiceEncoding {
			value, err := migrationSecretReader(ctx, 1024)(id, id, encoding)
			if err != nil || !bytes.Equal(value, fixture.value) {
				t.Fatal("legacy staging read depended on an external tool", err)
			}
			clearBytes(value)
		}
		store, err := openMigrationCredentialStore(ctx, legacyInventoryRow{ID: id, Reference: id, Encoding: encoding}, 1024)
		if err != nil {
			t.Fatal(err)
		}
		value, present, err := store.Load(ctx)
		if err != nil || !present || !bytes.Equal(value, fixture.value) {
			store.Close()
			t.Fatal("wire secret changed", err)
		}
		clearBytes(value)
		if err := store.Delete(ctx); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if value, present, err := store.Load(ctx); err != nil || present || len(value) != 0 {
			store.Close()
			t.Fatal("wire absence not confirmed", err)
		}
		store.Close()
		store.Close()
	}
	if _, err := openMigrationCredentialStore(ctx, legacyInventoryRow{ID: id, Reference: id, Encoding: darwinKeychainEncoding}, 1024); err == nil {
		t.Fatal("foreign store admitted")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "absent-bus"))
	if _, err := openMigrationCredentialStore(ctx, legacyInventoryRow{ID: id, Reference: id, Encoding: linuxSecretServiceEncoding}, 1024); err == nil {
		t.Fatal("unavailable bus admitted")
	}
}
