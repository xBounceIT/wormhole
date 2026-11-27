//go:build linux

package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type linuxLoginFixture struct{ sleepFD *os.File }

func (linuxLoginFixture) GetSessionByPID(pid uint32) (dbus.ObjectPath, *dbus.Error) {
	if pid != 1234 {
		return "", dbus.NewError("org.freedesktop.login1.NoSessionForPID", nil)
	}
	return linuxFixtureSession, nil
}

func (f linuxLoginFixture) Inhibit(what, who, why, mode string) (dbus.UnixFD, *dbus.Error) {
	if what != "sleep" || who != "Wormhole" || why == "" || mode != "delay" || f.sleepFD == nil {
		return -1, dbus.NewError("org.freedesktop.login1.InhibitDenied", nil)
	}
	return dbus.UnixFD(f.sleepFD.Fd()), nil
}

type privateDBusSleepLease struct {
	io.Closer
	closed chan struct{}
}

func (f *privateDBusSleepLease) Close() error {
	err := f.Closer.Close()
	close(f.closed)
	return err
}

func TestLinuxVaultMonitorWithPrivateDBus(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	address := startPrivateLinuxTestBus(t, ctx, cancel)
	server, err := dbus.Connect(address, dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	const screenSaver = "org.freedesktop.ScreenSaver"
	for _, name := range []string{linuxLoginService, screenSaver} {
		result, err := server.RequestName(name, dbus.NameFlagDoNotQueue)
		if err != nil || result != dbus.RequestNameReplyPrimaryOwner {
			t.Fatal("could not register the private desktop test provider", err)
		}
	}
	readLease, writeLease, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readLease.Close()
	defer writeLease.Close()
	if err := server.Export(linuxLoginFixture{sleepFD: readLease}, linuxLoginManagerPath, linuxLoginService+".Manager"); err != nil {
		t.Fatal(err)
	}
	dial := func(address string, options ...dbus.ConnOption) (linuxVaultConnection, error) {
		return dbus.Connect(address, options...)
	}
	system := openLinuxVaultBus(ctx, dial, address, linuxLoginMatches())
	screen := openLinuxVaultBus(ctx, dial, address, linuxScreenSaverMatches())
	if system == nil || screen == nil {
		t.Fatal("could not subscribe monitor connections to the private bus")
	}

	output, child := io.Pipe()
	defer output.Close()
	done := make(chan int, 1)
	acks := make(chan uint32, 1)
	descriptors := make(chan *privateDBusSleepLease, 2)
	sleep := &linuxSleepDelay{acks: acks, acquire: func(ctx context.Context) io.Closer {
		fd := acquireLinuxSleepDelay(ctx, system)
		if fd == nil {
			descriptors <- nil
			return nil
		}
		lease := &privateDBusSleepLease{Closer: fd, closed: make(chan struct{})}
		descriptors <- lease
		return lease
	}}
	go func() {
		defer child.Close()
		done <- serveLinuxVaultSession(ctx, system, screen, 1234, child, sleep)
	}()
	reader := bufio.NewReader(output)
	expect := func(want string) {
		t.Helper()
		if line, err := reader.ReadString('\n'); line != want || err != nil {
			t.Fatalf("desktop monitor output = %q %v, want %q", line, err, want)
		}
	}
	expect("ready\n")
	first := <-descriptors
	if first == nil {
		t.Fatal("private logind did not send a native delay descriptor")
	}
	if err := server.Emit(linuxFixtureSession, linuxPropertiesSignal,
		linuxLoginSession, map[string]dbus.Variant{"Active": dbus.MakeVariant(false)}, []string{}); err != nil {
		t.Fatal(err)
	}
	expect("lock\n")
	if err := server.Emit("/ScreenSaver", screenSaver+".ActiveChanged", true); err != nil {
		t.Fatal(err)
	}
	expect("lock\n")
	if err := server.Emit(linuxLoginManagerPath, linuxPrepareForSleep, true); err != nil {
		t.Fatal(err)
	}
	expect("sleep 1\n")
	select {
	case <-first.closed:
		t.Fatal("native descriptor was closed before confirmation")
	default:
	}
	acks <- 1
	select {
	case <-first.closed:
	case <-ctx.Done():
		t.Fatal("matching acknowledgement did not close the native descriptor")
	}
	if err := server.Emit(linuxLoginManagerPath, linuxPrepareForSleep, false); err != nil {
		t.Fatal(err)
	}
	expect("resume 1\n")
	second := <-descriptors
	if second == nil {
		t.Fatal("private logind did not issue a new descriptor on resume")
	}
	cancel()
	if result := <-done; result != 0 {
		t.Fatal("intentional parent cancellation was treated as transport failure", result)
	}
	select {
	case <-second.closed:
	default:
		t.Fatal("process cancellation leaked the resumed descriptor")
	}
}
