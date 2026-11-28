package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

const linuxFixtureSession = dbus.ObjectPath(linuxSessionNamespace + "/fixture")

type linuxFixtureObject struct {
	dbus.BusObject
	call func(string, ...any) *dbus.Call
}

func (o linuxFixtureObject) CallWithContext(_ context.Context, method string, _ dbus.Flags, args ...any) *dbus.Call {
	return o.call(method, args...)
}

type linuxFixtureBus struct {
	ctx        context.Context
	owner      string
	session    dbus.ObjectPath
	matchError error
	matches    int
	closed     int
	terminated chan struct{}
}

func (b *linuxFixtureBus) Context() context.Context { return b.ctx }
func (b *linuxFixtureBus) Close() error {
	b.closed++
	if b.terminated != nil && b.closed == 1 {
		close(b.terminated)
	}
	return nil
}
func (b *linuxFixtureBus) AddMatchSignalContext(context.Context, ...dbus.MatchOption) error {
	b.matches++
	return b.matchError
}
func (b *linuxFixtureBus) BusObject() dbus.BusObject {
	return linuxFixtureObject{call: func(method string, args ...any) *dbus.Call {
		if method != "org.freedesktop.DBus.GetNameOwner" || len(args) != 1 || b.owner == "" {
			return &dbus.Call{Err: errors.New("no trusted owner")}
		}
		return &dbus.Call{Body: []any{b.owner}}
	}}
}
func (b *linuxFixtureBus) Object(owner string, path dbus.ObjectPath) dbus.BusObject {
	return linuxFixtureObject{call: func(method string, args ...any) *dbus.Call {
		if owner != b.owner || path != "/org/freedesktop/login1" ||
			method != linuxLoginService+".Manager.GetSessionByPID" ||
			!reflect.DeepEqual(args, []any{uint32(1234)}) || b.session == "" {
			return &dbus.Call{Err: errors.New("unknown Linux session")}
		}
		return &dbus.Call{Body: []any{b.session}}
	}}
}

func linuxFixtureMonitor(b *linuxFixtureBus) *linuxVaultBus {
	return &linuxVaultBus{linuxVaultConnection: b, signals: make(chan *dbus.Signal, 4), overflow: make(chan struct{}, 1)}
}

func TestLinuxLockSignalUsesCurrentServiceOwnerAndActualLogindSession(t *testing.T) {
	fixture := &linuxFixtureBus{owner: ":1.4", session: linuxFixtureSession}
	bus := linuxFixtureMonitor(fixture)
	signal := &dbus.Signal{Name: linuxLoginSession + ".Lock", Sender: ":1.4", Path: linuxFixtureSession}
	if !bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("trusted lock for the actual session was ignored")
	}
	for _, pid := range []uint32{0, 99} {
		if bus.verify(t.Context(), signal, true, pid) {
			t.Fatal("signal was accepted without a matching parent session")
		}
	}
	signal.Path = "/org/freedesktop/login1/session/other"
	if bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("another session's lock was accepted")
	}
	signal.Path = "/"
	if bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("non-session path was accepted")
	}
	signal.Path = linuxFixtureSession
	fixture.owner = ":1.5"
	if bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("a previous or forged owner sent a lock")
	}
	signal.Sender = fixture.owner
	if !bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("the replacement owner was ignored")
	}
	signal.Sender = linuxLoginService
	if bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("a signal without a unique sender was accepted")
	}
	signal.Sender = ":1.5"
	fixture.owner = ""
	if bus.verify(t.Context(), signal, true, 1234) {
		t.Fatal("a signal without a live owner was accepted")
	}
}

func TestLinuxLockSignalsOnlyAcceptDesktopLockAndDeactivation(t *testing.T) {
	for _, test := range []struct {
		changed     map[string]dbus.Variant
		invalidated []string
		lock        bool
	}{
		{map[string]dbus.Variant{"Active": dbus.MakeVariant(false)}, nil, true},
		{map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, nil, true},
		{map[string]dbus.Variant{"Active": dbus.MakeVariant(true), "LockedHint": dbus.MakeVariant(false)}, nil, false},
		{map[string]dbus.Variant{"LockedHint": dbus.MakeVariant("unexpected type")}, nil, true},
		{nil, []string{"LockedHint"}, true},
		{nil, []string{"IdleHint"}, false},
	} {
		signal := &dbus.Signal{Name: linuxPropertiesSignal, Body: []any{linuxLoginSession, test.changed, test.invalidated}}
		if got := linuxVaultLockService(signal, true) != ""; got != test.lock {
			t.Fatalf("properties signal gives lock=%v for %#v", got, test)
		}
	}
	for _, signal := range []*dbus.Signal{
		nil,
		{Name: linuxLoginSession + ".Unlock"},
		{Name: linuxLoginSession + ".Lock", Body: []any{true}},
		{Name: linuxPropertiesSignal},
		{Name: linuxPropertiesSignal, Body: []any{linuxLoginSession, true, []string{}}},
		{Name: linuxPropertiesSignal, Body: []any{"org.freedesktop.login1.Seat", map[string]dbus.Variant{}, []string{"Active"}}},
	} {
		if linuxVaultLockService(signal, true) != "" {
			t.Fatalf("accepted a non-lock signal: %#v", signal)
		}
	}
	for service, paths := range linuxScreenSaverPaths {
		for _, path := range paths {
			signal := &dbus.Signal{Name: service + ".ActiveChanged", Path: path, Body: []any{true}}
			if linuxVaultLockService(signal, false) != service || linuxVaultLockService(signal, true) != "" {
				t.Fatalf("screen saver source resolved incorrectly: %#v", signal)
			}
			for _, body := range [][]any{nil, {false}, {[]string{"true"}}, {true, true}} {
				signal.Body = body
				if linuxVaultLockService(signal, false) != "" {
					t.Fatalf("invalid screen saver body was accepted: %#v", body)
				}
			}
			signal.Body, signal.Path = []any{true}, "/unexpected"
			if linuxVaultLockService(signal, false) != "" {
				t.Fatal("wrong screen saver path was accepted")
			}
		}
	}
}

func TestLinuxVaultSessionMonitorStopsOnParentEOF(t *testing.T) {
	input, parent := io.Pipe()
	defer input.Close()
	defer parent.Close()
	output, child := io.Pipe()
	defer output.Close()
	defer child.Close()
	system := &linuxFixtureBus{ctx: t.Context()}
	screen := &linuxFixtureBus{ctx: t.Context()}
	done := make(chan int, 1)
	go func() {
		done <- monitorLinuxVaultSession(input, child, func(address string, _ ...dbus.ConnOption) (linuxVaultConnection, error) {
			switch address {
			case "unix:path=/run/dbus/system_bus_socket":
				return system, nil
			case "unix:abstract=fixture;unix:path=/fallback":
				return screen, nil
			default:
				return nil, errors.New("unexpected bus")
			}
		}, nil, "unix:abstract=fixture;unix:path=/fallback", 1234)
	}()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("monitor readiness = %q %v", line, err)
	}
	_ = parent.Close()
	if result := <-done; result != 0 || system.closed != 1 || screen.closed != 1 ||
		system.matches != 4 || screen.matches != 4 {
		t.Fatalf("monitor did not subscribe and close both buses: %d %#v %#v", result, system, screen)
	}
}

func TestLinuxVaultSessionMonitorEmitsOnlyLockAndHandlesSourceLoss(t *testing.T) {
	systemContext, stopSystem := context.WithCancel(t.Context())
	defer stopSystem()
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: systemContext, owner: ":1.4", session: linuxFixtureSession})
	screen := linuxFixtureMonitor(&linuxFixtureBus{ctx: t.Context(), owner: ":1.5"})
	output, child := io.Pipe()
	defer output.Close()
	defer child.Close()
	done := make(chan int, 1)
	go func() { done <- serveLinuxVaultSession(t.Context(), system, screen, 1234, child, nil) }()
	reader := bufio.NewReader(output)
	expect := func(want string) {
		t.Helper()
		if line, err := reader.ReadString('\n'); err != nil || line != want {
			t.Fatalf("output = %q %v, want %q", line, err, want)
		}
	}
	expect("ready\n")
	system.DeliverSignal("", "", &dbus.Signal{Name: linuxLoginSession + ".Lock", Sender: ":1.4", Path: linuxFixtureSession})
	expect("lock\n")
	screen.DeliverSignal("", "", &dbus.Signal{Name: "org.gnome.ScreenSaver.ActiveChanged", Sender: ":1.5",
		Path: "/org/gnome/ScreenSaver", Body: []any{true}})
	expect("lock\n")
	stopSystem()
	if result := <-done; result != 1 {
		t.Fatal("lost an active signal source without failing the monitor", result)
	}
}

func TestLinuxVaultSessionMonitorBoundsUnavailableSourcesAndOverflow(t *testing.T) {
	for _, address := range []string{"", "tcp:host=127.0.0.1", "unix:path=/first;tcp:host=127.0.0.1"} {
		if b := openLinuxVaultBus(t.Context(), func(string, ...dbus.ConnOption) (linuxVaultConnection, error) {
			t.Fatal("dialed an unsupported bus address")
			return nil, nil
		}, address, nil); b != nil {
			t.Fatal("unavailable source was accepted")
		}
	}
	b := &linuxFixtureBus{ctx: t.Context(), matchError: errors.New("fixture missing rules")}
	if openLinuxVaultBus(t.Context(), func(string, ...dbus.ConnOption) (linuxVaultConnection, error) {
		return b, nil
	}, "unix:abstract=fixture", linuxLoginMatches()) != nil || b.closed != 1 {
		t.Fatal("failed subscription was left open")
	}
	if openLinuxVaultBus(t.Context(), func(string, ...dbus.ConnOption) (linuxVaultConnection, error) {
		return nil, errors.New("fixture unavailable")
	}, "unix:abstract=fixture", nil) != nil {
		t.Fatal("failed desktop connection registered as ready")
	}
	var output bytes.Buffer
	if serveLinuxVaultSession(t.Context(), nil, nil, 1234, &output, nil) == 0 || output.Len() != 0 {
		t.Fatal("monitor with no sources registered")
	}
	for _, system := range []bool{true, false} {
		flooded := linuxFixtureMonitor(&linuxFixtureBus{ctx: t.Context()})
		for range 8 {
			flooded.DeliverSignal("", "", nil)
		}
		if len(flooded.signals) != 4 || len(flooded.overflow) != 1 {
			t.Fatal("signal flood was not bounded")
		}
		for len(flooded.signals) != 0 {
			<-flooded.signals
		}
		output.Reset()
		primary, optional := flooded, (*linuxVaultBus)(nil)
		if !system {
			primary, optional = optional, primary
		}
		if serveLinuxVaultSession(t.Context(), primary, optional, 1234, &output, nil) != 1 || output.String() != "ready\n" {
			t.Fatal("overflow did not retire the monitor and notify main via process close")
		}
	}
}
