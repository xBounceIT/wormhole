package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

type sleepLeaseFixture struct {
	closes int
	closed chan struct{}
}

func (f *sleepLeaseFixture) Close() error {
	f.closes++
	if f.closed != nil && f.closes == 1 {
		close(f.closed)
	}
	return nil
}

func sleepSignal(sender string, preparing bool) *dbus.Signal {
	return &dbus.Signal{Sender: sender, Path: linuxLoginManagerPath, Name: linuxPrepareForSleep, Body: []any{preparing}}
}

func TestLinuxSleepDelayWaitsForTheCurrentTicketAndRearms(t *testing.T) {
	ctx := t.Context()
	const owner = ":1.2"
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: ctx, owner: owner})
	var leases []*sleepLeaseFixture
	delay := linuxSleepDelay{acquire: func(context.Context) io.Closer {
		lease := &sleepLeaseFixture{}
		leases = append(leases, lease)
		return lease
	}}
	var out bytes.Buffer
	signal := func(event *dbus.Signal) {
		t.Helper()
		handled, err := delay.handle(ctx, system, event, &out)
		if !handled || err != nil {
			t.Fatalf("sleep signal missed: %v %v", handled, err)
		}
	}
	if handled, _ := delay.handle(ctx, system, nil, &out); handled {
		t.Fatal("claimed a non-sleep signal")
	}
	delay.arm(ctx)
	delay.arm(ctx)
	signal(sleepSignal(":1.99", true))
	signal(&dbus.Signal{Sender: owner, Name: linuxPrepareForSleep, Body: []any{true}})
	signal(&dbus.Signal{Sender: owner, Path: linuxLoginManagerPath, Name: linuxPrepareForSleep, Body: []any{"true"}})
	if out.Len() != 0 || len(leases) != 1 {
		t.Fatal("forged or malformed sleep signal changed native state")
	}

	signal(sleepSignal(owner, true))
	signal(sleepSignal(owner, true))
	delay.acknowledge(0)
	delay.acknowledge(2)
	if leases[0].closes != 0 || out.String() != "sleep 1\n" {
		t.Fatal("duplicate signal or stale acknowledgement changed the active lease")
	}
	delay.acknowledge(1)
	delay.acknowledge(1)
	if leases[0].closes != 1 {
		t.Fatal("verified acknowledgement did not release exactly one lease")
	}
	signal(sleepSignal(owner, false))
	signal(sleepSignal(owner, false))
	signal(sleepSignal(owner, true))
	delay.acknowledge(1)
	if len(leases) != 2 || leases[1].closes != 0 || out.String() != "sleep 1\nresume 1\nsleep 2\n" {
		t.Fatal("an old acknowledgement released a new suspend cycle")
	}

	// If logind times out or cancels before retirement is confirmed, discard
	// the old lease on resume and take a fresh one for the next transition.
	signal(sleepSignal(owner, false))
	if len(leases) != 3 || leases[1].closes != 1 || out.String() != "sleep 1\nresume 1\nsleep 2\nresume 2\n" {
		t.Fatal("resume did not retire and replace the timed-out lease")
	}
	delay.release()
}

func TestLinuxSleepDelayKeepsDefaultLockWhenLogindDeniesInhibition(t *testing.T) {
	ctx := t.Context()
	var output bytes.Buffer
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: ctx, owner: ":1.2"})
	delay := linuxSleepDelay{acquire: func(context.Context) io.Closer { return nil }}
	delay.arm(ctx)
	for _, preparing := range []bool{true, false} {
		if handled, err := delay.handle(ctx, system, sleepSignal(":1.2", preparing), &output); !handled || err != nil {
			t.Fatalf("uninhibited fallback returned %t %v", handled, err)
		}
	}
	if output.String() != "lock\n" || delay.pending {
		t.Fatal("uninhibited sleep attempted the confirmed delay protocol")
	}
}

func TestLinuxSleepDelayReleasesThroughTheMonitorAndOnExit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: ctx, owner: ":1.2"})
	first := &sleepLeaseFixture{closed: make(chan struct{})}
	second := &sleepLeaseFixture{closed: make(chan struct{})}
	leases := []io.Closer{first, second}
	acks := make(chan uint32, 1)
	sleep := &linuxSleepDelay{acks: acks, acquire: func(context.Context) io.Closer {
		lease := leases[0]
		leases = leases[1:]
		return lease
	}}
	output, child := io.Pipe()
	defer output.Close()
	defer child.Close()
	done := make(chan int, 1)
	go func() { done <- serveLinuxVaultSession(ctx, system, nil, 1234, child, sleep) }()
	reader := bufio.NewReader(output)
	expect := func(want string) {
		t.Helper()
		if got, err := reader.ReadString('\n'); got != want || err != nil {
			t.Fatalf("monitor emitted %q, %v, want %q", got, err, want)
		}
	}
	expect("ready\n")
	system.DeliverSignal("", "", sleepSignal(":1.2", true))
	expect("sleep 1\n")
	select {
	case <-first.closed:
		t.Fatal("descriptor was released before acknowledgement")
	default:
	}
	acks <- 1
	<-first.closed
	system.DeliverSignal("", "", sleepSignal(":1.2", false))
	expect("resume 1\n")
	cancel()
	if result := <-done; result != 0 || second.closes != 1 {
		t.Fatalf("source exit did not close its new descriptor: %d, %d", result, second.closes)
	}
}

func TestLinuxSleepAcknowledgementsHaveOneBoundedCanonicalShape(t *testing.T) {
	acks := make(chan uint32, 5)
	readLinuxSleepAcks(t.Context(), strings.NewReader("ready\nack\nack \nack 0\nack 01\nack +2\nack -1\nack 4294967296\nack 12345678901\nack 1\nack 4294967295\n"), acks)
	close(acks)
	var got []uint32
	for value := range acks {
		got = append(got, value)
	}
	if !reflect.DeepEqual(got, []uint32{1, 4294967295}) {
		t.Fatalf("incorrect acknowledgements: %v", got)
	}
}

func TestLinuxSleepMonitorReleasesItsLeaseWhenLogindRestarts(t *testing.T) {
	ctx := t.Context()
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: ctx, owner: ":1.2"})
	lease := &sleepLeaseFixture{}
	delay := &linuxSleepDelay{acquire: func(context.Context) io.Closer { return lease }}
	signal := &dbus.Signal{Path: "/org/freedesktop/DBus", Name: "org.freedesktop.DBus.NameOwnerChanged",
		Sender: ":1.99", Body: []any{linuxLoginService, ":1.2", ""}}
	if linuxLoginOwnerChanged(signal) {
		t.Fatal("accepted a forged daemon signal")
	}
	unknown := *signal
	unknown.Sender = "org.freedesktop.DBus"
	unknown.Body = []any{"org.example.Unrelated", ":1.2", ""}
	if linuxLoginOwnerChanged(&unknown) {
		t.Fatal("unrelated service must not invalidate the monitor")
	}
	signal.Sender = "org.freedesktop.DBus"
	system.DeliverSignal("", "", signal)
	var output bytes.Buffer
	if result := serveLinuxVaultSession(ctx, system, nil, 1234, &output, delay); result != 1 || lease.closes != 1 {
		t.Fatalf("monitor retained a stale logind lease: %d, %d", result, lease.closes)
	}
}

func TestLinuxSleepMonitorKeepsItsDelayWhenScreenSaverDisconnects(t *testing.T) {
	ctx := t.Context()
	screenContext, stopScreen := context.WithCancel(ctx)
	defer stopScreen()
	system := linuxFixtureMonitor(&linuxFixtureBus{ctx: ctx, owner: ":1.2", session: linuxFixtureSession})
	screenClosed := make(chan struct{})
	screen := linuxFixtureMonitor(&linuxFixtureBus{ctx: screenContext, terminated: screenClosed})
	lease := &sleepLeaseFixture{closed: make(chan struct{})}
	leases := []io.Closer{lease, &sleepLeaseFixture{}}
	acks := make(chan uint32, 1)
	delay := &linuxSleepDelay{acks: acks, acquire: func(context.Context) io.Closer {
		next := leases[0]
		leases = leases[1:]
		return next
	}}
	output, child := io.Pipe()
	defer output.Close()
	defer child.Close()
	done := make(chan int, 1)
	go func() {
		defer child.Close()
		done <- serveLinuxVaultSession(ctx, system, screen, 1234, child, delay)
	}()
	reader := bufio.NewReader(output)
	expect := func(want string) {
		t.Helper()
		if got, err := reader.ReadString('\n'); err != nil || got != want {
			t.Fatalf("monitor emitted %q %v, want %q", got, err, want)
		}
	}
	expect("ready\n")
	system.DeliverSignal("", "", sleepSignal(":1.2", true))
	expect("sleep 1\n")
	stopScreen()
	<-screenClosed
	system.DeliverSignal("", "", &dbus.Signal{Name: linuxLoginSession + ".Lock", Sender: ":1.2", Path: linuxFixtureSession})
	expect("lock\n")
	select {
	case <-lease.closed:
		t.Fatal("lost ScreenSaver released logind's lease")
	default:
	}
	acks <- 1
	<-lease.closed
	// The resumed descriptor is a different lease, even if the active sleep
	// cycle had to be completed without the optional ScreenSaver source.
	system.DeliverSignal("", "", sleepSignal(":1.2", false))
	expect("resume 1\n")
	if result := <-done; result != 1 {
		t.Fatal("monitor did not reconnect after the completed delay cycle")
	}
}
