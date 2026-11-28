package main

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const linuxBusQueryTimeout = time.Second

type linuxVaultBus struct {
	linuxVaultConnection
	signals  chan *dbus.Signal
	overflow chan struct{}
}

type linuxVaultConnection interface {
	Context() context.Context
	Close() error
	AddMatchSignalContext(context.Context, ...dbus.MatchOption) error
	BusObject() dbus.BusObject
	Object(string, dbus.ObjectPath) dbus.BusObject
}

type linuxVaultDial func(string, ...dbus.ConnOption) (linuxVaultConnection, error)

func (b *linuxVaultBus) DeliverSignal(_, _ string, signal *dbus.Signal) {
	select {
	case b.signals <- signal:
	default:
		select {
		case b.overflow <- struct{}{}:
		default:
		}
	}
}

func openLinuxVaultBus(ctx context.Context, dial linuxVaultDial, address string, matches [][]dbus.MatchOption) *linuxVaultBus {
	// Neither the system nor the user bus needs a TCP address or auto-launch.
	for _, candidate := range strings.Split(address, ";") {
		if !strings.HasPrefix(candidate, "unix:") {
			return nil
		}
	}
	b := &linuxVaultBus{signals: make(chan *dbus.Signal, 16), overflow: make(chan struct{}, 1)}
	conn, err := dial(address, dbus.WithContext(ctx), dbus.WithSignalHandler(b))
	if err != nil {
		return nil
	}
	b.linuxVaultConnection = conn
	for _, match := range matches {
		call, cancel := context.WithTimeout(ctx, linuxBusQueryTimeout)
		err := conn.AddMatchSignalContext(call, match...)
		cancel()
		if err != nil {
			_ = conn.Close()
			return nil
		}
	}
	return b
}

func linuxLoginMatches() [][]dbus.MatchOption {
	return [][]dbus.MatchOption{
		{dbus.WithMatchSender(linuxLoginService), dbus.WithMatchPathNamespace(linuxSessionNamespace),
			dbus.WithMatchInterface(linuxLoginSession), dbus.WithMatchMember("Lock")},
		{dbus.WithMatchSender(linuxLoginService), dbus.WithMatchPathNamespace(linuxSessionNamespace),
			dbus.WithMatchInterface("org.freedesktop.DBus.Properties"), dbus.WithMatchMember("PropertiesChanged"),
			dbus.WithMatchArg(0, linuxLoginSession)},
		{dbus.WithMatchSender(linuxLoginService), dbus.WithMatchObjectPath(linuxLoginManagerPath),
			dbus.WithMatchInterface(linuxLoginService + ".Manager"), dbus.WithMatchMember("PrepareForSleep")},
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchObjectPath("/org/freedesktop/DBus"),
			dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
			dbus.WithMatchArg(0, linuxLoginService)},
	}
}

func linuxScreenSaverMatches() [][]dbus.MatchOption {
	var matches [][]dbus.MatchOption
	for service, paths := range linuxScreenSaverPaths {
		for _, path := range paths {
			matches = append(matches, []dbus.MatchOption{
				dbus.WithMatchSender(service), dbus.WithMatchObjectPath(path),
				dbus.WithMatchInterface(service), dbus.WithMatchMember("ActiveChanged"),
			})
		}
	}
	return matches
}

func (b *linuxVaultBus) verify(ctx context.Context, signal *dbus.Signal, system bool, pid uint32) bool {
	service := linuxVaultLockService(signal, system)
	if service == "" ||
		(system && !strings.HasPrefix(string(signal.Path), linuxSessionNamespace+"/")) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, linuxBusQueryTimeout)
	defer cancel()
	// Unicast signals can bypass a daemon's match rules. Verify the unique
	// sender again before acting on this candidate, even after service restart.
	if !b.ownsSender(ctx, service, signal.Sender) {
		return false
	}
	if !system {
		return true
	}
	// Resolve the real main process session each time. This avoids pinning a
	// stale object across a logind restart or trusting XDG_SESSION_ID.
	var session dbus.ObjectPath
	manager := b.Object(signal.Sender, linuxLoginManagerPath)
	return manager.CallWithContext(ctx, linuxLoginService+".Manager.GetSessionByPID", 0, pid).Store(&session) == nil &&
		session == signal.Path
}

func (b *linuxVaultBus) ownsSender(ctx context.Context, service, sender string) bool {
	var owner string
	return strings.HasPrefix(sender, ":") &&
		b.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, service).Store(&owner) == nil &&
		owner == sender
}

type linuxSleepInhibitor func(context.Context, *linuxVaultBus) io.Closer

// This helper accepts only acknowledgements and keeps desktop metadata private.
func monitorLinuxVaultSession(input io.Reader, output io.Writer, dial linuxVaultDial, inhibit linuxSleepInhibitor, sessionAddress string, parentPID uint32) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	acks := make(chan uint32, 1)
	go func() {
		defer cancel()
		readLinuxSleepAcks(ctx, input, acks)
	}()

	system := openLinuxVaultBus(ctx, dial, "unix:path=/run/dbus/system_bus_socket", linuxLoginMatches())
	screen := openLinuxVaultBus(ctx, dial, sessionAddress, linuxScreenSaverMatches())
	var sleep *linuxSleepDelay
	if system != nil && inhibit != nil {
		sleep = &linuxSleepDelay{acks: acks, acquire: func(ctx context.Context) io.Closer {
			return inhibit(ctx, system)
		}}
	}
	return serveLinuxVaultSession(ctx, system, screen, parentPID, output, sleep)
}

func serveLinuxVaultSession(ctx context.Context, system, screen *linuxVaultBus, pid uint32, output io.Writer, sleep *linuxSleepDelay) int {
	var systemSignals, screenSignals <-chan *dbus.Signal
	var systemDone, screenDone <-chan struct{}
	var systemOverflow, screenOverflow <-chan struct{}
	if system != nil {
		defer system.Close()
		systemSignals, systemDone, systemOverflow = system.signals, system.Context().Done(), system.overflow
	}
	if screen != nil {
		defer func() {
			if screen != nil {
				_ = screen.Close()
			}
		}()
		screenSignals, screenDone, screenOverflow = screen.signals, screen.Context().Done(), screen.overflow
	}
	if ctx.Err() != nil {
		return 0
	}
	if system == nil && screen == nil {
		return 1
	}
	var acks <-chan uint32
	if sleep != nil {
		defer sleep.release()
		sleep.arm(ctx)
		acks = sleep.acks
	}
	if _, err := io.WriteString(output, "ready\n"); err != nil {
		return 1
	}
	sourceLost := func() int {
		if ctx.Err() != nil {
			return 0
		}
		return 1
	}
	screenLostDuringSleep := false
	preserveDelay := func() bool {
		if sleep == nil || !sleep.pending {
			return false
		}
		// A lost ScreenSaver connection does not invalidate logind's delay.
		// Stop watching it and reconnect after the current sleep cycle.
		_ = screen.Close()
		screen = nil
		screenSignals, screenDone, screenOverflow = nil, nil, nil
		screenLostDuringSleep = true
		return true
	}
	for {
		var shouldLock bool
		select {
		case <-ctx.Done():
			return 0
		case <-systemDone:
			return sourceLost()
		case <-screenDone:
			if preserveDelay() {
				continue
			}
			return sourceLost()
		case <-systemOverflow:
			return sourceLost()
		case <-screenOverflow:
			if preserveDelay() {
				continue
			}
			return sourceLost()
		case ticket := <-acks:
			sleep.acknowledge(ticket)
		case signal := <-systemSignals:
			if linuxLoginOwnerChanged(signal) {
				// The system bus can stay connected across a logind restart.
				// The old delay descriptor and any pending resume are stale.
				return sourceLost()
			}
			if sleep != nil {
				handled, err := sleep.handle(ctx, system, signal, output)
				if err != nil {
					return 1
				}
				if handled {
					if screenLostDuringSleep && !sleep.pending {
						return sourceLost()
					}
					continue
				}
			}
			shouldLock = system.verify(ctx, signal, true, pid)
		case signal := <-screenSignals:
			shouldLock = screen.verify(ctx, signal, false, pid)
		}
		if shouldLock {
			if _, err := io.WriteString(output, "lock\n"); err != nil {
				return 1
			}
		}
	}
}
