//go:build linux

package main

import (
	"context"
	"io"
	"os"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func runVaultSessionMonitor(input io.Reader, output io.Writer) int {
	return monitorLinuxVaultSession(input, output, func(address string, options ...dbus.ConnOption) (linuxVaultConnection, error) {
		return dbus.Connect(address, options...)
	}, acquireLinuxSleepDelay, os.Getenv("DBUS_SESSION_BUS_ADDRESS"), uint32(os.Getppid()))
}

func acquireLinuxSleepDelay(ctx context.Context, system *linuxVaultBus) io.Closer {
	ctx, cancel := context.WithTimeout(ctx, linuxBusQueryTimeout)
	defer cancel()
	var fd dbus.UnixFD
	manager := system.Object(linuxLoginService, linuxLoginManagerPath)
	if manager.CallWithContext(ctx, linuxLoginService+".Manager.Inhibit", dbus.FlagNoAutoStart,
		"sleep", "Wormhole", "Retire vault keys before suspend", "delay").Store(&fd) != nil || fd < 0 {
		return nil
	}
	unix.CloseOnExec(int(fd))
	return os.NewFile(uintptr(fd), "logind-sleep-delay")
}
