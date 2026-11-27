package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	linuxLoginManagerPath = "/org/freedesktop/login1"
	linuxPrepareForSleep  = linuxLoginService + ".Manager.PrepareForSleep"
)

type linuxSleepDelay struct {
	acquire func(context.Context) io.Closer
	acks    <-chan uint32
	lease   io.Closer
	ticket  uint32
	pending bool
}

func (s *linuxSleepDelay) arm(ctx context.Context) {
	if s.lease == nil {
		s.lease = s.acquire(ctx)
	}
}

func (s *linuxSleepDelay) release() {
	if s.lease != nil {
		_ = s.lease.Close()
		s.lease = nil
	}
}

func (s *linuxSleepDelay) acknowledge(ticket uint32) {
	if s.pending && s.ticket == ticket {
		s.release()
	}
}

func (s *linuxSleepDelay) handle(ctx context.Context, system *linuxVaultBus, signal *dbus.Signal, output io.Writer) (bool, error) {
	if signal == nil || signal.Name != linuxPrepareForSleep {
		return false, nil
	}
	if signal.Path != linuxLoginManagerPath || len(signal.Body) != 1 {
		return true, nil
	}
	preparing, ok := signal.Body[0].(bool)
	if !ok {
		return true, nil
	}
	query, cancel := context.WithTimeout(ctx, linuxBusQueryTimeout)
	defer cancel()
	if !system.ownsSender(query, linuxLoginService, signal.Sender) {
		return true, nil
	}
	if preparing {
		if s.pending {
			return true, nil
		}
		if s.lease == nil {
			// logind denied the inhibitor or the provider was unavailable.
			// Preserve the ordinary lock signal without claiming a delay.
			_, err := io.WriteString(output, "lock\n")
			return true, err
		}
		if s.ticket == ^uint32(0) {
			return true, fmt.Errorf("vault sleep ticket exhausted")
		}
		s.ticket++
		s.pending = true
		_, err := fmt.Fprintf(output, "sleep %d\n", s.ticket)
		return true, err
	}
	if !s.pending {
		s.arm(ctx)
		return true, nil
	}
	s.release()
	s.pending = false
	s.arm(ctx)
	_, err := fmt.Fprintf(output, "resume %d\n", s.ticket)
	return true, err
}

// stdin is owned by main. Only a bounded acknowledgement of the currently
// pending cycle can release its descriptor. EOF also ends the native monitor.
func readLinuxSleepAcks(ctx context.Context, input io.Reader, acks chan<- uint32) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 32), 32)
	for scanner.Scan() {
		text, ok := strings.CutPrefix(scanner.Text(), "ack ")
		if !ok || len(text) == 0 || len(text) > 10 || text[0] == '0' {
			continue
		}
		ticket, err := strconv.ParseUint(text, 10, 32)
		if err != nil || strconv.FormatUint(ticket, 10) != text {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case acks <- uint32(ticket):
		}
	}
}
