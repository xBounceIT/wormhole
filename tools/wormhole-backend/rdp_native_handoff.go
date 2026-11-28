package main

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errRdpNativeHandoff = errors.New("native RDP credential handoff failed")

type rdpNativeApply func([]byte, []byte, []byte, bool, bool) error

// The handoff owns its mutable credential buffers until one local COM setter
// consumes them. No authentication payload is written to the C# command pipe.
type rdpNativeHandoff struct {
	mu                               sync.Mutex
	password, gateway                []byte
	primaryProvided, gatewayProvided bool
	state                            atomic.Uint32 // 0 pending, 1 applying, 2 applied, 3 failed/closed
	timer                            *time.Timer
}

func newRdpNativeHandoff(password, gateway []byte, primaryProvided, gatewayProvided bool) *rdpNativeHandoff {
	return &rdpNativeHandoff{password: password, gateway: gateway, primaryProvided: primaryProvided, gatewayProvided: gatewayProvided}
}

func (h *rdpNativeHandoff) start(timeout time.Duration, interrupt func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state.Load() != 0 || h.timer != nil {
		return
	}
	h.timer = time.AfterFunc(timeout, func() {
		if h.state.Swap(3) != 2 {
			interrupt()
		}
		h.close()
	})
}

func (h *rdpNativeHandoff) consume(reference []byte, apply rdpNativeApply) (err error) {
	if h == nil {
		return errRdpNativeHandoff
	}
	if apply == nil {
		h.close()
		return errRdpNativeHandoff
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.state.CompareAndSwap(0, 1) {
		return errRdpNativeHandoff
	}
	defer func() {
		if h.timer != nil {
			h.timer.Stop()
		}
		clear(h.password)
		clear(h.gateway)
		h.password, h.gateway = nil, nil
		fault := recover()
		if err != nil || fault != nil {
			h.state.Store(3)
		}
		if fault != nil {
			panic(fault)
		}
	}()
	if err = apply(reference, h.password, h.gateway, h.primaryProvided, h.gatewayProvided); err != nil {
		return err
	}
	if h.timer == nil || !h.timer.Stop() || !h.state.CompareAndSwap(1, 2) {
		return errRdpNativeHandoff
	}
	return nil
}

func (h *rdpNativeHandoff) applied() bool { return h == nil || h.state.Load() == 2 }
func (h *rdpNativeHandoff) close() {
	if h == nil {
		return
	}
	h.state.Store(3)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.timer != nil {
		h.timer.Stop()
	}
	clear(h.password)
	clear(h.gateway)
	h.password, h.gateway = nil, nil
}

// Ignore an unselected gateway credential rather than copying it into a native
// authentication operation that cannot use it.
func legacyRdpNativeHandoff(profile *rdpProfile) *rdpNativeHandoff {
	primary := profile.Password != ""
	gateway := profile.GatewayUsageMethod != 0 && !profile.GatewayUseSameCreds && profile.GatewayPassword != ""
	if !primary && !gateway {
		return nil
	}
	var password, gatewayPassword []byte
	if primary {
		password = []byte(profile.Password)
	}
	if gateway {
		gatewayPassword = []byte(profile.GatewayPassword)
	}
	return newRdpProtocolHandoff(profile, password, gatewayPassword, primary, gateway)
}

// Takes ownership of both buffers. Native credential sharing is a single-prompt
// feature, not a way to share programmatically supplied passwords. Materialize a
// supplied shared password into two explicit native setters instead; a missing
// password keeps the native one-prompt path. No separate gateway secret is read.
func newRdpProtocolHandoff(profile *rdpProfile, password, gateway []byte, primaryProvided, gatewayProvided bool) *rdpNativeHandoff {
	if profile.GatewayUsageMethod == 0 || profile.GatewayUseSameCreds {
		clear(gateway)
		gateway = nil
		gatewayProvided = false
		if profile.GatewayUsageMethod != 0 && profile.GatewayUseSameCreds && primaryProvided {
			gateway = bytes.Clone(password)
			gatewayProvided = true
			profile.GatewayUseSameCreds = false
			profile.GatewayUsername = profile.Username
			if profile.Domain != "" && !strings.Contains(profile.GatewayUsername, "\\") {
				profile.GatewayUsername = profile.Domain + "\\" + profile.GatewayUsername
			}
		}
	}
	return newRdpNativeHandoff(password, gateway, primaryProvided, gatewayProvided)
}
