package main

// The windowless FreeRDP adapter speaks a bounded binary protocol over private
// pipes. Only pixels and lifecycle events cross back into Electron; credentials
// travel once, on stdin, in the same validated arguments as the system client.
import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const rdpTileSize = 128

type rdpCertificate struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
}

type rdpFrame struct {
	DesktopWidth  int    `json:"desktopWidth"`
	DesktopHeight int    `json:"desktopHeight"`
	X             int    `json:"x"`
	Y             int    `json:"y"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	RGBA          []byte `json:"rgba"`
}

type rdpInput struct {
	Kind  string `json:"kind"`
	X     int    `json:"x,omitempty"`
	Y     int    `json:"y,omitempty"`
	Flags int    `json:"flags,omitempty"`
	Code  int    `json:"code,omitempty"`
	Down  bool   `json:"down,omitempty"`
}

func (input rdpInput) valid() bool {
	switch input.Kind {
	case "pointer":
		return input.X >= 0 && input.X < rdpMaxDimension && input.Y >= 0 && input.Y < rdpMaxDimension &&
			(input.Flags == 0x0800 || input.Flags == 0x1000 || input.Flags == 0x2000 || input.Flags == 0x4000 ||
				input.Flags == 0x9000 || input.Flags == 0xa000 || input.Flags == 0xc000 || input.Flags == 0x0278 || input.Flags == 0x0388)
	case "key":
		return input.Code > 0 && input.Code <= 0x1ff
	case "unicode":
		return input.Code > 0 && input.Code <= 0xffff
	case "painted":
		return input.Code > 0 && int64(input.Code) <= 0xffffffff
	case "release":
		return true
	}
	return false
}

func writeRdpFramebufferStart(writer io.Writer, args []string) error {
	if len(args) > 256 {
		return errors.New("too many RDP settings")
	}
	total := 4
	for _, arg := range args {
		total += 4 + len(arg)
	}
	if total > rdpMaxCommandBytes {
		return errors.New("RDP settings are too large")
	}
	data := make([]byte, 4, total)
	binary.BigEndian.PutUint32(data, uint32(len(args)))
	for _, arg := range args {
		data = binary.BigEndian.AppendUint32(data, uint32(len(arg)))
		data = append(data, arg...)
	}
	_, err := writer.Write(data)
	clear(data)
	return err
}

func readRdpFramebufferEvent(reader io.Reader) (rdpEvent, error) {
	var header [28]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return rdpEvent{}, err
	}
	values := [7]uint32{}
	for i := range values {
		values[i] = binary.BigEndian.Uint32(header[i*4:])
	}
	switch values[0] {
	case 1:
		return rdpEvent{Type: "connected"}, nil
	case 3:
		if values[1] == 0 {
			return rdpEvent{}, errors.New("invalid RDP paint sequence")
		}
		return rdpEvent{Type: "frameEnd", PaintID: values[1]}, nil
	case 4:
		if values[1] == 0 || values[1] > 4096 || values[2] == 0 || values[2] > 4096 {
			return rdpEvent{}, errors.New("invalid RDP certificate notice")
		}
		data := make([]byte, values[1]+values[2])
		if _, err := io.ReadFull(reader, data); err != nil {
			return rdpEvent{}, err
		}
		if !utf8.Valid(data[:values[1]]) || !utf8.Valid(data[values[1]:]) {
			return rdpEvent{}, errors.New("invalid RDP certificate text")
		}
		return rdpEvent{Type: "certificate", Certificate: &rdpCertificate{Host: string(data[:values[1]]), Fingerprint: string(data[values[1]:])}}, nil
	case 2:
		frame := &rdpFrame{DesktopWidth: int(values[1]), DesktopHeight: int(values[2]), X: int(values[3]), Y: int(values[4]), Width: int(values[5]), Height: int(values[6])}
		if frame.DesktopWidth < 1 || frame.DesktopHeight < 1 || frame.DesktopWidth > rdpMaxDimension || frame.DesktopHeight > rdpMaxDimension ||
			int64(frame.DesktopWidth)*int64(frame.DesktopHeight) > 64*1024*1024 || frame.Width < 1 || frame.Height < 1 ||
			frame.Width > rdpTileSize || frame.Height > rdpTileSize || frame.X+frame.Width > frame.DesktopWidth || frame.Y+frame.Height > frame.DesktopHeight {
			return rdpEvent{}, errors.New("invalid RDP framebuffer tile")
		}
		frame.RGBA = make([]byte, frame.Width*frame.Height*4)
		if _, err := io.ReadFull(reader, frame.RGBA); err != nil {
			return rdpEvent{}, err
		}
		return rdpEvent{Type: "frame", Frame: frame}, nil
	default:
		return rdpEvent{}, errors.New("invalid RDP framebuffer event")
	}
}

func encodeRdpFramebufferCommand(command rdpCommand) ([]byte, error) {
	values := [5]uint32{}
	switch command.Op {
	case "certificate":
		values[0] = 9
		if command.CertificateAccepted {
			values[1] = 1
		}
	case "input":
		if command.Input == nil || !command.Input.valid() {
			return nil, errors.New("invalid RDP input")
		}
		input := command.Input
		switch input.Kind {
		case "pointer":
			values = [5]uint32{1, uint32(input.Flags), uint32(input.X), uint32(input.Y)}
		case "key", "unicode":
			values[0], values[1] = 2, uint32(input.Code)
			if input.Kind == "unicode" {
				values[0] = 3
			}
			if input.Down {
				values[2] = 1
			}
		case "release":
			values[0] = 7
		case "painted":
			values[0], values[1] = 8, uint32(input.Code)
		}
	case "resize":
		if !command.Bounds.valid() {
			return nil, errors.New("invalid RDP bounds")
		}
		values = [5]uint32{4, uint32(min(command.Bounds.Width, 8192)), uint32(min(command.Bounds.Height, 8192))}
	case "show":
		values[0] = 5
	case "hide":
		values[0] = 6
	case "focus":
		values[0] = 5
	default:
		return nil, errors.New("unsupported RDP surface command")
	}
	data := make([]byte, 20)
	for i, value := range values {
		binary.BigEndian.PutUint32(data[i*4:], value)
	}
	return data, nil
}

func locateRdpFramebufferHost() string {
	if path := os.Getenv("WORMHOLE_FREERDP_HOST"); path != "" {
		return path
	}
	if sibling := bundledSibling("wormhole-freerdp-host" + executableSuffix()); sibling != "" {
		return sibling
	}
	// The macOS runtime bundle is staged beside the Go backend by the packaging job.
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(executable), "freerdp", "bin", "wormhole-freerdp-host")
}

func (c *rdpController) startFramebufferRdp(command rdpCommand) {
	handoff := false
	defer func() {
		if !handoff {
			command.forwarder.close()
			command.tunnel.close()
		}
	}()
	fail := func(message string) {
		writeRdpEvent(rdpEvent{Type: "error", RequestID: command.RequestID, SessionID: command.SessionID, LifecycleID: command.LifecycleID, Backend: "freerdp", Message: message})
	}
	args, err := buildFramebufferArguments(command)
	if err != nil {
		fail(err.Error())
		return
	}
	cmd := exec.Command(locateRdpFramebufferHost())
	cmd.Env = rdpChildEnvironment(os.Environ())
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		fail("could not open the embedded FreeRDP surface")
		return
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		fail("could not read the embedded FreeRDP surface")
		return
	}
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		fail("the embedded FreeRDP surface is unavailable in this build")
		return
	}
	process := &rdpProcess{sessionID: command.SessionID, lifecycleID: command.LifecycleID, backend: "freerdp", process: cmd, stdin: input, framebuffer: true, nativeEventsDone: make(chan struct{}), lifecycleGeneration: command.LifecycleGeneration, tunnel: command.tunnel, forwarder: command.forwarder}
	if err = process.framebufferWrite(func() error { return writeRdpFramebufferStart(input, args) }, 5*time.Second); err != nil {
		stopRdpProcess(process)
		_ = output.Close()
		_ = cmd.Wait()
		fail("could not initialize the embedded FreeRDP surface")
		return
	}
	c.mu.Lock()
	c.processes[command.SessionID] = process
	c.mu.Unlock()
	handoff = true
	writeRdpEvent(rdpEvent{Type: "started", RequestID: command.RequestID, SessionID: command.SessionID, LifecycleID: command.LifecycleID, Backend: "freerdp", LifecycleGeneration: command.LifecycleGeneration})
	go c.readFramebufferEvents(process, output)
	go c.waitForExit(process)
}

func (c *rdpController) readFramebufferEvents(process *rdpProcess, output io.ReadCloser) {
	defer output.Close()
	defer close(process.nativeEventsDone)
	for {
		event, err := readRdpFramebufferEvent(output)
		if err != nil {
			if err != io.EOF {
				_ = process.process.Process.Kill()
			}
			return
		}
		event.SessionID, event.LifecycleID, event.Backend = process.sessionID, process.lifecycleID, process.backend
		event.LifecycleGeneration = process.lifecycleGeneration
		if c.shouldForwardProcessEvent(process, event) {
			writeRdpEvent(event)
		}
	}
}

func (process *rdpProcess) writeFramebuffer(command rdpCommand) error {
	data, err := encodeRdpFramebufferCommand(command)
	if err != nil {
		return err
	}
	return process.framebufferWrite(func() error {
		_, err := process.stdin.Write(data)
		return err
	}, 5*time.Second)
}

func buildFramebufferArguments(command rdpCommand) ([]string, error) {
	command.Profile.FullScreen = false
	command.Profile.UseAllMonitors = false
	args, err := buildFreeRdpArguments(command)
	if err == nil && command.Profile.ServerAuthentication != nil && *command.Profile.ServerAuthentication == 1 {
		args = append(args, "/cert:deny")
	}
	return args, err
}

// A child stuck connecting must not hold the controller's command loop forever.
// Killing it also unblocks an OS pipe write; wait for the timeout callback so a
// late timer cannot kill a successfully initialized process.
func (process *rdpProcess) framebufferWrite(write func() error, timeout time.Duration) error {
	process.stdinMu.Lock()
	defer process.stdinMu.Unlock()
	if process.stdin == nil {
		return io.ErrClosedPipe
	}
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		if process.process != nil && process.process.Process != nil {
			_ = process.process.Process.Kill()
		}
		_ = process.stdin.Close()
		close(expired)
	})
	err := write()
	if !timer.Stop() {
		<-expired
		return os.ErrDeadlineExceeded
	}
	return err
}
