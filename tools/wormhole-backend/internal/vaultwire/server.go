// Package vaultwire implements the bounded, stdio-only vault transport. It has
// no network listener and never exposes raw handler errors on the wire.
package vaultwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	Version                 = 1
	MaxFrameBytes           = 8 * 1024 * 1024
	MaxRequestID            = 1<<53 - 1 // exactly representable by Electron's JSON number
	DefaultHeartbeatTimeout = 30 * time.Second
	ShutdownTimeout         = time.Second
)

var (
	ErrProtocol                 = errors.New("vault_invalid_request")
	ErrHeartbeat                = errors.New("vault_heartbeat_expired")
	ErrOutput                   = errors.New("vault_output_closed")
	ErrShutdown                 = errors.New("vault_shutdown_timeout")
	ErrCleanup                  = errors.New("vault_cleanup_failed")
	ErrRetired                  = errors.New("vault_session_retired")
	ErrWorkspaceConnectionLimit = errors.New("vault_workspace_connection_limit")
)

type Request struct {
	Version   uint16          `json:"version"`
	ID        uint64          `json:"id"`
	Operation string          `json:"operation"`
	TargetID  uint64          `json:"targetId,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	Version uint16          `json:"version"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Event   string          `json:"event,omitempty"`
}

// Handler owns all application authorization. Operations are serialized; it
// must observe ctx before committing mutations. Close must invalidate keys and
// close its database. Only ciphertext and explicitly allowed metadata may be
// returned; errors are deliberately reduced to a fixed code by the transport.
// Payload is borrowed until Handle returns. A returned result transfers ownership
// to Serve, may alias payload, and must not subsequently be retained or mutated.
// Close runs only after Handle returns. Failure to stop/close within the shutdown
// deadline requires the owning executable to exit; Serve is not restartable.
type Handler interface {
	Handle(ctx context.Context, operation string, payload json.RawMessage) (json.RawMessage, error)
	Close() error
}

// Authentication may install keys before its result is consumed. These handlers
// require process exit when that request is cancelled, including queued results.
type CancelExitPolicy interface {
	ExitOnCancel(operation string) bool
}

// SharedCatalogEventSource supplies coalesced, payload-free invalidations. The
// source is configured before Serve; it must never block an application worker.
type SharedCatalogEventSource interface {
	SharedCatalogEvents() <-chan struct{}
}

type inbound struct {
	request Request
	err     error
}
type completed struct {
	id     uint64
	result json.RawMessage
	err    error
}

func decodeRequest(frame []byte) (Request, error) {
	if len(frame) > MaxFrameBytes || !utf8.Valid(frame) {
		return Request{}, ErrProtocol
	}
	// encoding/json otherwise accepts duplicate and case-insensitive field names.
	// Decode exact names once so alternate parsers cannot disagree on IDs.
	var request Request
	accepted := false
	defer func() {
		if !accepted {
			clear(request.Payload)
		}
	}()
	fields := json.NewDecoder(bytes.NewReader(frame))
	if token, err := fields.Token(); err != nil || token != json.Delim('{') {
		return Request{}, ErrProtocol
	}
	seen := make(map[string]bool, 5)
	for fields.More() {
		token, err := fields.Token()
		if err != nil {
			return Request{}, ErrProtocol
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return Request{}, ErrProtocol
		}
		var target any
		switch name {
		case "version":
			target = &request.Version
		case "id":
			target = &request.ID
		case "operation":
			target = &request.Operation
		case "targetId":
			target = &request.TargetID
		case "payload":
			target = &request.Payload
		default:
			return Request{}, ErrProtocol
		}
		seen[name] = true
		if fields.Decode(target) != nil {
			return Request{}, ErrProtocol
		}
	}
	if token, err := fields.Token(); err != nil || token != json.Delim('}') || fields.Decode(new(any)) != io.EOF {
		return Request{}, ErrProtocol
	}
	if request.Version != Version || request.ID == 0 || request.ID > MaxRequestID || len(request.Operation) == 0 || len(request.Operation) > 64 {
		return Request{}, ErrProtocol
	}
	for _, c := range request.Operation {
		if !(c >= 'a' && c <= 'z') && c != '-' {
			return Request{}, ErrProtocol
		}
	}
	if request.Operation == "cancel" {
		if request.TargetID == 0 || request.TargetID >= request.ID || len(request.Payload) != 0 {
			return Request{}, ErrProtocol
		}
	} else if request.TargetID != 0 {
		return Request{}, ErrProtocol
	}
	if (request.Operation == "heartbeat" || request.Operation == "lock") && len(request.Payload) != 0 {
		return Request{}, ErrProtocol
	}
	accepted = true
	return request, nil
}

func splitFrame(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		frame := data[:i]
		if len(frame) > 0 && frame[len(frame)-1] == '\r' {
			frame = frame[:len(frame)-1]
		}
		return i + 1, frame, nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, ErrProtocol
	}
	return 0, nil, nil
}

// Enforce the bound after JSON escaping and envelope overhead, not just on the
// handler's RawMessage. A malformed response never escapes via an encoder error.
func encodeResponse(response Response) []byte {
	frame, err := json.Marshal(response)
	if err != nil || len(frame) > MaxFrameBytes {
		clear(frame)
		frame, _ = json.Marshal(Response{Version: Version, ID: response.ID, Error: "vault_invalid_response"})
	}
	return append(frame, '\n')
}

func (result completed) response(cancelled bool) Response {
	response := Response{Version: Version, ID: result.id, Result: result.result}
	switch {
	case cancelled || errors.Is(result.err, context.Canceled):
		response.Error = "vault_cancelled"
	case errors.Is(result.err, ErrWorkspaceConnectionLimit):
		response.Error = ErrWorkspaceConnectionLimit.Error()
	case result.err != nil:
		response.Error = "vault_operation_failed"
	case len(result.result) > MaxFrameBytes-1024 || !json.Valid(result.result):
		response.Error = "vault_invalid_response"
	}
	if response.Error != "" {
		clear(result.result)
		response.Result = nil
	}
	return response
}

// Serve owns both pipes and handler until it returns. IDs strictly increase for
// the process lifetime, so duplicates/replays need no unbounded ID cache.
// EOF, a malformed frame, output failure or heartbeat expiry cancels in-flight
// work and closes the handler. The executable must exit after Serve returns.
func Serve(ctx context.Context, input io.ReadCloser, output io.WriteCloser, handler Handler, heartbeatTimeout time.Duration) (serveErr error) {
	ctx, stop := context.WithCancel(ctx)
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = DefaultHeartbeatTimeout
	}
	in := make(chan inbound, 1)
	out := make(chan Response, 8)
	writeFailure := make(chan struct{}, 1)
	done := make(chan completed, 1)
	var workers sync.WaitGroup
	defer func() {
		stop()
		pipeFailures := make(chan bool, 2)
		// Close must unblock pending I/O, but an adapter may itself stall. Include
		// both closures in the same deadline as handler and worker teardown.
		workers.Go(func() { pipeFailures <- input.Close() != nil })
		workers.Go(func() { pipeFailures <- output.Close() != nil })
		shutdown := make(chan error, 1)
		go func() {
			workers.Wait()
			// All producers have stopped; wipe anything shutdown did not consume.
			for len(in) > 0 {
				message := <-in
				clear(message.request.Payload)
			}
			for len(out) > 0 {
				response := <-out
				clear(response.Result)
			}
			for len(done) > 0 {
				result := <-done
				clear(result.result)
			}
			inputFailed, outputFailed := <-pipeFailures, <-pipeFailures
			if err := handler.Close(); err != nil || inputFailed || outputFailed {
				shutdown <- ErrCleanup
			} else {
				shutdown <- nil
			}
		}()
		timer := time.NewTimer(ShutdownTimeout)
		defer timer.Stop()
		select {
		case err := <-shutdown:
			if err != nil {
				serveErr = errors.Join(serveErr, ErrCleanup)
			}
		case <-timer.C:
			serveErr = errors.Join(serveErr, ErrShutdown)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	workers.Go(func() {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), MaxFrameBytes+2)
		scanner.Split(splitFrame)
		for scanner.Scan() {
			request, err := decodeRequest(scanner.Bytes())
			clear(scanner.Bytes())
			select {
			case in <- inbound{request, err}:
			case <-ctx.Done():
				clear(request.Payload)
				return
			}
			// Lock is terminal. Do not start another native read while the
			// main loop retires this owner and closes its pipes.
			if err != nil || request.Operation == "lock" {
				return
			}
		}
		err := scanner.Err()
		if err == nil {
			err = io.EOF
		} else {
			err = ErrProtocol
		}
		select {
		case in <- inbound{err: err}:
		case <-ctx.Done():
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case response := <-out:
				frame := encodeResponse(response)
				n, err := output.Write(frame)
				shortWrite := n != len(frame)
				clear(frame)
				clear(response.Result)
				if err != nil || shortWrite {
					select {
					case writeFailure <- struct{}{}:
					default:
					}
					return
				}
			}
		}
	})

	timer := time.NewTimer(heartbeatTimeout)
	defer timer.Stop()
	var lastID, activeID uint64
	var activeCancelled bool
	var activeExitOnCancel bool
	var cancel context.CancelFunc
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()
	send := func(response Response) error {
		select {
		case out <- response:
			return nil
		default:
			clear(response.Result)
			return ErrOutput
		}
	}
	var changes <-chan struct{}
	if source, ok := handler.(SharedCatalogEventSource); ok {
		changes = source.SharedCatalogEvents()
	}
	for {
		select {
		case _, ok := <-changes:
			if !ok {
				changes = nil
				continue
			}
			if err := send(Response{Version: Version, Event: "shared-catalog-changed"}); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-writeFailure:
			return ErrOutput
		case <-timer.C:
			return ErrHeartbeat
		case message := <-in:
			if message.err != nil {
				if errors.Is(message.err, io.EOF) {
					return nil
				}
				return message.err
			}
			r := message.request
			if r.ID <= lastID {
				clear(r.Payload)
				return ErrProtocol
			}
			lastID = r.ID
			response := Response{Version: Version, ID: r.ID}
			switch r.Operation {
			case "heartbeat":
				timer.Reset(heartbeatTimeout)
				response.Result = json.RawMessage(`{"alive":true}`)
			case "lock":
				return nil
			case "cancel":
				if activeID == r.TargetID && cancel != nil {
					if activeExitOnCancel {
						return nil
					}
					activeCancelled = true
					cancel()
					response.Result = json.RawMessage(`{"cancelled":true}`)
				} else {
					response.Result = json.RawMessage(`{"cancelled":false}`)
				}
			default:
				if activeID != 0 {
					clear(r.Payload)
					response.Error = "vault_busy"
				} else {
					requestContext, requestCancel := context.WithCancel(ctx)
					cancel = requestCancel
					activeID = r.ID
					activeCancelled = false
					activeExitOnCancel = false
					if policy, ok := handler.(CancelExitPolicy); ok {
						activeExitOnCancel = policy.ExitOnCancel(r.Operation)
					}
					workers.Go(func() {
						defer requestCancel()
						result, err := handler.Handle(requestContext, r.Operation, r.Payload)
						// A handler may return the borrowed input (or part of it).
						// Keep the response independent before retiring the request.
						if len(r.Payload) > 0 {
							owned := bytes.Clone(result)
							clear(result)
							result = owned
						}
						clear(r.Payload)
						if requestContext.Err() != nil {
							clear(result)
							result = nil
							if !errors.Is(err, ErrRetired) {
								err = context.Canceled
							}
						}
						select {
						case done <- completed{r.ID, result, err}:
						case <-ctx.Done():
							clear(result)
						}
					})
					continue
				}
			}
			if err := send(response); err != nil {
				return err
			}
		case result := <-done:
			if errors.Is(result.err, ErrRetired) {
				clear(result.result)
				return ErrRetired
			}
			cancel()
			cancel = nil
			activeID = 0
			response := result.response(activeCancelled)
			if err := send(response); err != nil {
				return err
			}
		}
	}
}
