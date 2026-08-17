package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	mcpDefaultCommandTimeout = 30 * time.Second
	mcpMaxCommandTimeout     = time.Hour
	mcpDefaultReadBytes      = 64 * 1024
	mcpMaxReadBytes          = 1024 * 1024
	mcpMaxCommandBytes       = 64 * 1024
	mcpMaxSendTextBytes      = 1024 * 1024
	mcpReplayCapacity        = 1024 * 1024
	mcpCommandCaptureBytes   = 1024 * 1024
	mcpMarkerTailBytes       = 512
)

var errMcpCommandInProgress = errors.New("a previous MCP command is still running")

type mcpSessionInfo struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Title    string `json:"title"`
	Status   string `json:"status"`
}

type mcpCommandResult struct {
	Output    string `json:"output"`
	ExitCode  *int   `json:"exitCode"`
	TimedOut  bool   `json:"timedOut"`
	Truncated bool   `json:"truncated"`
}

// mcpReplayBuffer keeps a bounded terminal byte stream. SSH sessions keep one filtered buffer for
// read_terminal and one raw buffer so run_command can detect sentinel markers without showing them
// to the user. The monotonically increasing position lets command capture consume output without
// retaining an unbounded transcript.
type mcpReplayBuffer struct {
	mu       sync.Mutex
	bytes    []byte
	total    uint64
	capacity int
	notify   chan struct{}
}

func newMcpReplayBuffer(capacity int) *mcpReplayBuffer {
	if capacity <= 0 {
		capacity = mcpReplayCapacity
	}
	return &mcpReplayBuffer{
		bytes:    make([]byte, 0, capacity),
		capacity: capacity,
		notify:   make(chan struct{}),
	}
}

func (buffer *mcpReplayBuffer) append(data []byte) {
	if buffer == nil || len(data) == 0 {
		return
	}

	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.bytes = append(buffer.bytes, data...)
	if len(buffer.bytes) > buffer.capacity {
		buffer.bytes = append([]byte(nil), buffer.bytes[len(buffer.bytes)-buffer.capacity:]...)
	}
	buffer.total += uint64(len(data))
	close(buffer.notify)
	buffer.notify = make(chan struct{})
}

func (buffer *mcpReplayBuffer) position() uint64 {
	if buffer == nil {
		return 0
	}
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.total
}

func (buffer *mcpReplayBuffer) since(position uint64) ([]byte, uint64, <-chan struct{}, bool) {
	if buffer == nil {
		return nil, position, nil, false
	}
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	start := buffer.total - uint64(len(buffer.bytes))
	dropped := position < start
	if position < start {
		position = start
	}
	index := int(position - start)
	result := append([]byte(nil), buffer.bytes[index:]...)
	return result, buffer.total, buffer.notify, dropped
}

func (buffer *mcpReplayBuffer) snapshotTail(maxBytes int) []byte {
	if buffer == nil || maxBytes <= 0 {
		return nil
	}
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if maxBytes > len(buffer.bytes) {
		maxBytes = len(buffer.bytes)
	}
	result := append([]byte(nil), buffer.bytes[len(buffer.bytes)-maxBytes:]...)
	for len(result) > 0 && result[0]&0xc0 == 0x80 {
		result = result[1:]
	}
	return result
}

type mcpCommandCapture struct {
	start     []byte
	endPrefix []byte
	captured  []byte
	tail      []byte
	exitCode  *int
	completed bool
	truncated bool
}

type mcpPresentationState uint8

const (
	mcpPresentationMatchingEcho mcpPresentationState = iota
	mcpPresentationMatchingEchoLineEnding
	mcpPresentationAwaitStartMarker
	mcpPresentationSwallowStartLineEnding
	mcpPresentationSwallowOptionalLFThenPassing
	mcpPresentationPassing
	mcpPresentationSwallowEndLineEnding
	mcpPresentationSwallowOptionalLFThenPassThrough
	mcpPresentationPassThrough
)

const (
	mcpMaxEndMarkerDigits      = 10
	mcpMaxRetiredPresentations = 8
)

type mcpCommandPresentationFilter struct {
	inputPayload         []byte
	expectedEcho         []byte
	expectedEchoFallback []int
	presentation         []byte
	startMarker          []byte
	startMarkerFallback  []int
	endMarkerPrefix      []byte
	pending              []byte
	suppressedEcho       []byte
	scanPosition         int
	echoMatched          int
	startMarkerMatched   int
	readlineRedrawStart  int
	retiredPending       int
	state                mcpPresentationState
	abandoned            bool
	wrapperWritten       bool
	interruptWritten     bool
	retired              bool
	complete             bool
}

type mcpEndMarkerSearch struct {
	found        bool
	start        int
	endExclusive int
	waitStart    int
}

func newMcpCommandPresentationFilter(
	command string,
	payload []byte,
	startMarker []byte,
	endMarkerPrefix []byte,
) *mcpCommandPresentationFilter {
	echo := payload
	if len(echo) > 0 && echo[len(echo)-1] == '\r' {
		echo = echo[:len(echo)-1]
	}
	return &mcpCommandPresentationFilter{
		inputPayload:         append([]byte(nil), payload...),
		expectedEcho:         append([]byte(nil), echo...),
		expectedEchoFallback: buildPrefixFallback(echo),
		presentation:         []byte(command + "\r\n"),
		startMarker:          append([]byte(nil), startMarker...),
		startMarkerFallback:  buildPrefixFallback(startMarker),
		endMarkerPrefix:      append([]byte(nil), endMarkerPrefix...),
		readlineRedrawStart:  -1,
		state:                mcpPresentationMatchingEcho,
	}
}

func (filter *mcpCommandPresentationFilter) filter(data []byte) []byte {
	if filter == nil || len(data) == 0 {
		return nil
	}
	if filter.state == mcpPresentationPassThrough {
		return append([]byte(nil), data...)
	}

	filter.pending = append(filter.pending, data...)
	output := make([]byte, 0, len(data))
	for {
		switch filter.state {
		case mcpPresentationMatchingEcho:
			if !filter.findEchoOrStartMarker(&output) {
				return output
			}
		case mcpPresentationMatchingEchoLineEnding:
			if !filter.matchEchoLineEndingOrFailOpen(&output) {
				return output
			}
		case mcpPresentationAwaitStartMarker:
			if !filter.matchStartMarkerOrFailOpen(&output) {
				return output
			}
		case mcpPresentationSwallowStartLineEnding:
			if !filter.consumeLineEndingOrWait(
				mcpPresentationPassing,
				mcpPresentationSwallowOptionalLFThenPassing,
			) {
				return output
			}
		case mcpPresentationSwallowOptionalLFThenPassing:
			if !filter.consumeOptionalLFOrWait(mcpPresentationPassing) {
				return output
			}
		case mcpPresentationPassing:
			if !filter.passUntilEndMarker(&output) {
				return output
			}
		case mcpPresentationSwallowEndLineEnding:
			if !filter.consumeLineEndingOrWait(
				mcpPresentationPassThrough,
				mcpPresentationSwallowOptionalLFThenPassThrough,
			) {
				return output
			}
			filter.complete = true
		case mcpPresentationSwallowOptionalLFThenPassThrough:
			if !filter.consumeOptionalLFOrWait(mcpPresentationPassThrough) {
				return output
			}
			filter.complete = true
		case mcpPresentationPassThrough:
			filter.complete = true
			filter.drainTo(&output, len(filter.pending))
			return output
		}
	}
}

func (filter *mcpCommandPresentationFilter) findEchoOrStartMarker(output *[]byte) bool {
	// A prompt emitted just before the MCP write can be read after this filter is installed.
	// Stream both possible prefixes so a fragmented maximum-size echo remains linear.
	for filter.scanPosition < len(filter.pending) {
		value := filter.pending[filter.scanPosition]
		filter.echoMatched = advancePrefixMatch(
			filter.echoMatched,
			value,
			filter.expectedEcho,
			filter.expectedEchoFallback,
		)
		filter.startMarkerMatched = advancePrefixMatch(
			filter.startMarkerMatched,
			value,
			filter.startMarker,
			filter.startMarkerFallback,
		)
		filter.scanPosition++
		if filter.scanPosition >= 2 &&
			filter.pending[filter.scanPosition-2] == '\r' &&
			filter.pending[filter.scanPosition-1] == '<' {
			filter.readlineRedrawStart = filter.scanPosition - 2
		}

		echoComplete := filter.echoMatched == len(filter.expectedEcho)
		markerComplete := filter.startMarkerMatched == len(filter.startMarker)
		if !echoComplete && !markerComplete {
			continue
		}
		echoStart := filter.scanPosition - filter.echoMatched
		markerStart := filter.scanPosition - filter.startMarkerMatched
		if markerComplete && (!echoComplete || markerStart < echoStart) {
			filter.drainBeforeWrapperMatch(output, markerStart)
			filter.consumePending(len(filter.startMarker))
			*output = append(*output, filter.presentation...)
			filter.state = mcpPresentationSwallowStartLineEnding
			return true
		}
		filter.drainBeforeWrapperMatch(output, echoStart)
		filter.state = mcpPresentationMatchingEchoLineEnding
		return true
	}

	if filter.readlineRedrawStart >= 0 &&
		len(filter.pending)-filter.readlineRedrawStart > len(filter.expectedEcho)+len(filter.startMarker)+3 {
		filter.readlineRedrawStart = -1
	}
	keep := maxInt(filter.echoMatched, filter.startMarkerMatched)
	if filter.readlineRedrawStart >= 0 {
		keep = len(filter.pending) - filter.readlineRedrawStart
	} else if len(filter.pending) > 0 && filter.pending[len(filter.pending)-1] == '\r' {
		keep = maxInt(keep, 1)
	}
	filter.drainTo(output, len(filter.pending)-keep)
	if filter.readlineRedrawStart >= 0 {
		filter.readlineRedrawStart = 0
	}
	filter.scanPosition = len(filter.pending)
	return false
}

func (filter *mcpCommandPresentationFilter) drainBeforeWrapperMatch(output *[]byte, matchStart int) {
	redrawContentStart := filter.readlineRedrawStart + 2
	redrawContentEnd := matchStart
	if redrawContentEnd > redrawContentStart && filter.pending[redrawContentEnd-1] == '\n' {
		redrawContentEnd--
		if redrawContentEnd > redrawContentStart && filter.pending[redrawContentEnd-1] == '\r' {
			redrawContentEnd--
		}
	} else if redrawContentEnd > redrawContentStart && filter.pending[redrawContentEnd-1] == '\r' {
		redrawContentEnd--
	}
	confirmedRedraw := filter.readlineRedrawStart >= 0 &&
		redrawContentStart < redrawContentEnd &&
		bytes.HasSuffix(filter.expectedEcho, filter.pending[redrawContentStart:redrawContentEnd])
	if !confirmedRedraw {
		filter.drainTo(output, matchStart)
		return
	}
	redrawBytes := matchStart - filter.readlineRedrawStart
	filter.drainTo(output, filter.readlineRedrawStart)
	filter.consumePending(redrawBytes)
	filter.readlineRedrawStart = -1
}

func (filter *mcpCommandPresentationFilter) matchEchoLineEndingOrFailOpen(output *[]byte) bool {
	lineEndingStart := len(filter.expectedEcho)
	if len(filter.pending) <= lineEndingStart {
		return false
	}

	first := filter.pending[lineEndingStart]
	if first == '\n' {
		filter.confirmEcho(lineEndingStart + 1)
		return true
	}
	if first != '\r' {
		filter.failOpen(output)
		return true
	}
	if len(filter.pending) == lineEndingStart+1 {
		return false
	}
	echoLength := lineEndingStart + 1
	if filter.pending[lineEndingStart+1] == '\n' {
		echoLength++
	}
	filter.confirmEcho(echoLength)
	return true
}

func (filter *mcpCommandPresentationFilter) confirmEcho(echoLength int) {
	filter.suppressedEcho = append([]byte(nil), filter.pending[:echoLength]...)
	filter.consumePending(echoLength)
	filter.state = mcpPresentationAwaitStartMarker
}

func (filter *mcpCommandPresentationFilter) matchStartMarkerOrFailOpen(output *[]byte) bool {
	if len(filter.pending) == 0 {
		return false
	}
	comparable := minInt(len(filter.pending), len(filter.startMarker))
	for index := 0; index < comparable; index++ {
		if filter.pending[index] == filter.startMarker[index] {
			continue
		}
		filter.failOpen(output)
		return true
	}
	if len(filter.pending) < len(filter.startMarker) {
		return false
	}
	filter.consumePending(len(filter.startMarker))
	filter.suppressedEcho = nil
	*output = append(*output, filter.presentation...)
	filter.state = mcpPresentationSwallowStartLineEnding
	return true
}

func (filter *mcpCommandPresentationFilter) failOpen(output *[]byte) {
	if filter.retired && filter.state == mcpPresentationMatchingEchoLineEnding {
		filter.consumePending(len(filter.expectedEcho))
	} else if len(filter.suppressedEcho) > 0 && !filter.retired {
		*output = append(*output, filter.suppressedEcho...)
	}
	filter.suppressedEcho = nil
	filter.drainTo(output, len(filter.pending))
	filter.state = mcpPresentationPassThrough
	filter.complete = true
}

func (filter *mcpCommandPresentationFilter) passUntilEndMarker(output *[]byte) bool {
	search := filter.findEndMarker()
	if search.found {
		filter.drainTo(output, search.start)
		filter.consumePending(search.endExclusive - search.start)
		filter.state = mcpPresentationSwallowEndLineEnding
		return true
	}
	if search.waitStart >= 0 {
		filter.drainTo(output, search.waitStart)
		return false
	}
	keep := filter.longestPrefixSuffixLength()
	filter.drainTo(output, maxInt(0, len(filter.pending)-keep))
	return false
}

func (filter *mcpCommandPresentationFilter) findEndMarker() mcpEndMarkerSearch {
	for index := 0; index < len(filter.pending); index++ {
		prefixMatch := filter.prefixMatchLengthAt(index)
		if prefixMatch == 0 {
			continue
		}
		if prefixMatch < len(filter.endMarkerPrefix) {
			if index+prefixMatch == len(filter.pending) {
				return mcpEndMarkerSearch{waitStart: index}
			}
			continue
		}

		position := index + len(filter.endMarkerPrefix)
		digitStart := position
		for position < len(filter.pending) &&
			position-digitStart <= mcpMaxEndMarkerDigits &&
			filter.pending[position] >= '0' &&
			filter.pending[position] <= '9' {
			position++
		}

		digitCount := position - digitStart
		if digitCount > mcpMaxEndMarkerDigits {
			continue
		}
		if digitCount == 0 {
			if position == len(filter.pending) {
				return mcpEndMarkerSearch{waitStart: index}
			}
			continue
		}
		if position >= len(filter.pending) {
			return mcpEndMarkerSearch{waitStart: index}
		}
		if filter.pending[position] != '@' {
			continue
		}
		if position+1 >= len(filter.pending) {
			return mcpEndMarkerSearch{waitStart: index}
		}
		if filter.pending[position+1] != '@' {
			continue
		}
		return mcpEndMarkerSearch{found: true, start: index, endExclusive: position + 2}
	}
	return mcpEndMarkerSearch{waitStart: -1}
}

func (filter *mcpCommandPresentationFilter) consumeLineEndingOrWait(
	nextState mcpPresentationState,
	afterCRState mcpPresentationState,
) bool {
	if len(filter.pending) == 0 {
		return false
	}
	if filter.pending[0] == '\r' {
		filter.consumePending(1)
		if len(filter.pending) == 0 {
			filter.state = afterCRState
			return false
		}
		if filter.pending[0] == '\n' {
			filter.consumePending(1)
		}
		filter.state = nextState
		return true
	}
	if filter.pending[0] == '\n' {
		filter.consumePending(1)
	}
	filter.state = nextState
	return true
}

func (filter *mcpCommandPresentationFilter) consumeOptionalLFOrWait(nextState mcpPresentationState) bool {
	if len(filter.pending) == 0 {
		return false
	}
	if filter.pending[0] == '\n' {
		filter.consumePending(1)
	}
	filter.state = nextState
	return true
}

func (filter *mcpCommandPresentationFilter) prefixMatchLengthAt(index int) int {
	matched := 0
	for matched < len(filter.endMarkerPrefix) &&
		index+matched < len(filter.pending) &&
		filter.pending[index+matched] == filter.endMarkerPrefix[matched] {
		matched++
	}
	return matched
}

func (filter *mcpCommandPresentationFilter) longestPrefixSuffixLength() int {
	return longestPrefixSuffixLength(filter.pending, filter.endMarkerPrefix)
}

func longestPrefixSuffixLength(data, prefix []byte) int {
	maxLength := minInt(len(data), len(prefix)-1)
	for length := maxLength; length > 0; length-- {
		if bytes.Equal(data[len(data)-length:], prefix[:length]) {
			return length
		}
	}
	return 0
}

func buildPrefixFallback(prefix []byte) []int {
	if len(prefix) <= 1 {
		return nil
	}
	fallback := make([]int, len(prefix))
	for index, matched := 1, 0; index < len(prefix); index++ {
		for matched > 0 && prefix[index] != prefix[matched] {
			matched = fallback[matched-1]
		}
		if prefix[index] == prefix[matched] {
			matched++
		}
		fallback[index] = matched
	}
	return fallback
}

func advancePrefixMatch(matched int, value byte, prefix []byte, fallback []int) int {
	if len(prefix) == 0 {
		return 0
	}
	for matched > 0 && value != prefix[matched] {
		matched = fallback[matched-1]
	}
	if value == prefix[matched] {
		matched++
	}
	return matched
}

func (filter *mcpCommandPresentationFilter) drainTo(output *[]byte, count int) {
	if count <= 0 {
		return
	}
	discard := minInt(count, filter.retiredPending)
	filter.consumePending(discard)
	count -= discard
	if count <= 0 {
		return
	}
	*output = append(*output, filter.pending[:count]...)
	filter.consumePending(count)
}

func (filter *mcpCommandPresentationFilter) consumePending(count int) {
	if count <= 0 {
		return
	}
	filter.retiredPending = maxInt(0, filter.retiredPending-count)
	filter.pending = filter.pending[count:]
}

func newMcpCommandCapture(command string) (mcpCommandCapture, []byte, error) {
	if len(command) == 0 || len(command) > mcpMaxCommandBytes {
		return mcpCommandCapture{}, nil, errors.New("MCP command is empty or too large")
	}
	for _, value := range []byte(command) {
		if value < 0x20 || value == 0x7f {
			return mcpCommandCapture{}, nil, errors.New("MCP command contains control characters")
		}
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return mcpCommandCapture{}, nil, errors.New("could not create the MCP command marker")
	}
	token := hex.EncodeToString(random[:])
	start := []byte("@@WHS_" + token + "@@")
	endPrefix := []byte("@@WHE_" + token + "_")
	escaped := strings.ReplaceAll(command, "'", "'\\''")
	payload := fmt.Sprintf(
		"printf '@@WHS_%%s@@\\n' %s; eval '%s'; __wh_rc=$?; printf '@@WHE_%%s_%%s@@\\n' %s \"$__wh_rc\"\r",
		token,
		escaped,
		token,
	)
	return mcpCommandCapture{
		start:     start,
		endPrefix: endPrefix,
		captured:  make([]byte, 0, minInt(mcpCommandCaptureBytes, len(command)*2+128)),
	}, []byte(payload), nil
}

func (capture *mcpCommandCapture) push(data []byte) {
	if capture.completed || len(data) == 0 {
		return
	}
	capture.tail = append(capture.tail, data...)
	if exitCode, ok := parseMcpEndMarker(capture.tail, capture.endPrefix); ok {
		capture.exitCode = exitCode
		capture.completed = true
	}
	if len(capture.tail) > mcpMarkerTailBytes {
		capture.tail = append([]byte(nil), capture.tail[len(capture.tail)-mcpMarkerTailBytes:]...)
	}

	room := mcpCommandCaptureBytes - len(capture.captured)
	if room <= 0 {
		capture.truncated = true
		return
	}
	take := len(data)
	if take > room {
		take = room
		capture.truncated = true
	}
	capture.captured = append(capture.captured, data[:take]...)
}

func (capture *mcpCommandCapture) finish(timedOut bool) mcpCommandResult {
	start := bytes.Index(capture.captured, capture.start)
	if start < 0 {
		return mcpCommandResult{
			ExitCode:  capture.exitCode,
			TimedOut:  timedOut,
			Truncated: capture.truncated,
		}
	}
	body := capture.captured[start+len(capture.start):]
	if index := bytes.Index(body, capture.endPrefix); index >= 0 {
		body = body[:index]
	}
	return mcpCommandResult{
		Output:    strings.Trim(string(stripMcpAnsi(body)), "\n"),
		ExitCode:  capture.exitCode,
		TimedOut:  timedOut,
		Truncated: capture.truncated,
	}
}

func parseMcpEndMarker(data, prefix []byte) (*int, bool) {
	index := bytes.Index(data, prefix)
	if index < 0 {
		return nil, false
	}
	suffix := data[index+len(prefix):]
	end := bytes.Index(suffix, []byte("@@"))
	if end < 1 {
		return nil, false
	}
	digits := suffix[:end]
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return nil, false
		}
	}
	var value int
	for _, digit := range digits {
		value = value*10 + int(digit-'0')
		if value > 255 {
			return nil, false
		}
	}
	return &value, true
}

func (native *sshNativeSession) runMcpCommand(
	ctx context.Context,
	command string,
	timeout time.Duration,
) (mcpCommandResult, error) {
	if native == nil || native.mcpReplay == nil || native.mcpCommandReplay == nil {
		return mcpCommandResult{}, errSSHSessionClosed
	}
	if timeout <= 0 {
		timeout = mcpDefaultCommandTimeout
	}
	if timeout > mcpMaxCommandTimeout {
		return mcpCommandResult{}, errors.New("MCP command timeout is too large")
	}

	if err := native.acquireMcpCommand(ctx); err != nil {
		return mcpCommandResult{}, err
	}
	defer native.releaseMcpCommand()
	if err := ctx.Err(); err != nil {
		return mcpCommandResult{}, err
	}

	capture, payload, err := newMcpCommandCapture(command)
	if err != nil {
		return mcpCommandResult{}, err
	}
	position := native.mcpCommandReplay.position()
	if err := native.beginMcpCommandPresentation(command, payload, capture.start, capture.endPrefix); err != nil {
		return mcpCommandResult{}, err
	}
	clearPresentation := true
	defer func() {
		if clearPresentation {
			native.clearMcpCommandPresentation()
		}
	}()
	if err := ctx.Err(); err != nil {
		return mcpCommandResult{}, err
	}
	if err := native.write(payload); err != nil {
		return mcpCommandResult{}, err
	}

	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		data, next, notify, dropped := native.mcpCommandReplay.since(position)
		if dropped {
			capture.truncated = true
		}
		capture.push(data)
		position = next
		if capture.completed {
			native.retireMcpCommandPresentation()
			clearPresentation = false
			return capture.finish(false), nil
		}

		select {
		case <-commandContext.Done():
			native.abandonMcpCommandPresentation()
			clearPresentation = false
			if errors.Is(ctx.Err(), context.Canceled) {
				return mcpCommandResult{}, ctx.Err()
			}
			return capture.finish(true), nil
		case <-native.done:
			return mcpCommandResult{}, errSSHSessionClosed
		case <-notify:
		}
	}
}

func (native *sshNativeSession) acquireMcpCommand(ctx context.Context) error {
	native.mcpCommandGateMu.Lock()
	if native.mcpCommandGate == nil {
		native.mcpCommandGate = make(chan struct{}, 1)
	}
	gate := native.mcpCommandGate
	native.mcpCommandGateMu.Unlock()

	select {
	case gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-native.done:
		return errSSHSessionClosed
	}
}

func (native *sshNativeSession) releaseMcpCommand() {
	native.mcpCommandGateMu.Lock()
	gate := native.mcpCommandGate
	native.mcpCommandGateMu.Unlock()
	if gate != nil {
		<-gate
	}
}

func stripMcpAnsi(input []byte) []byte {
	type state uint8
	const (
		normal state = iota
		escape
		csi
		osc
		oscEscape
	)

	output := make([]byte, 0, len(input))
	current := normal
	for index := 0; index < len(input); index++ {
		value := input[index]
		switch current {
		case normal:
			switch value {
			case 0x1b:
				current = escape
			case '\r':
				if index+1 < len(input) && input[index+1] == '\n' {
					output = append(output, '\n')
					index++
				}
			default:
				output = append(output, value)
			}
		case escape:
			switch value {
			case '[':
				current = csi
			case ']':
				current = osc
			default:
				current = normal
			}
		case csi:
			if value >= 0x40 && value <= 0x7e {
				current = normal
			}
		case osc:
			switch value {
			case 0x07:
				current = normal
			case 0x1b:
				current = oscEscape
			}
		case oscEscape:
			switch value {
			case '\\':
				current = normal
			case 0x1b:
			default:
				current = osc
			}
		}
	}
	return output
}
