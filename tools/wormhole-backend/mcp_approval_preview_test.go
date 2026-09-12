package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMcpExecutionPreviewPreservesTextAndEscapesControls(t *testing.T) {
	input := "printf 'ciao 世界'\r\n\x03<script>alert(1)</script>"
	preview := newMcpExecutionPreview(mcpExecutionArguments{SessionID: "session", Text: &input})
	var decoded mcpExecutionArguments
	if err := json.Unmarshal([]byte(preview.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Text == nil || *decoded.Text != input || decoded.SessionID != "session" || preview.Truncated || preview.Redacted {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	if strings.ContainsAny(preview.Content, "\r\x03<") || !strings.Contains(preview.Content, `\r\n\u0003`) {
		t.Fatalf("control characters or HTML were not escaped: %q", preview.Content)
	}
	empty := ""
	if preview := newMcpExecutionPreview(mcpExecutionArguments{Text: &empty}); !strings.Contains(preview.Content, `"text": ""`) {
		t.Fatal("empty text must remain visible")
	}
}

func TestMcpExecutionPreviewRedactsBeforeRendererDelivery(t *testing.T) {
	for _, input := range []string{
		`curl --password "sample-sensitive-value" https://example.test`,
		`API_KEY='sample-sensitive-value' curl https://example.test`,
		`curl 'https://example.test/?access_token=sample-sensitive-value&query=hello'`,
		`curl -H 'Authorization: Bearer sample-sensitive-value' https://example.test`,
		`curl -H 'Cookie: auth=sample-sensitive-value' https://example.test`,
		`curl https://user:sample-sensitive-value@example.test`,
		`echo Bearer sample-sensitive-value`,
		"cat <<'EOF'\n-----BEGIN OPENSSH PRIVATE KEY-----\nsample-sensitive-value\n-----END OPENSSH PRIVATE KEY-----\nEOF",
		"-----BEGIN PRIVATE KEY-----\nsample-sensitive-value",
	} {
		original := input
		for _, arguments := range []mcpExecutionArguments{{Command: &input}, {Text: &input}} {
			preview := newMcpExecutionPreview(arguments)
			if !preview.Redacted || strings.Contains(preview.Content, "sample-sensitive-value") {
				t.Fatalf("sensitive value reached the preview for %q", original)
			}
			if input != original {
				t.Fatal("preview sanitization changed execution input")
			}
		}
	}
}

func TestMcpExecutionPreviewRedactsShellCredentialForms(t *testing.T) {
	for name, input := range map[string]string{
		"user flag":              `curl --user 'alice:sample-sensitive-value' https://example.test; printf done`,
		"short user flag":        `curl -u alice:sample-sensitive-value https://example.test; printf done`,
		"sshpass":                `sshpass -p sample-sensitive-value ssh example.test; printf done`,
		"quoted cookie":          `curl -H 'Cookie: session="sample-sensitive-value"; pref=blue' https://example.test; printf done`,
		"concatenated quotes":    `TOKEN='prefix-'"sample-sensitive-value" curl https://example.test; printf done`,
		"escaped space":          `PASSWORD=prefix\ sample-sensitive-value printf done`,
		"continued quoted value": "TOKEN=\"prefix\\\nsample-sensitive-value\" curl https://example.test; printf done",
		"unfinished quote":       `TOKEN='sample-sensitive-value`,
		"json value":             `curl -d '{"password":"sample-sensitive-value","keep":"visible"}' https://example.test; printf done`,
	} {
		t.Run(name, func(t *testing.T) {
			preview := newMcpExecutionPreview(mcpExecutionArguments{Command: &input})
			if !preview.Redacted || strings.Contains(preview.Content, "sample-sensitive-value") {
				t.Fatal("recognizable credential reached the preview")
			}
			if name != "unfinished quote" && !strings.Contains(preview.Content, "printf done") {
				t.Fatal("redaction hid a separate shell operation")
			}
			if name == "json value" && !strings.Contains(preview.Content, "visible") {
				t.Fatal("redaction hid an unrelated JSON value")
			}
		})
	}
}

func TestMcpExecutionPreviewEscapesUnicodeControlsWithoutChangingInput(t *testing.T) {
	input := "printf '\u202eecho\u202c \u200b \u2066id\u2069 \u009b \U000e0001 世界'"
	preview := newMcpExecutionPreview(mcpExecutionArguments{Command: &input})
	for _, char := range preview.Content {
		if char >= 0x80 && (unicode.Is(unicode.Cf, char) || unicode.IsControl(char)) {
			t.Errorf("preview contains invisible control U+%04X", char)
		}
	}
	var decoded mcpExecutionArguments
	if err := json.Unmarshal([]byte(preview.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command == nil || *decoded.Command != input || preview.Redacted || preview.Truncated {
		t.Fatal("control escaping changed the requested command")
	}
}

func TestMcpExecutionPreviewBoundsEncodedContentWithoutSplittingUTF8(t *testing.T) {
	empty := ""
	overhead := len(newMcpExecutionPreview(mcpExecutionArguments{Text: &empty}).Content)
	exact := strings.Repeat("x", mcpMaxExecutionPreviewBytes-overhead)
	preview := newMcpExecutionPreview(mcpExecutionArguments{Text: &exact})
	if preview.Truncated || len(preview.Content) != mcpMaxExecutionPreviewBytes {
		t.Fatal("a preview at the limit was incorrectly truncated")
	}
	for _, input := range []string{exact + "x", strings.Repeat("界", mcpMaxExecutionPreviewBytes), strings.Repeat("\x03", mcpMaxExecutionPreviewBytes)} {
		preview := newMcpExecutionPreview(mcpExecutionArguments{Text: &input})
		if !preview.Truncated || len(preview.Content) > mcpMaxExecutionPreviewBytes || !utf8.ValidString(preview.Content) {
			t.Fatal("oversized preview was not safely bounded")
		}
	}
	input := `PASSWORD="` + strings.Repeat("x", mcpMaxSendTextBytes) + `"`
	preview = newMcpExecutionPreview(mcpExecutionArguments{Text: &input})
	if preview.Truncated || !preview.Redacted || strings.Contains(preview.Content, "xxxx") {
		t.Fatal("redaction must happen before truncation")
	}
}

func newMcpPreviewTestClient(t *testing.T) (*mcp.ClientSession, *mcpController, *sshNativeSession, *bytes.Buffer) {
	t.Helper()
	var output bytes.Buffer
	server := &sshServer{
		databasePath: createMcpConnectionTestDatabase(t),
		output:       &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:     make(map[string]*sshNativeSession),
	}
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id: "session", server: server, done: make(chan struct{}), terminal: terminal,
		mcpSession:       mcpSessionInfo{ID: "session", Host: "example.test", Port: 22, Username: "user", Title: "Test SSH"},
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
	}
	server.sessions[native.id] = native
	controller := newMcpController(server)
	controller.setLocked(false)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := newMcpServer(controller).Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "preview-test", Version: "1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession, controller, native, &output
}

func TestMcpToolsPreviewEffectiveArgumentsBeforeApproval(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		tool      string
		arguments map[string]any
		want      map[string]any
		approve   bool
	}{
		{"command defaults", "run_command", map[string]any{"sessionId": "session", "command": "printf hello"}, map[string]any{"sessionId": "session", "command": "printf hello", "timeoutSeconds": float64(30)}, true},
		{"command denied", "run_command", map[string]any{"sessionId": "session", "command": "printf hello", "timeoutSeconds": 9}, map[string]any{"sessionId": "session", "command": "printf hello", "timeoutSeconds": float64(9)}, false},
		{"raw text", "send_text", map[string]any{"sessionId": "session", "text": "echo hello\r\x03"}, map[string]any{"sessionId": "session", "text": "echo hello\r\x03"}, true},
		{"redacted text unchanged on execution", "send_text", map[string]any{"sessionId": "session", "text": "PASSWORD=example-value\r"}, map[string]any{"sessionId": "session", "text": "PASSWORD=[redacted]\r"}, true},
		{"text denied", "send_text", map[string]any{"sessionId": "session", "text": "echo hello\r"}, map[string]any{"sessionId": "session", "text": "echo hello\r"}, false},
		{"read defaults", "read_terminal", map[string]any{"sessionId": "session"}, map[string]any{"sessionId": "session", "maxBytes": float64(mcpDefaultReadBytes)}, true},
		{"read denied", "read_terminal", map[string]any{"sessionId": "session", "maxBytes": 512}, map[string]any{"sessionId": "session", "maxBytes": float64(512)}, false},
		{"open connection", "open_connection", map[string]any{"connectionId": "ssh-node"}, map[string]any{"connectionId": "ssh-node"}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client, controller, native, output := newMcpPreviewTestClient(t)
			writes := make(chan string, 2)
			native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
				writes <- string(data)
				if scenario.tool == "run_command" {
					token := extractMcpPayloadToken(t, string(data))
					native.publishTerminalData([]byte(strings.TrimSuffix(string(data), "\r") + "\r\n@@WHS_" + token + "@@\r\nhello\r\n@@WHE_" + token + "_0@@\r\n"))
				}
				return len(data), nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type response struct {
				result *mcp.CallToolResult
				err    error
			}
			completed := make(chan response, 1)
			go func() {
				result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: scenario.tool, Arguments: scenario.arguments})
				completed <- response{result, err}
			}()
			requestID := waitForMcpApprovalRequest(t, controller)
			if len(writes) != 0 {
				t.Fatal("tool executed before approval")
			}
			controller.server.output.mu.Lock()
			wire := append([]byte(nil), output.Bytes()...)
			controller.server.output.mu.Unlock()
			var event sshWireEvent
			if err := json.Unmarshal(bytes.TrimSpace(wire), &event); err != nil {
				t.Fatal(err)
			}
			if event.Type != "mcp.approval" || event.RequestID != requestID || event.Tool != scenario.tool || event.ExecutionPreview == nil {
				t.Fatalf("unexpected approval: %#v", event)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(event.ExecutionPreview.Content), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, scenario.want) {
				t.Fatalf("preview arguments = %#v, want %#v", got, scenario.want)
			}
			if err := controller.resolveApproval(requestID, scenario.approve); err != nil {
				t.Fatal(err)
			}
			responseValue := <-completed
			if responseValue.err != nil || responseValue.result == nil || responseValue.result.IsError == scenario.approve {
				t.Fatalf("unexpected tool result: %#v, %v", responseValue.result, responseValue.err)
			}
			if scenario.approve && (scenario.tool == "run_command" || scenario.tool == "send_text") {
				select {
				case written := <-writes:
					if scenario.tool == "send_text" && written != scenario.arguments["text"] {
						t.Fatal("execution did not preserve original raw text")
					}
					if scenario.tool == "run_command" && !strings.Contains(written, scenario.arguments["command"].(string)) {
						t.Fatal("execution did not preserve original command")
					}
				default:
					t.Fatal("approved tool did not execute")
				}
			} else if len(writes) != 0 {
				t.Fatal("tool unexpectedly wrote to the terminal")
			}
		})
	}
}

func TestMcpInvalidExecutionArgumentsDoNotRequestApproval(t *testing.T) {
	client, controller, native, output := newMcpPreviewTestClient(t)
	native.stdin = callbackWriteCloser{write: func([]byte) (int, error) {
		t.Error("invalid tool input reached terminal")
		return 0, io.ErrClosedPipe
	}}
	for _, request := range []*mcp.CallToolParams{
		{Name: "run_command", Arguments: map[string]any{"sessionId": "session", "command": ""}},
		{Name: "run_command", Arguments: map[string]any{"sessionId": "session", "command": strings.Repeat("x", mcpMaxCommandBytes+1)}},
		{Name: "run_command", Arguments: map[string]any{"sessionId": "session", "command": "true", "timeoutSeconds": 3601}},
		{Name: "send_text", Arguments: map[string]any{"sessionId": "session", "text": strings.Repeat("x", mcpMaxSendTextBytes+1)}},
		{Name: "read_terminal", Arguments: map[string]any{"sessionId": "session", "maxBytes": mcpMaxReadBytes + 1}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result, err := client.CallTool(ctx, request)
		cancel()
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid %s arguments were not rejected: %v", request.Name, err)
		}
	}
	controller.server.output.mu.Lock()
	defer controller.server.output.mu.Unlock()
	if output.Len() != 0 {
		t.Fatal("invalid arguments created an approval")
	}
}
