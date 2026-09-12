package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const mcpMaxExecutionPreviewBytes = 64 * 1024

const mcpPreviewSecretKey = `[a-z0-9_-]*(?:password|passwd|passphrase|token|secret|api[_-]?key|private[_-]?key|session[_-]?key)[a-z0-9_-]*`

// Shell values can concatenate quoted and unquoted segments and escape spaces.
// An unfinished quote still contains sensitive text (notably with send_text).
const mcpPreviewShellValue = `(?:"(?:\\[\s\S]|[^"\\])*(?:"|$)|'[^']*(?:'|$)|\\[\s\S]|[^\s;&|<>()'"\\])+`

// Only MCP input fields belong here, never resolved credentials or session internals.
type mcpExecutionArguments struct {
	SessionID      string  `json:"sessionId,omitempty"`
	ConnectionID   string  `json:"connectionId,omitempty"`
	Command        *string `json:"command,omitempty"`
	Text           *string `json:"text,omitempty"`
	TimeoutSeconds int     `json:"timeoutSeconds,omitempty"`
	MaxBytes       int     `json:"maxBytes,omitempty"`
}

type mcpExecutionPreview struct {
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
	Redacted  bool   `json:"redacted"`
}

var mcpPreviewSecretPatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`), "[redacted private key]"},
	{regexp.MustCompile(`(?i)(\b(?:proxy-authorization|authorization|cookie|set-cookie)\s*:\s*)(?:=(?:"(?:\\.|[^"\\])*"|'[^']*')|[^\r\n'"])+`), "${1}[redacted]"},
	{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@]+@`), "${1}[redacted]@"},
	// Quoted JSON keys use a single JSON value, rather than shell-word concatenation.
	{regexp.MustCompile(`(?i)(["']` + mcpPreviewSecretKey + `["']\s*:\s*)("(?:\\.|[^"\\])*(?:"|$)|'[^']*(?:'|$)|[^,\s}]+)`), `${1}"[redacted]"`},
	{regexp.MustCompile(`(?i)((?:--` + mcpPreviewSecretKey + `["']?|\b` + mcpPreviewSecretKey + `\b)\s*(?:=|:|\s)\s*)` + mcpPreviewShellValue), "${1}[redacted]"},
	{regexp.MustCompile(`(?i)((?:--(?:proxy-)?user(?:=|\s+)|(?:^|\s)-[uU]\s*))` + mcpPreviewShellValue), "${1}[redacted]"},
	{regexp.MustCompile(`(?i)(\bsshpass\b[^\r\n;&|]*?\s-p\s*)` + mcpPreviewShellValue), "${1}[redacted]"},
	{regexp.MustCompile(`(?i)(\b(?:bearer|basic)\s+)[a-z0-9_+./=-]+`), "${1}[redacted]"},
}

func newMcpExecutionPreview(arguments mcpExecutionArguments) *mcpExecutionPreview {
	preview := &mcpExecutionPreview{}
	for _, field := range []**string{&arguments.Command, &arguments.Text} {
		if *field == nil {
			continue
		}
		original := **field
		value := original
		for _, rule := range mcpPreviewSecretPatterns {
			value = rule.pattern.ReplaceAllString(value, rule.replacement)
		}
		preview.Redacted = preview.Redacted || value != original
		*field = &value
	}
	// This fixed struct contains only strings and integers, so marshaling cannot fail.
	encoded, _ := json.MarshalIndent(arguments, "", "  ")
	encoded = escapeMcpPreviewControls(encoded)
	if len(encoded) > mcpMaxExecutionPreviewBytes {
		end := mcpMaxExecutionPreviewBytes
		for !utf8.RuneStart(encoded[end]) {
			end--
		}
		encoded = encoded[:end]
		preview.Truncated = true
	}
	preview.Content = string(encoded)
	return preview
}

func escapeMcpPreviewControls(encoded []byte) []byte {
	// JSON leaves Unicode formatting and C1 controls literal. Escape them so they
	// cannot reorder or hide the preview, while JSON decoding preserves the input.
	var escaped bytes.Buffer
	escaped.Grow(len(encoded))
	for _, char := range string(encoded) {
		if char >= 0x80 && (unicode.Is(unicode.Cf, char) || unicode.IsControl(char)) {
			if char > 0xffff {
				high, low := utf16.EncodeRune(char)
				fmt.Fprintf(&escaped, `\u%04x\u%04x`, high, low)
			} else {
				fmt.Fprintf(&escaped, `\u%04x`, char)
			}
		} else {
			escaped.WriteRune(char)
		}
	}
	return escaped.Bytes()
}
