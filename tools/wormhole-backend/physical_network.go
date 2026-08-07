package main

import "strings"

type openVPNTransportRemote struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type openVPNDirectiveScope struct {
	port     string
	protocol string
}

type openVPNRemoteDraft struct {
	scope    *openVPNDirectiveScope
	host     string
	port     string
	protocol string
}

func extractOpenVPNTransportRemotes(profile string) []openVPNTransportRemote {
	top := &openVPNDirectiveScope{}
	current := top
	var opaque string
	var drafts []openVPNRemoteDraft
	for _, rawLine := range splitVPNProfileLines(profile) {
		line := strings.TrimSpace(rawLine)
		if opaque != "" {
			if isVPNCloseTag(line, opaque) {
				opaque = ""
			}
			continue
		}
		if current != top && isVPNCloseTag(line, "connection") {
			current = top
			continue
		}
		if block, ok := vpnOpenTag(line); ok {
			if strings.EqualFold(block, "connection") {
				current = &openVPNDirectiveScope{}
			} else {
				opaque = block
			}
			continue
		}
		tokens := tokenizeOpenVPNDirective(line)
		if len(tokens) < 2 {
			continue
		}
		switch strings.ToLower(tokens[0]) {
		case "port":
			current.port = tokens[1]
		case "proto":
			current.protocol = tokens[1]
		case "remote":
			draft := openVPNRemoteDraft{scope: current, host: tokens[1]}
			if len(tokens) >= 3 {
				draft.port = tokens[2]
			}
			if len(tokens) >= 4 {
				draft.protocol = tokens[3]
			}
			drafts = append(drafts, draft)
		}
	}
	remotes := make([]openVPNTransportRemote, 0, len(drafts))
	for _, draft := range drafts {
		port := draft.port
		if port == "" {
			port = draft.scope.port
		}
		if port == "" {
			port = top.port
		}
		if port == "" {
			port = "1194"
		}
		protocol := draft.protocol
		if protocol == "" {
			protocol = draft.scope.protocol
		}
		if protocol == "" {
			protocol = top.protocol
		}
		if protocol == "" {
			protocol = "udp"
		}
		remotes = append(remotes, openVPNTransportRemote{Host: draft.host, Port: port, Protocol: protocol})
	}
	return remotes
}

func tokenizeOpenVPNDirective(line string) []string {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return nil
	}
	var tokens []string
	var token strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if token.Len() > 0 {
			tokens = append(tokens, token.String())
			token.Reset()
		}
	}
	for _, character := range line {
		switch {
		case escaped:
			token.WriteRune(character)
			escaped = false
		case character == '\\':
			escaped = true
		case quote != 0:
			if character == quote {
				quote = 0
			} else {
				token.WriteRune(character)
			}
		case character == '\'' || character == '"':
			quote = character
		case character == ' ' || character == '\t':
			flush()
		default:
			token.WriteRune(character)
		}
	}
	if escaped {
		token.WriteByte('\\')
	}
	flush()
	return tokens
}
