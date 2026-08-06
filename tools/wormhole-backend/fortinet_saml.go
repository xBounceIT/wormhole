package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	fortinetSAMLDefaultCallbackPort = 8020
	fortinetSAMLMaxAuthIDLength     = 4096
	fortinetSAMLMaxHeaderBytes      = 16 * 1024
)

func authenticateFortinetExternalSAML(ctx context.Context, host string, port, callbackPort int) (string, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(callbackPort)))
	if err != nil {
		return "", fmt.Errorf("could not listen for the Fortinet SAML callback on port %d", callbackPort)
	}
	defer listener.Close()
	gatewayURL, err := buildWebURL("https", host, port)
	if err != nil {
		return "", errors.New("Fortinet gateway is invalid")
	}
	start, _ := url.Parse(gatewayURL)
	start.Path = "/remote/saml/start"
	start.RawQuery = "redirect=1"
	startURL := start.String()
	if err := openExternalURL(ctx, startURL); err != nil {
		return "", err
	}
	return waitForFortinetSAMLCallback(ctx, listener)
}

func waitForFortinetSAMLCallback(ctx context.Context, listener net.Listener) (string, error) {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", errors.New("Fortinet SAML callback listener failed")
		}
		authID, valid := readFortinetSAMLCallback(connection)
		_ = connection.Close()
		if valid {
			return authID, nil
		}
	}
}

func readFortinetSAMLCallback(connection net.Conn) (string, bool) {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(connection, 4096)
	requestLine, err := reader.ReadString('\n')
	if err != nil || len(requestLine) > fortinetSAMLMaxHeaderBytes {
		writeFortinetSAMLResponse(connection, false)
		return "", false
	}
	consumed := len(requestLine)
	for {
		line, err := reader.ReadString('\n')
		consumed += len(line)
		if consumed > fortinetSAMLMaxHeaderBytes || err != nil {
			writeFortinetSAMLResponse(connection, false)
			return "", false
		}
		if line == "\r\n" {
			break
		}
	}
	parts := strings.Fields(strings.TrimSpace(requestLine))
	if len(parts) != 3 || parts[0] != "GET" || (parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1") {
		writeFortinetSAMLResponse(connection, false)
		return "", false
	}
	authID, valid := parseFortinetSAMLAuthID(parts[1])
	writeFortinetSAMLResponse(connection, valid)
	return authID, valid
}

func parseFortinetSAMLAuthID(requestTarget string) (string, bool) {
	if len(requestTarget) == 0 || len(requestTarget) > fortinetSAMLMaxAuthIDLength+1024 || requestTarget[0] != '/' {
		return "", false
	}
	parsed, err := url.ParseRequestURI(requestTarget)
	if err != nil {
		return "", false
	}
	authID := strings.TrimSpace(parsed.Query().Get("id"))
	if authID == "" || len(authID) > fortinetSAMLMaxAuthIDLength {
		return "", false
	}
	return authID, true
}

func writeFortinetSAMLResponse(writer io.Writer, success bool) {
	status := "400 Bad Request"
	body := "Invalid authentication callback."
	if success {
		status = "200 OK"
		body = "Authentication received. You can return to Wormhole."
	}
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\n\r\n%s", status, len(body), body)
}

func openExternalURL(ctx context.Context, target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return errors.New("Fortinet SAML URL is invalid")
	}
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.CommandContext(ctx, "rundll32.exe", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.CommandContext(ctx, "open", target)
	default:
		command = exec.CommandContext(ctx, "xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return errors.New("could not open the system browser for Fortinet SAML")
	}
	go func() { _ = command.Wait() }()
	return nil
}
