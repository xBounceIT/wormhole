package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	errForcepointCertificateUntrusted = errors.New("Forcepoint gateway certificate requires verification")
	errForcepointCertificateInvalid   = errors.New("Forcepoint gateway certificate is expired or invalid; contact the VPN administrator")
)

type forcepointGatewayCertificate struct {
	pin      string
	subject  string
	issuer   string
	expires  time.Time
	verified bool
}

// Probe only TLS, before a sidecar or any VPN authentication is started. The
// verification callback always verifies the peer or aborts the handshake. An
// untrusted public certificate is returned for explicit fingerprint confirmation;
// it never authorizes this connection to send credentials.
func probeForcepointCertificate(ctx context.Context, host string, port int, roots *x509.CertPool) (*forcepointGatewayCertificate, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var certificate *forcepointGatewayCertificate
	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"ssvtp/1"},
		InsecureSkipVerify: true, // mandatory replacement verification below
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("Forcepoint gateway did not provide a server certificate")
			}
			leaf := state.PeerCertificates[0]
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errForcepointCertificateInvalid
			}
			digest := sha256.Sum256(leaf.Raw)
			certificate = &forcepointGatewayCertificate{
				pin: hex.EncodeToString(digest[:]), subject: leaf.Subject.String(),
				issuer: leaf.Issuer.String(), expires: leaf.NotAfter,
			}
			intermediates := x509.NewCertPool()
			for _, peer := range state.PeerCertificates[1:] {
				intermediates.AddCert(peer)
			}
			_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates})
			if err == nil {
				certificate.verified = true
				return nil
			}
			var unknownCA x509.UnknownAuthorityError
			var hostname x509.HostnameError
			if errors.As(err, &unknownCA) || errors.As(err, &hostname) {
				return errForcepointCertificateUntrusted
			}
			return errForcepointCertificateInvalid
		},
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if conn != nil {
		_ = conn.Close()
	}
	if errors.Is(probeCtx.Err(), context.Canceled) {
		return nil, errors.New("Forcepoint certificate prompt cancelled")
	}
	if probeCtx.Err() != nil {
		return nil, errors.New("Forcepoint TLS connection timed out while verifying the gateway certificate")
	}
	if errors.Is(err, errForcepointCertificateUntrusted) || err == nil {
		return certificate, nil
	}
	if errors.Is(err, errForcepointCertificateInvalid) {
		return nil, errForcepointCertificateInvalid
	}
	return nil, errors.New("Forcepoint TLS connection failed; check the SSL gateway host, port and network connectivity")
}

func prepareForcepointAuthentication(ctx context.Context, raw json.RawMessage, snapshots ...tunnelConfigSnapshot) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, errors.New("Forcepoint tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if err := validateTunnelSettings(7, settings); err != nil {
		return nil, err
	}
	// An explicit pin is checked by the native transport on the actual VPN TLS
	// connection. Never replace it or offer to trust a changed pinned certificate.
	if tunnelSettingString(settings, "ServerCertSha256Pin") != "" {
		return json.Marshal(settings)
	}
	host := tunnelSettingString(settings, "Host")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	port := int(tunnelSettingNumber(settings, "Port"))
	if port == 0 {
		port = 443
	}
	certificate, err := probeForcepointCertificate(ctx, host, port, nil)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if certificate.verified {
		return raw, nil
	}
	// Public certificate metadata is bounded and quoted so controls in an
	// untrusted subject cannot disguise the fingerprint or gateway identity.
	label := func(value string) string {
		if len(value) > 256 {
			value = value[:256]
		}
		return strconv.QuoteToASCII(value)
	}
	fingerprint := strings.ToUpper(certificate.pin)
	groups := make([]string, 0, 8)
	for offset := 0; offset < len(fingerprint); offset += 8 {
		groups = append(groups, fingerprint[offset:offset+8])
	}
	accepted, err := requestTunnelPrompt(ctx, tunnelPrompt{
		Title: "Verify Forcepoint gateway certificate",
		Message: fmt.Sprintf("This computer does not trust the certificate presented by %s. Compare its SHA-256 fingerprint with your administrator or a trusted Forcepoint client before accepting.\n\nSubject: %s\nIssuer: %s\nSHA-256: %s\nExpires (UTC): %s\n\nAccepting saves this exact certificate for this tunnel.",
			label(net.JoinHostPort(host, strconv.Itoa(port))), label(certificate.subject), label(certificate.issuer), strings.Join(groups, " "), certificate.expires.UTC().Format(time.RFC3339)),
		Confirmation: true, AcceptLabel: "Trust certificate and connect",
	})
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if accepted != "accept" {
		return nil, errors.New("Forcepoint certificate prompt cancelled")
	}
	settings["ServerCertSha256Pin"], _ = json.Marshal(certificate.pin)
	pinned, err := json.Marshal(settings)
	if err != nil {
		return nil, errors.New("Forcepoint tunnel settings are invalid")
	}
	if len(snapshots) > 0 && snapshots[0].id != "" {
		if err := persistForcepointPinIfUnchanged(snapshots[0], raw, pinned); err != nil {
			clearBytes(pinned)
			return nil, err
		}
	}
	return pinned, nil
}

func persistForcepointPinIfUnchanged(snapshot tunnelConfigSnapshot, original, pinned json.RawMessage) error {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	release, err := acquireTunnelMutationLock(snapshot.databasePath)
	if err != nil {
		return err
	}
	defer release()
	details, err := readTunnelUnlocked(snapshot.databasePath, tunnelReadRequest{ID: snapshot.id})
	if err != nil {
		return errors.New("the Forcepoint tunnel changed during certificate verification; retry the connection")
	}
	defer clearBytes(details.Settings)
	if details.Kind != 7 || (!bytes.Equal(details.Settings, original) && !bytes.Equal(details.Settings, pinned)) {
		return errors.New("the Forcepoint tunnel changed during certificate verification; retry the connection")
	}
	if bytes.Equal(details.Settings, pinned) {
		return nil
	}
	if err := protectFile(legacyTunnelSecretPath(snapshot.databasePath, snapshot.id), pinned); err != nil {
		return errors.New("could not save the verified Forcepoint gateway certificate")
	}
	return nil
}
