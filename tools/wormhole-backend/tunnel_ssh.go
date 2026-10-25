package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/internal/sshauth"
	"golang.org/x/crypto/ssh"
)

const maxSSHJumpDepth = 3

func validSSHFingerprint(pin string) bool {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pin, "SHA256:"))
	return strings.HasPrefix(pin, "SHA256:") && err == nil && len(b) == sha256.Size
}

func validateSSHJumpSettings(settings map[string]json.RawMessage) error {
	allowed := map[string]bool{"Mode": true, "JumpConnectionId": true, "Host": true, "Port": true, "Username": true, "CredentialId": true, "HostKeySha256": true, "KeepaliveSeconds": true}
	for key := range settings {
		if !allowed[key] {
			return errors.New("SSH tunnel settings must contain references only, never credentials")
		}
		if key != "Port" && key != "KeepaliveSeconds" {
			var value string
			if err := json.Unmarshal(settings[key], &value); err != nil || strings.TrimSpace(string(settings[key])) == "null" {
				return errors.New("SSH tunnel reference settings must be strings")
			}
		}
	}
	mode := tunnelSettingString(settings, "Mode")
	if mode != "connection" && mode != "manual" {
		return errors.New("SSH tunnel mode is invalid")
	}
	if err := validateOptionalTunnelInteger(settings, "KeepaliveSeconds", 1, 3600); err != nil {
		return err
	}
	if mode == "connection" {
		if normalizeTunnelID(tunnelSettingString(settings, "JumpConnectionId")) == "" {
			return errors.New("SSH tunnel jump connection id is invalid")
		}
		for _, key := range []string{"Host", "Port", "Username", "CredentialId", "HostKeySha256"} {
			if _, present := settings[key]; present {
				return errors.New("SSH tunnel connection mode cannot override its saved connection")
			}
		}
		return nil
	}
	if _, present := settings["JumpConnectionId"]; present {
		return errors.New("SSH tunnel manual mode cannot reference a connection")
	}
	host := tunnelSettingString(settings, "Host")
	port := tunnelSettingNumber(settings, "Port")
	if len(host) > 1024 || formatTunnelEndpoint(host, strconv.FormatInt(port, 10)) == "" || strings.IndexFunc(host, unicode.IsControl) >= 0 {
		return errors.New("SSH tunnel host or port is invalid")
	}
	user := tunnelSettingString(settings, "Username")
	if strings.TrimSpace(user) == "" || len(user) > 512 || strings.IndexFunc(user, unicode.IsControl) >= 0 {
		return errors.New("SSH tunnel username is invalid")
	}
	if normalizeTunnelID(tunnelSettingString(settings, "CredentialId")) == "" {
		return errors.New("SSH tunnel credential id is invalid")
	}
	if pin := tunnelSettingString(settings, "HostKeySha256"); pin != "" && !validSSHFingerprint(pin) {
		return errors.New("SSH tunnel host-key fingerprint is invalid")
	}
	return nil
}

func resolveSSHJumpTarget(snapshot tunnelConfigSnapshot) (sshTarget, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(snapshot.settings, &settings); err != nil {
		return sshTarget{}, errors.New("SSH tunnel settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if err := validateSSHJumpSettings(settings); err != nil {
		return sshTarget{}, err
	}
	var target sshTarget
	var err error
	if tunnelSettingString(settings, "Mode") == "connection" {
		target, err = loadSSHTarget(snapshot.databasePath, tunnelSettingString(settings, "JumpConnectionId"))
		if err != nil && (err.Error() == "SSH connection was not found" || strings.Contains(err.Error(), "not an SSH")) {
			err = errors.New("SSH tunnel jump connection was not found or is not SSH")
		}
	} else {
		target = sshTarget{host: tunnelSettingString(settings, "Host"), port: int(tunnelSettingNumber(settings, "Port")), username: strings.TrimSpace(tunnelSettingString(settings, "Username")), knownHostFingerprint: tunnelSettingString(settings, "HostKeySha256"), credentialID: tunnelSettingString(settings, "CredentialId")}
		db, openErr := openDatabase(snapshot.databasePath, false)
		if openErr != nil {
			return target, openErr
		}
		err = loadSSHCredential(db, snapshot.databasePath, target.credentialID, &target, "", "", false, false)
		_ = db.Close()
	}
	if err != nil && strings.Contains(err.Error(), "Bitwarden") {
		return sshTarget{}, errors.New("Bitwarden credentials are not yet supported for SSH tunnels")
	}
	if err != nil && err.Error() == "SSH credential was not found" {
		return sshTarget{}, errors.New("SSH tunnel credential was not found; Bitwarden credentials are not yet supported for SSH tunnels")
	}
	if err != nil {
		clearBytes(target.privateKey)
		return sshTarget{}, err
	}
	if target.password == "" && len(target.privateKey) == 0 {
		return target, errors.New("SSH tunnel has no usable saved credential; Bitwarden credentials are not yet supported for SSH tunnels")
	}
	return target, nil
}

// Identity includes the resolved inheritance, protected credential contents and every upstream
// config, so a new lease cannot silently reuse a session established before a credential rotation.
// Only the digest survives this calculation; neither it nor its input is sent to the renderer.
func sshJumpIdentity(databasePath, id string, path []string) (string, error) {
	tunnelMutationMu.RLock()
	defer tunnelMutationMu.RUnlock()
	return sshJumpIdentityUnlocked(databasePath, id, path)
}

func sshJumpIdentityUnlocked(databasePath, id string, path []string) (string, error) {
	identity, _, err := sshJumpIdentitiesUnlocked(databasePath, id, path)
	return identity, err
}

func sshJumpIdentitiesUnlocked(databasePath, id string, path []string) (string, string, error) {
	for _, visited := range path {
		if strings.EqualFold(id, visited) {
			return "", "", errors.New("SSH tunnel chain contains a cycle")
		}
	}
	if len(path) >= maxSSHJumpDepth {
		return "", "", errors.New("SSH tunnel chain exceeds the maximum depth of 3")
	}
	snapshot, err := loadTunnelSnapshot(databasePath, id)
	if err != nil {
		return "", "", err
	}
	snapshot, err = loadTunnelSnapshotSettings(snapshot)
	if err != nil {
		return "", "", err
	}
	defer clearBytes(snapshot.settings)
	var target *sshTarget
	upstream, upstreamConfiguration := "", ""
	if snapshot.kind == 7 {
		resolved, err := resolveSSHJumpTarget(snapshot)
		if err != nil {
			return "", "", err
		}
		defer clearBytes(resolved.privateKey)
		target = &resolved
		if resolved.tunnelConfigID != "" {
			upstream, upstreamConfiguration, err = sshJumpIdentitiesUnlocked(databasePath, resolved.tunnelConfigID, append(path, id))
			if err != nil {
				return "", "", err
			}
		}
	}
	return sshJumpSnapshotIdentity(snapshot, target, upstream, true), sshJumpSnapshotIdentity(snapshot, target, upstreamConfiguration, false), nil
}

// TOFU may refresh only the trust part of a pending identity. A concurrent credential or
// upstream edit must not relabel an older in-flight authentication as the new configuration.
func sshJumpSnapshotIdentity(snapshot tunnelConfigSnapshot, target *sshTarget, upstream string, includeTrust bool) string {
	settings := snapshot.settings
	if !includeTrust && snapshot.kind == 7 {
		var values map[string]json.RawMessage
		_ = json.Unmarshal(settings, &values)
		delete(values, "HostKeySha256")
		settings, _ = json.Marshal(values)
		defer clearTunnelSettingsMap(values)
		defer clearBytes(settings)
	}
	hash := sha256.New()
	// Length-prefix every byte string: passwords and passphrases may themselves contain NUL.
	write := func(value string) {
		_, _ = fmt.Fprintf(hash, "%d:", len(value))
		_, _ = io.WriteString(hash, value)
	}
	for _, value := range []string{snapshot.id, snapshot.updatedAt, strconv.FormatInt(snapshot.kind, 10), string(settings)} {
		write(value)
	}
	if target != nil {
		pin := target.knownHostFingerprint
		if !includeTrust {
			pin = ""
		}
		for _, value := range []string{target.host, strconv.Itoa(target.port), target.username, pin, target.credentialID, target.password, string(target.privateKey), target.keyPassphrase, upstream} {
			write(value)
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

type sshJumpPathKey struct{}
type sshJumpTrustRefreshKey struct{}

func prepareSSHJump(ctx context.Context, snapshot tunnelConfigSnapshot) (json.RawMessage, *tunnelRuntime, string, error) {
	target, err := resolveSSHJumpTarget(snapshot)
	if err != nil {
		return nil, nil, "", err
	}
	defer clearBytes(target.privateKey)
	sourceTarget := target
	var upstream *tunnelRuntime
	if target.tunnelConfigID != "" {
		upstream, err = startTunnelRuntime(ctx, snapshot.databasePath, target.tunnelConfigID)
		if err != nil {
			return nil, nil, "", err
		}
	}
	succeeded := false
	defer func() {
		if !succeeded {
			upstream.close()
		}
	}()
	pin, err := probeSSHJump(ctx, target, upstream)
	if err != nil {
		return nil, nil, "", err
	}
	if target.knownHostFingerprint == "" {
		answer, err := requestTunnelPrompt(ctx, tunnelPrompt{Title: "Trust SSH jump host", Message: fmt.Sprintf("Trust %s:%d with host key %s?", target.host, target.port, pin), Confirmation: true, AcceptLabel: "Trust"})
		if err != nil {
			return nil, nil, "", err
		}
		if answer != "true" && answer != "yes" && answer != "accept" {
			return nil, nil, "", errors.New("SSH tunnel host-key trust was cancelled")
		}
		if err := verifySSHJumpTargetCurrent(snapshot, sourceTarget); err != nil {
			return nil, nil, "", err
		}
		if err := persistSSHJumpPin(ctx, snapshot, target, pin); err != nil {
			return nil, nil, "", err
		}
		sourceTarget.knownHostFingerprint = pin
	}
	if len(target.privateKey) > 0 {
		passphrase := []byte(target.keyPassphrase)
		_, parseErr := sshauth.ParseSigner(target.privateKey, passphrase, nil)
		clearBytes(passphrase)
		var missing *ssh.PassphraseMissingError
		if errors.As(parseErr, &missing) {
			target.keyPassphrase, err = requestTunnelPrompt(ctx, tunnelPrompt{Title: "SSH tunnel key passphrase", Message: "Enter the jump host private key passphrase.", Secret: true})
			if err != nil {
				return nil, nil, "", err
			}
			passphrase = []byte(target.keyPassphrase)
			_, parseErr = sshauth.ParseSigner(target.privateKey, passphrase, nil)
			clearBytes(passphrase)
		}
		if parseErr != nil {
			return nil, nil, "", errors.New("SSH tunnel private key, certificate or passphrase is invalid")
		}
	}
	tunnelMutationMu.RLock()
	latest, err := currentSSHJumpSnapshot(snapshot, sourceTarget)
	upstreamIdentity := ""
	if err == nil && upstream != nil {
		upstreamIdentity, err = sshJumpIdentityUnlocked(snapshot.databasePath, sourceTarget.tunnelConfigID, nil)
		if err == nil && (upstreamIdentity != upstream.entry.identity || !upstream.entry.process.alive()) {
			err = errors.New("SSH tunnel upstream changed while authentication was in progress")
		}
	}
	identity := sshJumpSnapshotIdentity(latest, &sourceTarget, upstreamIdentity, true)
	clearBytes(latest.settings)
	tunnelMutationMu.RUnlock()
	if err != nil {
		return nil, nil, "", err
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(snapshot.settings, &settings)
	defer clearTunnelSettingsMap(settings)
	keepalive := tunnelSettingNumber(settings, "KeepaliveSeconds")
	if keepalive == 0 {
		keepalive = 30
	}
	payload, err := json.Marshal(map[string]any{"host": target.host, "port": target.port, "username": target.username, "password": target.password, "private_key": string(target.privateKey), "key_passphrase": target.keyPassphrase, "host_key_sha256": pin, "keepalive_s": keepalive, "upstream_socks": upstream.socksEndpoint()})
	succeeded = err == nil
	return payload, upstream, identity, err
}

func verifySSHJumpTargetCurrent(snapshot tunnelConfigSnapshot, expected sshTarget) error {
	tunnelMutationMu.RLock()
	defer tunnelMutationMu.RUnlock()
	latest, err := currentSSHJumpSnapshot(snapshot, expected)
	clearBytes(latest.settings)
	return err
}

func currentSSHJumpSnapshot(snapshot tunnelConfigSnapshot, expected sshTarget) (tunnelConfigSnapshot, error) {
	latest, err := loadTunnelSnapshot(snapshot.databasePath, snapshot.id)
	if err != nil || latest.updatedAt != snapshot.updatedAt || latest.kind != 7 {
		return tunnelConfigSnapshot{}, errors.New("SSH tunnel changed while authentication was in progress")
	}
	latest, err = loadTunnelSnapshotSettings(latest)
	if err != nil {
		return tunnelConfigSnapshot{}, err
	}
	current, err := resolveSSHJumpTarget(latest)
	defer clearBytes(current.privateKey)
	if err != nil || current.host != expected.host || current.port != expected.port || current.username != expected.username || current.credentialID != expected.credentialID || current.password != expected.password || !bytes.Equal(current.privateKey, expected.privateKey) || current.keyPassphrase != expected.keyPassphrase || current.tunnelConfigID != expected.tunnelConfigID || current.knownHostFingerprint != expected.knownHostFingerprint {
		clearBytes(latest.settings)
		return tunnelConfigSnapshot{}, errors.New("SSH jump connection, credential or host key changed while authentication was in progress")
	}
	return latest, nil
}

func probeSSHJump(ctx context.Context, target sshTarget, upstream *tunnelRuntime) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	address := net.JoinHostPort(normalizeSSHHost(target.host), strconv.Itoa(target.port))
	var conn net.Conn
	var err error
	if upstream != nil {
		conn, err = upstream.dialContext(ctx, "tcp", address)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return "", errors.New("could not reach SSH jump host")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	pin := ""
	_, _, _, _ = ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: target.username, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		pin = ssh.FingerprintSHA256(key)
		return errors.New("SSH host-key probe complete")
	}})
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if pin == "" {
		return "", errors.New("SSH jump host did not provide a host key")
	}
	if target.knownHostFingerprint != "" && target.knownHostFingerprint != pin {
		// Do not let the target session's mismatch UX replace the target's pin with the bastion's.
		return "", fmt.Errorf("SSH tunnel host key mismatch (expected %s, received %s); verify the jump host before forgetting its pin", target.knownHostFingerprint, pin)
	}
	return pin, nil
}

func persistSSHJumpPin(ctx context.Context, snapshot tunnelConfigSnapshot, target sshTarget, pin string) error {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	release, err := acquireTunnelConfigurationLock(ctx, snapshot.databasePath)
	if err != nil {
		return err
	}
	defer release()
	latest, err := currentSSHJumpSnapshot(snapshot, target)
	defer clearBytes(latest.settings)
	if err != nil {
		return err
	}
	refresh := func() error {
		if callback, ok := ctx.Value(sshJumpTrustRefreshKey{}).(func() error); ok {
			return callback()
		}
		return nil
	}
	if target.nodeID != "" {
		if err := persistSSHJumpNodePin(ctx, snapshot.databasePath, target, pin); err != nil {
			return err
		}
		return refresh()
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(latest.settings, &settings)
	defer clearTunnelSettingsMap(settings)
	if existing := tunnelSettingString(settings, "HostKeySha256"); existing != "" && existing != pin {
		return errSSHHostFingerprintChanged
	}
	settings["HostKeySha256"], _ = json.Marshal(pin)
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	defer clearBytes(raw)
	if err := protectFile(legacyTunnelSecretPath(snapshot.databasePath, snapshot.id), raw); err != nil {
		return err
	}
	return refresh()
}

func persistSSHJumpNodePin(ctx context.Context, databasePath string, target sshTarget, pin string) error {
	if len(target.nodeTrustContext) == 0 {
		return errors.New("SSH jump connection context is missing")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	// Reserve SQLite's writer before checking public connection metadata. Do not read
	// credentials here: credential writers take their file lock before SQLite's writer lock.
	if _, err := transaction.ExecContext(ctx, "UPDATE Nodes SET UpdatedAt=UpdatedAt WHERE lower(Id)=?;", target.nodeID); err != nil {
		return errors.New("could not reserve SSH jump host trust")
	}
	reader, err := openDatabase(databasePath, true)
	if err != nil {
		return err
	}
	if reader == nil {
		return errors.New("SSH jump connection changed while confirming its host key")
	}
	nodes, err := loadSSHNodes(reader)
	_ = reader.Close()
	if err != nil {
		return err
	}
	for id, expected := range target.nodeTrustContext {
		current := nodes[id]
		if current == nil || !reflect.DeepEqual(*current, expected) {
			return errors.New("SSH jump connection changed while confirming its host key")
		}
	}
	result, err := transaction.ExecContext(ctx,
		"UPDATE Nodes SET SshKnownHostFingerprint=?,UpdatedAt=? WHERE lower(Id)=? AND COALESCE(TRIM(SshKnownHostFingerprint),'')='';",
		pin, time.Now().UTC().Format(time.RFC3339Nano), target.nodeID)
	if err != nil {
		return errors.New("could not save SSH jump host trust")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errSSHHostFingerprintChanged
	}
	return transaction.Commit()
}

func readSSHJumpReady(ctx context.Context, reader *bufio.Reader, stdin io.Writer, ready chan<- string, failures chan<- error) {
	for count := 0; count < 65; count++ {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			failures <- errors.New("SSH tunnel exited before reporting readiness")
			return
		}
		if strings.HasPrefix(string(line), "READY ") {
			readTunnelReady(bufio.NewReader(strings.NewReader(string(line))), ready, failures)
			return
		}
		var prompt struct {
			Message *string `json:"message"`
		}
		if !strings.HasPrefix(string(line), "PROMPT ") || json.Unmarshal(line[7:], &prompt) != nil || prompt.Message == nil || len(*prompt.Message) > 1024 || strings.IndexFunc(*prompt.Message, unicode.IsControl) >= 0 {
			failures <- errors.New("SSH tunnel returned an invalid authentication prompt")
			return
		}
		answer, err := requestTunnelPrompt(ctx, tunnelPrompt{Title: "SSH tunnel authentication", Message: *prompt.Message, Secret: true})
		if err != nil {
			failures <- err
			return
		}
		if len(answer) > 16384 {
			failures <- errors.New("SSH tunnel authentication answer is too large")
			return
		}
		raw, _ := json.Marshal(map[string]string{"answer": answer})
		_, err = stdin.Write(raw)
		clearBytes(raw)
		if err == nil {
			_, err = stdin.Write([]byte{'\n'})
		}
		if err != nil {
			failures <- errors.New("SSH tunnel authentication was interrupted")
			return
		}
	}
	failures <- errors.New("SSH tunnel authentication exceeds limits")
}
