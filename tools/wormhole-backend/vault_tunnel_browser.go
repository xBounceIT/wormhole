package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"net"
	"strings"
)

type sealedTunnelBrowserFlow interface {
	close()
	complete(context.Context, *json.Encoder, []byte) ([]byte, error)
	recipient() *sealedTunnelControlRecipient
}
type sealedTunnelBrowser struct {
	binding           vault.TunnelBrowserBinding
	key               *securemem.Buffer
	public, uid       []byte
	listener          net.Listener
	response          chan vault.SealedBundle
	negotiationFailed bool // provider failed before a user challenge was published
}

func (a *sealedTunnelBrowser) recipient() *sealedTunnelControlRecipient {
	return &sealedTunnelControlRecipient{"browser-authentication", a.binding.ChallengeID, a.response, 16384}
}
func newSealedTunnelBrowser(b vault.TunnelBundleBinding, configuration []byte) (*sealedTunnelBrowser, error) {
	if b.Kind != 9 {
		return nil, nil
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	if fortinetUserAuth(settings) != 3 {
		return nil, nil
	}
	if validateFortinetIPsecSettings(settings) != nil || strings.TrimSpace(tunnelSettingString(settings, "FallbackTunnelId")) != "" {
		return nil, vault.ErrPolicy
	}
	a := &sealedTunnelBrowser{binding: vault.TunnelBrowserBinding{Route: b, ChallengeID: uuid.NewString(), IgnoreCertificateErrors: tunnelSettingBool(settings, "TrustServerCertificate")}, response: make(chan vault.SealedBundle, 1), uid: make([]byte, 16)}
	if _, err = rand.Read(a.uid); err != nil {
		a.close()
		return nil, err
	}
	a.listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		a.close()
		return nil, err
	}
	a.binding.CallbackURL = "http://" + a.listener.Addr().String() + "/"
	a.key, a.public, err = newSealedTunnelRecipientKey()
	if err != nil {
		a.close()
		return nil, err
	}
	return a, nil
}
func (a *sealedTunnelBrowser) close() {
	if a.listener != nil {
		_ = a.listener.Close()
	}
	if a.key != nil {
		_ = a.key.Close()
	}
	vault.Wipe(a.uid)
}
func (a *sealedTunnelBrowser) complete(ctx context.Context, encoder *json.Encoder, configuration []byte) ([]byte, error) {
	defer a.close()
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	port := a.listener.Addr().(*net.TCPAddr).Port
	samlPort := tunnelSettingNumber(settings, "SamlPort")
	if samlPort == 0 {
		samlPort = 1001
	}
	hosts := append([]string{tunnelSettingString(settings, "Host")}, strings.Split(tunnelSettingString(settings, "RemoteGateways"), ",")...)
	var chosen string
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		base, e := buildWebURL("https", host, int(samlPort))
		if e != nil {
			return nil, vault.ErrFormat
		}
		a.binding.StartURL, err = requestFortinetIPsecSAML(ctx, base, strings.ToUpper(hex.EncodeToString(a.uid)), port, a.binding.IgnoreCertificateErrors)
		if err == nil {
			chosen = host
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if err != nil || chosen == "" {
		a.negotiationFailed = err != nil
		return nil, vault.ErrPolicy
	}
	if err = encoder.Encode(struct {
		Type                    string `json:"type"`
		SessionID               string `json:"sessionId"`
		ChallengeID             string `json:"challengeId"`
		PublicKey               []byte `json:"publicKey"`
		StartURL                string `json:"startURL"`
		CallbackURL             string `json:"callbackURL"`
		IgnoreCertificateErrors bool   `json:"ignoreCertificateErrors"`
	}{"browser-authentication-required", a.binding.Route.SessionID, a.binding.ChallengeID, a.public, a.binding.StartURL, a.binding.CallbackURL, a.binding.IgnoreCertificateErrors}); err != nil {
		return nil, err
	}
	var envelope vault.SealedBundle
	select {
	case envelope = <-a.response:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	var raw []byte
	err = a.key.With(func(key []byte) error {
		var e error
		raw, e = vault.OpenTunnelBrowserToken(key, a.binding, envelope)
		return e
	})
	defer vault.Wipe(raw)
	if err != nil {
		return nil, err
	}
	if err = a.key.Close(); err != nil {
		return nil, err
	}
	// The selected gateway, UID and token never come from the renderer or storage.
	for _, name := range []string{"Username", "Password", "RemoteGateways"} {
		vault.Wipe(settings[name])
		delete(settings, name)
	}
	settings["Host"], _ = json.Marshal(chosen)
	settings["UserAuth"] = json.RawMessage("3")
	settings["SamlUid"], _ = json.Marshal(strings.ToUpper(hex.EncodeToString(a.uid)))
	settings["SamlToken"], _ = json.Marshal(string(raw[2:]))
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}

// Only successful in-process completion can mint this transient launch witness.
// An encrypted saved configuration containing token-shaped fields is insufficient.
type sealedTunnelBrowserKey struct{}
type sealedTunnelBrowserPermit struct {
	binding vault.TunnelBundleBinding
	digest  [32]byte
}

func sealedTunnelBrowserConfig(ctx context.Context, b vault.TunnelBundleBinding, configuration []byte) (string, []byte, error) {
	permit, ok := ctx.Value(sealedTunnelBrowserKey{}).(sealedTunnelBrowserPermit)
	if !ok || permit.binding != b || permit.digest != sha256.Sum256(configuration) || (b.Kind != 9 && b.Kind != 2) {
		return "", nil, vault.ErrPolicy
	}
	if b.Kind == 2 {
		return sealedTunnelCookieConfig(configuration)
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return "", nil, err
	}
	defer clearTunnelSettingsMap(settings)
	if fortinetUserAuth(settings) != 3 || tunnelSettingString(settings, "FallbackTunnelId") != "" {
		return "", nil, vault.ErrPolicy
	}
	for _, name := range []string{"SamlUid", "SamlToken"} {
		value := tunnelSettingString(settings, name)
		decoded, e := hex.DecodeString(value)
		valid := e == nil && len(decoded) == 16
		vault.Wipe(decoded)
		if !valid {
			return "", nil, vault.ErrFormat
		}
		vault.Wipe(settings[name])
		delete(settings, name)
	}
	if validateFortinetIPsecSettings(settings) != nil {
		return "", nil, vault.ErrFormat
	}
	return tunnelSidecarCommand(9, configuration)
}
