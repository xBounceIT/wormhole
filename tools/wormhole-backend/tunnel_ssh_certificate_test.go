package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/internal/sshauth"
	"golang.org/x/crypto/ssh"
)

func TestSSHJumpSavedCertificateAndPKCS8Authentication(t *testing.T) {
	for _, mode := range []string{"connection", "manual"} {
		t.Run(mode, func(t *testing.T) {
			host, port, pin := jumpTestServer(t)
			path, details := jumpFixture(t, host, port)
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key := testPKCS8Key(t, private, "phrase", false, "2.16.840.1.101.3.4.1.42")
			if err := protectFile(credentialPrivateKeyPath(path, jumpCredentialID), key); err != nil {
				t.Fatal(err)
			}
			signer, err := parseSSHSigner(key, []byte("phrase"))
			if err != nil {
				t.Fatal(err)
			}
			certificate, ca := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
			line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(certificate))
			jumpExec(t, path, "UPDATE CredentialProfiles SET Kind=1,SshCertificate=? WHERE Id=?;", string(line), jumpCredentialID)
			jumpExec(t, path, "DELETE FROM CredentialSecrets WHERE Id=?;", jumpCredentialID)
			jumpExec(t, path, "UPDATE Nodes SET SshKnownHostFingerprint=? WHERE Id=?;", pin, jumpNodeID)
			if mode == "manual" {
				raw, _ := json.Marshal(map[string]any{"Mode": mode, "Host": host, "Port": port, "Username": "ops", "CredentialId": jumpCredentialID})
				details, err = updateTunnel(path, tunnelWriteRequest{ID: details.ID, Name: details.Name, Kind: 8, Settings: raw})
				if err != nil {
					t.Fatal(err)
				}
			}
			prompts := 0
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
				if prompt.Confirmation {
					return "accept", nil
				}
				if !prompt.Secret {
					t.Fatal("passphrase prompt must be secret")
				}
				prompts++
				return "phrase", nil
			})
			payload, upstream, identity, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID))
			upstream.close()
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(payload)
			var config struct {
				PrivateKey    string `json:"private_key"`
				Certificate   string `json:"certificate"`
				KeyPassphrase string `json:"key_passphrase"`
			}
			if err := json.Unmarshal(payload, &config); err != nil {
				t.Fatal(err)
			}
			if prompts != 1 || config.PrivateKey != string(key) || config.Certificate != string(line) || config.KeyPassphrase != "phrase" {
				t.Fatal("saved certificate or prompted PKCS8 passphrase was not forwarded through stdin")
			}
			parsed, err := sshauth.ParseSigner([]byte(config.PrivateKey), []byte(config.KeyPassphrase), []byte(config.Certificate))
			if err != nil || parsed.PublicKey().Type() != certificate.Type() {
				t.Fatal("sidecar cannot use the saved certificate and encrypted PKCS8 key")
			}
			snapshot := jumpSnapshot(t, path, details.ID)
			defer clearBytes(snapshot.settings)
			target, err := resolveSSHJumpTarget(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(target.privateKey)
			defer clearBytes(target.certificate)
			certificate.KeyId = "renewed certificate"
			if err := certificate.SignCert(rand.Reader, ca); err != nil {
				t.Fatal(err)
			}
			jumpExec(t, path, "UPDATE CredentialProfiles SET SshCertificate=? WHERE Id=?;", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(certificate))), jumpCredentialID)
			next, err := sshJumpIdentity(path, details.ID, nil)
			if err != nil || next == identity {
				t.Fatal("certificate renewal reused an obsolete tunnel identity")
			}
			if err := verifySSHJumpTargetCurrent(snapshot, target); err == nil {
				t.Fatal("authentication accepted certificate rotation after resolving the credential")
			}
			certificate.ValidBefore = 1
			if err := certificate.SignCert(rand.Reader, ca); err != nil {
				t.Fatal(err)
			}
			jumpExec(t, path, "UPDATE CredentialProfiles SET SshCertificate=? WHERE Id=?;", string(ssh.MarshalAuthorizedKey(certificate)), jumpCredentialID)
			if payload, _, _, err := prepareSSHJump(ctx, jumpSnapshot(t, path, details.ID)); err == nil || len(payload) != 0 {
				t.Fatal("expired saved certificate reached the sidecar")
			}
		})
	}
}
