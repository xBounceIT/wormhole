package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"golang.org/x/crypto/ssh"
)

// Electron starts this synthetic server in an isolated test executable. Only
// public identifiers go to stdout; the fixture database uses the real vault.
func TestVaultSSHRelayFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_SSH_RELAY")
	if path == "" {
		t.Skip("Electron relay integration fixture")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing = true
	owner, err := initializeVaultFiles(context.Background(), path, doc, root)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	nodeID := uuid.NewString()
	host, user, pin := "127.0.0.1", "relay-user", ssh.FingerprintSHA256(signer.PublicKey())
	protocol, inline := 0, true
	sftpOnly := os.Getenv("WORMHOLE_TEST_SSH_RELAY_SFTP") == "1"
	if sftpOnly {
		protocol = 7
	}
	probeHost := os.Getenv("WORMHOLE_TEST_SSH_RELAY_PROBE") == "1"
	if probeHost && os.Getenv("WORMHOLE_TEST_SSH_RELAY_ROUTE") == "1" {
		pin = ""
	}
	metadata := vaultstore.NodeMetadata{ID: nodeID, Name: "Relay fixture", Kind: 1, Protocol: &protocol, Host: &host, Port: &port, Username: &user, UseInlinePassword: &inline, SshKnownHostFingerprint: &pin}
	if os.Getenv("WORMHOLE_TEST_SSH_RELAY_ROUTE") == "1" {
		host = "127.0.0.2"
		tunnel, e := owner.PutTunnel(context.Background(), vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Relay VPN", Kind: 6}, []byte(`{"Host":"gateway.invalid","Username":"vpn-user","Password":"route-sidecar-password"}`), 0)
		if e != nil {
			t.Fatal(e)
		}
		enabled := true
		metadata.TunnelEnabled = &enabled
		metadata.TunnelConfigID = &tunnel.ID
	}
	_, err = owner.PutNode(context.Background(), metadata, []localvault.SecretChange{{Field: "inlinePassword", Value: []byte("relay-native-only-password")}}, 0)
	if err != nil {
		owner.Close()
		t.Fatal(err)
	}
	credential, err := owner.PutCredential(context.Background(), vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Quick relay account", Protocol: "ssh", Kind: "password", Provider: "local", Username: user}, []localvault.SecretChange{{Field: "password", Value: []byte("relay-native-only-password")}}, 0)
	if err != nil {
		owner.Close()
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"workspaceId": doc.VaultID, "nodeId": nodeID, "port": port, "host": host, "credentialId": credential.ID, "tunnelId": metadata.TunnelConfigID}); err != nil {
		t.Fatal(err)
	}
	accepted := false
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != user || !bytes.Equal(password, []byte("relay-native-only-password")) {
			return nil, io.ErrUnexpectedEOF
		}
		accepted = true
		return nil, nil
	}}
	config.AddHostKey(signer)
	handlers := sftp.InMemHandler()
	connections := 1
	if os.Getenv("WORMHOLE_TEST_SSH_RELAY_RECONNECT") == "1" {
		connections = 2
	}
	for attempt := 0; attempt < connections; attempt++ {
		accepted = false
		var workers sync.WaitGroup
		if probeHost {
			probe, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			attempted := false
			config.AuthLogCallback = func(ssh.ConnMetadata, string, error) { attempted = true }
			unexpected, _, _, err := ssh.NewServerConn(probe, config)
			if err == nil {
				unexpected.Close()
			}
			probe.Close()
			if err == nil || accepted || attempted {
				t.Fatal("identity probe attempted authentication")
			}
			config.AuthLogCallback = nil
		}
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		native, channels, requests, err := ssh.NewServerConn(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		defer native.Close()
		go ssh.DiscardRequests(requests)
		if !accepted {
			t.Fatal("missing native authentication")
		}
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				t.Fatal(err)
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer channel.Close()
				for request := range requests {
					if (sftpOnly || os.Getenv("WORMHOLE_TEST_SSH_RELAY_FILE_ONLY") == "1") && request.Type != "subsystem" {
						t.Error("SFTP opened a shell or terminal request")
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
						return
					}
					if request.WantReply {
						_ = request.Reply(true, nil)
					}
					if request.Type == "subsystem" {
						subsystem := sftp.NewRequestServer(channel, handlers)
						_ = subsystem.Serve()
						_ = subsystem.Close()
						return
					}
					if request.Type == "shell" {
						_, _ = channel.Write([]byte("relay-ready\r\n"))
						go io.Copy(channel, channel)
					}
				}
			}()
		}
		native.Close()
		connection.Close()
		workers.Wait()
	}

}
