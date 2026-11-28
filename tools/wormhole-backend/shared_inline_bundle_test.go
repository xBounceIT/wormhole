package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"golang.org/x/crypto/ssh"
)

func installSharedInlineFixture(t *testing.T, c *sharedAdmissionController, wire map[string]any, signing vault.KeyRef, mode string, customize ...func(*vaultstore.NodeMetadata)) {
	t.Helper()
	editSharedConnectionFixture(t, c.trustBinding.WorkspaceID, signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
		enabled, user := true, "inline-user"
		n.UseInlinePassword = &enabled
		n.Username = &user
		if n.Protocol != nil && (*n.Protocol == 0 || *n.Protocol == 7) {
			pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{25}, 32))
			n.SshKnownHostFingerprint = &pin
		}
		for _, setup := range customize {
			setup(n)
		}
	})
	metadata := wire["metadata"].(map[string]any)
	metadata["credential"] = nil
	nodeRow := metadata["chain"].([]any)[0].([]any)
	account := wire["accounts"].([]any)[0].(map[string]any)
	account["account"] = "inline"
	valueRow := account["values"].([]any)[0].([]any)
	password := []byte("inline-native-secret")
	if mode == "empty" {
		password = []byte{}
	}
	binding := vault.SharedValueBinding{WorkspaceID: c.trustBinding.WorkspaceID, OwnerKind: "node", OwnerID: uuid.MustParse(nodeRow[1].(string)), Field: "inlinePassword", Version: 9, DEK: vault.KeyRef{ID: uuid.MustParse(valueRow[6].(string)), Version: 1}}
	value, err := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSharedEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	valueRow[1], valueRow[4], valueRow[8] = nodeRow[1], "inlinePassword", hex.EncodeToString(raw)
	record := sharedcatalog.NodeFieldsRecord{NodeID: nodeRow[1].(string), Fields: []vaultstore.CredentialField{{Field: "inlinePassword", Version: 9, Present: true}}}
	if mode == "absent" || mode == "removed" {
		if mode == "absent" {
			record.Fields = []vaultstore.CredentialField{}
		} else {
			record.Fields[0].Present = false
		}
		account["values"], account["copies"] = []any{}, []any{}
		wire["roots"] = []any{}
	}
	revision, _ := strconv.ParseUint(nodeRow[6].(string), 10, 64)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignSelection(c.trustBinding.WorkspaceID, uuid.MustParse(nodeRow[5].(string)), record, revision, signing, key)
	if err != nil {
		t.Fatal(err)
	}
	fieldRow := append([]any{}, nodeRow...)
	raw, _ = json.Marshal(record)
	fieldRow[4], fieldRow[11] = string(raw), hex.EncodeToString(seal.Signature)
	wire["formatVersion"], wire["nodeFields"] = 3, fieldRow
}

func TestSharedInlineProtocolBundlesUseOnlySignedNodeFields(t *testing.T) {
	for _, protocol := range []int{0, 7} {
		for _, mode := range []string{"password", "empty", "absent", "removed"} {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) { n.Protocol = &protocol })
			installSharedInlineFixture(t, c, wire, account.State.Signing, mode)
			q, private := sharedSSHRequest(node)
			q.SFTPOnly = protocol == 7
			result, err := c.SealSSHConnection(context.Background(), q, "ui")
			// Existing SSH framing/native authentication requires a usable credential.
			// Unlike VNC, absent/empty SSH passwords do not select a no-auth fallback.
			if mode != "password" {
				if err != vault.ErrPolicy || len(result.Bundle.Ciphertext) != 0 {
					t.Fatal("empty inline SSH accepted", protocol, mode, err)
				}
				continue
			}
			if err != nil {
				t.Fatal("inline SSH", protocol, err)
			}
			frame, err := vault.OpenBundle(private, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := vault.DecodeSSHBundle(frame)
			if err != nil || string(payload.Password) != "inline-native-secret" || payload.Username != "inline-user" || payload.SFTPOnly != (protocol == 7) || len(payload.PrivateKey) != 0 {
				t.Fatal("inline SSH fields", err)
			}
			vault.Wipe(frame)
		}
	}
}

func TestSharedInlineProtocolRejectsUnauthenticatedManifest(t *testing.T) {
	for _, protocol := range []int{0, 7} {
		c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
		editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) { n.Protocol = &protocol })
		installSharedInlineFixture(t, c, wire, account.State.Signing, "password")
		wire["nodeFields"].([]any)[11] = hex.EncodeToString(make([]byte, 64))
		begins := 0
		begin := p.begin
		p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
			begins++
			return begin(ctx, id, source)
		}
		q, _ := sharedSSHRequest(node)
		q.SFTPOnly = protocol == 7
		result, err := c.SealSSHConnection(context.Background(), q, "ui")
		if err == nil || len(result.Bundle.Ciphertext) != 0 {
			t.Fatal("forged inline SSH")
		}
		if begins != 1 || c.Unlocked() {
			t.Fatal("failed inline release did not audit and retire")
		}
	}
}

func TestSharedInlineNativeSSHAndSFTPAuthentication(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, protocol := range []int{0, 7} {
			t.Run(strconv.Itoa(protocol)+"-routed-"+strconv.FormatBool(routed), func(t *testing.T) {
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
				authenticated := make(chan bool, 1)
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
						ok := meta.User() == "inline-user" && bytes.Equal(password, []byte("inline-native-secret"))
						authenticated <- ok
						if !ok {
							return nil, io.ErrUnexpectedEOF
						}
						return nil, nil
					}}
					config.AddHostKey(signer)
					native, channels, requests, err := ssh.NewServerConn(conn, config)
					if err != nil {
						done <- err
						return
					}
					defer native.Close()
					go ssh.DiscardRequests(requests)
					var workers sync.WaitGroup
					workerError := make(chan error, 1)
					for incoming := range channels {
						channel, requests, err := incoming.Accept()
						if err != nil {
							native.Close()
							workers.Wait()
							done <- err
							return
						}
						workers.Add(1)
						go func() {
							defer workers.Done()
							defer channel.Close()
							for request := range requests {
								if protocol == 7 && request.Type != "subsystem" {
									if request.WantReply {
										_ = request.Reply(false, nil)
									}
									select {
									case workerError <- io.ErrUnexpectedEOF:
									default:
									}
									return
								}
								if request.WantReply {
									_ = request.Reply(true, nil)
								}
								if request.Type == "subsystem" {
									server := sftp.NewRequestServer(channel, sftp.InMemHandler())
									_ = server.Serve()
									_ = server.Close()
									return
								}
								if request.Type == "shell" {
									_, _ = channel.Write([]byte("inline-ready\r\n"))
									_, _ = io.Copy(channel, channel)
									return
								}
							}
						}()
					}
					workers.Wait()
					select {
					case err := <-workerError:
						done <- err
					default:
						done <- nil
					}
				}()
				c, p, _, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
				installSharedInlineFixture(t, c, wire, account.State.Signing, "password", func(n *vaultstore.NodeMetadata) {
					host, port, pin := "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
					if routed {
						host, port = "unreachable-shared-route.invalid", 22
						enabled, id := true, uuid.NewString()
						n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
					}
					n.Protocol, n.Host, n.Port, n.SshKnownHostFingerprint = &protocol, &host, &port, &pin
				})
				if routed {
					installSharedTunnelReleaseFixture(t, wire, account, []byte(`{"ProfileOvpn":"native-shared-config","Password":"tunnel-secret"}`))
				}
				begins := 0
				begin := p.begin
				p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
					begins++
					return begin(ctx, id, source)
				}
				h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
				t.Cleanup(func() { _ = h.Close() })
				child := startSealedSSHTestChild(t, nil, sealedEditOptions(t))
				q, _ := sharedSSHRequest(node)
				q.PublicKey = child.public
				q.SFTPOnly = protocol == 7
				request := sharedPlanPayload(q)
				request["publicKey"], request["sftpOnly"] = q.PublicKey, q.SFTPOnly
				operation := "ssh-bundle"
				var tunnelChild *sealedSSHTestChild
				var routeProcess *tunnelProcess
				var borrowedSettings []byte
				var proxyDone <-chan error
				if routed {
					route := sharedRoutedPlan(t, h, q)
					endpoint, done := sharedRouteSOCKSFixture(t, listener.Addr().String(), route.Host, int(route.Port))
					proxyDone = done
					routeProcess = testSealedTunnelProcess(endpoint)
					native := startSealedTunnelTestChild(t, func(_ context.Context, b vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
						if b != route || !bytes.Contains(raw, []byte("tunnel-secret")) {
							t.Error("native tunnel binding/settings")
						}
						borrowedSettings = raw
						return routeProcess, nil
					})
					tunnelChild = &native
					query := sharedPlanPayload(q)
					query["publicKey"] = native.public
					packet, err := h.Handle(context.Background(), "tunnel-bundle", vaultInput(t, query))
					if err != nil {
						t.Fatal(err)
					}
					native.send(t, packet)
					var ready map[string]any
					if json.Unmarshal(native.line(t), &ready) != nil || ready["type"] != "ready" || ready["endpoint"] != endpoint {
						t.Fatal("native tunnel startup")
					}
					request["route"], request["endpoint"] = route, endpoint
					operation = "ssh-route-bundle"
				}
				response, err := h.Handle(context.Background(), operation, vaultInput(t, request))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(response, []byte("inline-native-secret")) {
					t.Fatal("plaintext SSH relay")
				}
				var packet map[string]json.RawMessage
				if json.Unmarshal(response, &packet) != nil {
					t.Fatal("SSH packet")
				}
				packet["columns"], packet["rows"] = json.RawMessage("80"), json.RawMessage("24")
				packetBytes, err := json.Marshal(packet)
				if err != nil {
					t.Fatal(err)
				}
				child.send(t, packetBytes)
				event := waitSealedMemberEvent(t, child, "connected", q.SessionID)
				wantBegins := 1
				if routed {
					wantBegins = 2
				}
				if event.Username != "inline-user" || begins != wantBegins {
					t.Fatal("inline connection identity or audit")
				}
				select {
				case ok := <-authenticated:
					if !ok {
						t.Fatal("inline authentication rejected")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("inline authentication timeout")
				}
				sendSealedSFTP(t, child, q.SessionID, map[string]any{"type": "sftp-open", "request_id": "inline-files"})
				if ready := waitSealedSFTPEvent(t, child, "sftp.ready", "inline-files"); ready.Path != "/" {
					t.Fatal("inline SFTP unavailable")
				}
				child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": q.SessionID}))
				if err := child.wait(t); err != nil {
					t.Fatal(err)
				}
				if tunnelChild != nil {
					tunnelChild.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": q.SessionID}))
					if err := tunnelChild.wait(t); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-proxyDone:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("SOCKS relay survived lock")
					}
					if routeProcess.alive() || !bytes.Equal(borrowedSettings, make([]byte, len(borrowedSettings))) {
						t.Fatal("route or settings survived lock")
					}
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("inline transport did not close")
				}
			})
		}
	}
}
