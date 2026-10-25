package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestForcepointConfirmationWireFixtureMatchesBrokerAndResolves(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "forcepoint-certificate-prompt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	for _, cancelled := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelled), func(t *testing.T) {
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(writer)})
			defer manager.close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				value, err := manager.promptTunnel("forcepoint-test-lease")(ctx, tunnelPrompt{
					Title:        "Verify Forcepoint gateway certificate",
					Message:      "Verify this gateway before connecting.\nSHA-256: " + strings.Repeat("AB", 32),
					Confirmation: true, AcceptLabel: "Trust certificate and connect",
				})
				if !cancelled && err == nil && value != "accept" {
					err = errors.New("certificate acceptance was lost")
				}
				result <- err
			}()
			decoder := json.NewDecoder(reader)
			var event map[string]any
			if err := decoder.Decode(&event); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(event, expected) {
				t.Fatalf("broker JSON differs from the renderer regression fixture: %#v", event)
			}
			go manager.handle(backendCommand{
				ID: "certificate-answer", Action: "tunnel.prompt-response", SessionID: "forcepoint-test-lease",
				PromptID: "tunnel-prompt-1", Value: "accept", Cancelled: cancelled,
			})
			var response backendResponse
			if err := decoder.Decode(&response); err != nil || !response.OK {
				t.Fatal("certificate response was not acknowledged", err)
			}
			var closed backendEvent
			if err := decoder.Decode(&closed); err != nil || closed.Type != "tunnel.prompt-closed" {
				t.Fatal("certificate prompt did not close", err)
			}
			err := <-result
			if cancelled {
				if err == nil || !strings.Contains(err.Error(), "cancelled") {
					t.Fatal("certificate cancellation was lost", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type forcepointTLSPeer struct {
	host string
	port int
	leaf *x509.Certificate
	pin  string
}

func newForcepointTLSPeer(t *testing.T, expired bool, subject string) forcepointTLSPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Hour)
	if expired {
		end = time.Now().Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: subject},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: end,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var applicationBytes atomic.Int64
	var peers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				applicationBytes.Add(n)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		peers.Wait()
		if applicationBytes.Load() != 0 {
			t.Error("certificate discovery sent VPN application data")
		}
	})
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	digest := sha256.Sum256(der)
	return forcepointTLSPeer{host, p, leaf, hex.EncodeToString(digest[:])}
}

func forcepointPeerSettings(peer forcepointTLSPeer) json.RawMessage {
	settings := forcepointSettingsForTest()
	settings["Host"], settings["Port"] = peer.host, peer.port
	raw, _ := json.Marshal(settings)
	return raw
}

func TestForcepointCertificateProbeVerifiesOrAbortsWithoutVPNData(t *testing.T) {
	peer := newForcepointTLSPeer(t, false, "Forcepoint test gateway")
	certificate, err := probeForcepointCertificate(context.Background(), peer.host, peer.port, nil)
	if err != nil || certificate == nil || certificate.verified || certificate.pin != peer.pin {
		t.Fatal("private certificate discovery failed", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(peer.leaf)
	certificate, err = probeForcepointCertificate(context.Background(), peer.host, peer.port, roots)
	if err != nil || certificate == nil || !certificate.verified {
		t.Fatal("trusted certificate did not pass normal verification", err)
	}
	expired := newForcepointTLSPeer(t, true, "Expired test gateway")
	if _, err := probeForcepointCertificate(context.Background(), expired.host, expired.port, nil); !errors.Is(err, errForcepointCertificateInvalid) {
		t.Fatal("expired certificate could reach the trust prompt", err)
	}
	for _, cancelled := range []bool{true, false} {
		var ctx context.Context
		var cancel context.CancelFunc
		if cancelled {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		} else {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}
		_, err := probeForcepointCertificate(ctx, peer.host, peer.port, nil)
		cancel()
		want := "timed out"
		if cancelled {
			want = "cancelled"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatal("incorrect cancellation classification", err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	if _, err := probeForcepointCertificate(context.Background(), "127.0.0.1", port, nil); err == nil || !strings.Contains(err.Error(), "network connectivity") {
		t.Fatal("network failure was mistaken for certificate consent", err)
	}
}

func TestForcepointCertificateConsentPinsAndProtectsExactPeer(t *testing.T) {
	peer := newForcepointTLSPeer(t, false, strings.Repeat("x", 300)+"\nforged")
	path := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(path, tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: forcepointPeerSettings(peer)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Confirmation || prompt.Secret || prompt.Browser || !strings.Contains(strings.ReplaceAll(prompt.Message, " ", ""), strings.ToUpper(peer.pin)) {
			t.Error("certificate prompt did not show the exact public fingerprint")
		}
		if strings.Contains(prompt.Message, "fixture-password") || strings.Contains(prompt.Message, "fixture-user") || strings.Contains(prompt.Message, "forged") {
			t.Error("certificate prompt exposed credentials or unbounded subject data")
		}
		return "accept", nil
	})
	snapshot := tunnelConfigSnapshot{databasePath: path, id: created.ID, kind: 7}
	pinned, err := prepareTunnelAuthentication(ctx, 7, created.Settings, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(pinned)
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(pinned, &settings)
	defer clearTunnelSettingsMap(settings)
	if tunnelSettingString(settings, "ServerCertSha256Pin") != peer.pin {
		t.Fatal("accepted certificate was not pinned")
	}
	saved, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
	if err != nil || !bytes.Equal(saved.Settings, pinned) {
		t.Fatal("certificate consent was not persisted", err)
	}
	defer clearBytes(saved.Settings)
	protected, err := os.ReadFile(legacyTunnelSecretPath(path, created.ID))
	if err != nil || bytes.Contains(protected, []byte("fixture-password")) || bytes.Contains(protected, []byte(peer.pin)) {
		t.Fatal("certificate settings were not protected", err)
	}
	if err := persistForcepointPinIfUnchanged(snapshot, created.Settings, pinned); err != nil {
		t.Fatal("repeated consent was not idempotent", err)
	}
	ctx = withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
		t.Error("saved pin prompted again")
		return "", nil
	})
	if _, err := prepareTunnelAuthentication(ctx, 7, pinned, snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestForcepointCertificateRejectionAndConcurrentEditsFailClosed(t *testing.T) {
	peer := newForcepointTLSPeer(t, false, "Forcepoint test gateway")
	for _, mode := range []string{"reject", "prompt-error", "cancel-after-accept", "changed", "changed-kind", "missing-handler"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wormhole.db")
			created, err := createTunnel(path, tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: forcepointPeerSettings(peer)})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prompted := false
			if mode != "missing-handler" {
				ctx = withTunnelPromptHandler(ctx, func(context.Context, tunnelPrompt) (string, error) {
					prompted = true
					switch mode {
					case "reject":
						return "", nil
					case "prompt-error":
						return "", errors.New("prompt unavailable")
					case "cancel-after-accept":
						cancel()
					case "changed", "changed-kind":
						var values map[string]any
						_ = json.Unmarshal(created.Settings, &values)
						values["Password"] = "new-password"
						next, _ := json.Marshal(values)
						kind := int64(7)
						if mode == "changed-kind" {
							kind = 6
						}
						if _, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: created.Name, Kind: kind, Settings: next}); err != nil {
							t.Error(err)
						}
					}
					return "accept", nil
				})
			}
			_, err = prepareTunnelAuthentication(ctx, 7, created.Settings, tunnelConfigSnapshot{databasePath: path, id: created.ID})
			want := map[string]string{
				"reject": "certificate prompt cancelled", "prompt-error": "prompt unavailable",
				"cancel-after-accept": "context canceled", "changed": "tunnel changed",
				"changed-kind": "tunnel changed", "missing-handler": "interactive authentication",
			}[mode]
			if err == nil || !strings.Contains(err.Error(), want) || (mode != "missing-handler" && !prompted) {
				t.Fatalf("expected %s rejection, got %v (prompted=%v)", mode, err, prompted)
			}
			saved, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(saved.Settings)
			var values map[string]json.RawMessage
			_ = json.Unmarshal(saved.Settings, &values)
			defer clearTunnelSettingsMap(values)
			if tunnelSettingString(values, "ServerCertSha256Pin") != "" {
				t.Fatal("rejection or concurrent edit persisted certificate trust")
			}
			if strings.HasPrefix(mode, "changed") && tunnelSettingString(values, "Password") != "new-password" {
				t.Fatal("certificate consent overwrote newer credentials")
			}
		})
	}
}

func TestForcepointCertificateConsentFeedsExistingProcessLifecycle(t *testing.T) {
	peer := newForcepointTLSPeer(t, false, "Forcepoint test gateway")
	t.Setenv("WORMHOLE_CISCOPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	prompted := false
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		prompted = prompt.Confirmation && !prompt.Secret
		return "accept", nil
	})
	process, err := startTunnelProcess(ctx, tunnelConfigSnapshot{kind: 7, settings: forcepointPeerSettings(peer)})
	if err != nil {
		t.Fatal(err)
	}
	defer process.close()
	if !prompted || !process.alive() || process.socks != "127.0.0.1:32123" {
		t.Fatal("approved fingerprint did not reach the supervised VPN process")
	}
}

func TestForcepointTrustSettingsFailBeforeNetworkOrCredentialExchange(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`{"Host":false}`)} {
		if _, err := prepareForcepointAuthentication(context.Background(), raw); err == nil {
			t.Fatal("invalid settings reached certificate discovery")
		}
	}
	settings := forcepointSettingsForTest()
	settings["ServerCertSha256Pin"] = strings.Repeat("ab:\n", 32)
	raw, _ := json.Marshal(settings)
	pinned, err := prepareForcepointAuthentication(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var normalized map[string]json.RawMessage
	_ = json.Unmarshal(pinned, &normalized)
	if tunnelSettingString(normalized, "ServerCertSha256Pin") != strings.Repeat("ab", 32) {
		t.Fatal("explicit pin was not normalized without probing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareForcepointAuthentication(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled pinned connection continued authentication", err)
	}
	if err := persistForcepointPinIfUnchanged(tunnelConfigSnapshot{databasePath: filepath.Join(t.TempDir(), "absent.db"), id: "missing"}, raw, pinned); err == nil {
		t.Fatal("missing tunnel was recreated by consent")
	}
}
