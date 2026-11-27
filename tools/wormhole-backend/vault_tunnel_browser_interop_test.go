package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVaultTunnelBrowserInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_SAML_INTEROP")
	if mode == "" {
		t.Skip("native isolated SAML browser fixture")
	}
	var mu sync.Mutex
	var port, uid string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml_login" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("gateway request")
			}
			values, _ := url.ParseQuery(body["bytes"])
			mu.Lock()
			port, uid = values.Get("REDIRECT_PORT"), values.Get("UID")
			mu.Unlock()
			fmt.Fprint(w, `window.location="/saml";`)
			return
		}
		if r.URL.Path == "/saml" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if mode == "cancel" {
				fmt.Fprint(w, "<h1>Waiting</h1>")
				return
			}
			token := strings.Repeat("ab", 16)
			if mode == "ready-mixed" {
				token = strings.Repeat("aB", 16)
			}
			if mode == "bad-token" {
				token = "bad"
			}
			mu.Lock()
			callback := "http://127.0.0.1:" + port + "/?tokenid=" + token
			mu.Unlock()
			if mode == "ready-redirect" {
				http.Redirect(w, r, callback, http.StatusFound)
				return
			}
			raw, _ := json.Marshal(callback)
			fmt.Fprintf(w, `<!doctype html><script>if(typeof require!=='undefined'||typeof process!=='undefined'||window.wormhole)throw Error('bridge exposed');location.href=%s;</script>`, raw)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	gateway, _ := url.Parse(server.URL)
	samlPort, _ := strconv.Atoi(gateway.Port())
	configuration, _ := json.Marshal(map[string]any{"Host": "127.0.0.1", "PreSharedKey": "synthetic-key", "SamlPort": samlPort, "UserAuth": 3, "TrustServerCertificate": true})
	defer vault.Wipe(configuration)
	b := sealedTunnelBinding()
	b.Kind = 9
	b.RowVersion = 9223372036854775807
	b.ConfigurationVersion = 9223372036854775806
	a, err := newSealedTunnelBrowser(b, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	accepted := make(chan bool, 1)
	go func() {
		conn, err := a.listener.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err == nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go func() {
		var envelope vault.SealedBundle
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16384))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&envelope) != nil {
			cancel()
			return
		}
		select {
		case a.response <- envelope:
		case <-ctx.Done():
		}
	}()
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"binding": b}) != nil {
		t.Fatal("binding")
	}
	result, err := a.complete(ctx, json.NewEncoder(os.Stdout), configuration)
	defer vault.Wipe(result)
	if <-accepted {
		t.Fatal("browser sent HTTP to the native reserved callback")
	}
	if mode == "cancel" || mode == "bad-token" {
		if err == nil {
			t.Fatal("cancelled browser accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		settings, _ := decodeVaultTunnelSettings(result)
		defer clearTunnelSettingsMap(settings)
		mu.Lock()
		wantUID := uid
		mu.Unlock()
		wantToken := strings.Repeat("ab", 16)
		if mode == "ready-mixed" {
			wantToken = strings.Repeat("aB", 16)
		}
		decoded, e := hex.DecodeString(wantUID)
		if e != nil || len(decoded) != 16 || tunnelSettingString(settings, "SamlUid") != wantUID || tunnelSettingString(settings, "SamlToken") != wantToken {
			t.Fatal("wrong native account token")
		}
		launch := context.WithValue(context.Background(), sealedTunnelBrowserKey{}, sealedTunnelBrowserPermit{b, sha256.Sum256(result)})
		_, sidecar, e := sealedTunnelBrowserConfig(launch, b, result)
		defer vault.Wipe(sidecar)
		if e != nil {
			t.Fatal(e)
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack")
	}
}
