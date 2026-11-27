package main

import (
	"context"
	"crypto/sha256"
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
	"sync/atomic"
	"testing"
	"time"
)

func TestVaultTunnelCookieInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_COOKIE_INTEROP")
	if mode == "" {
		t.Skip("native isolated SSL cookie fixture")
	}
	value := "Opaque+/=_~aB"
	if mode == "ready-large" {
		value = strings.Repeat("aB", 1750)
	}
	callbackMode := strings.Contains(mode, "callback")
	var callbackSent, loopbackReached atomic.Bool
	var callbackURL string
	if callbackMode {
		value = "Synthetic,callback+/="
		listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loopbackReached.Store(true)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer listener.Close()
		callbackURL = listener.URL + "/?id=" + url.QueryEscape(value)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callbackMode {
			switch r.URL.Path {
			case "/remote/saml/start":
				if r.URL.RawQuery != "redirect=1" {
					http.Error(w, "invalid start", http.StatusBadRequest)
					return
				}
				source := "/remote/saml/login"
				if mode == "callback-untrusted-source" {
					source = "/remote/portal"
				}
				http.Redirect(w, r, source, http.StatusFound)
			case "/remote/saml/login", "/remote/portal":
				callbackSent.Store(true)
				if mode == "ready-callback-navigation" {
					w.Header().Set("Content-Type", "text/html")
					target, _ := json.Marshal(callbackURL)
					fmt.Fprintf(w, "<script>location.assign(%s)</script>", target)
				} else {
					http.Redirect(w, r, callbackURL, http.StatusFound)
				}
			default:
				http.NotFound(w, r)
			}
			return
		}
		if r.URL.Path != "/remote/saml/start" && r.URL.Path != "/remote/complete" && r.URL.Path != "/remote/portal" {
			w.WriteHeader(404)
			return
		}
		if mode == "ready-late" && r.URL.Path == "/remote/saml/start" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script>if(typeof require!=='undefined'||typeof process!=='undefined'||window.wormhole)throw Error('bridge exposed');setTimeout(()=>fetch('/remote/complete'),25);</script>`)
			return
		}
		if mode == "cancel" {
			fmt.Fprint(w, "Waiting")
			return
		}
		if r.URL.Path != "/remote/portal" {
			cookie := &http.Cookie{Name: "SVPNCOOKIE", Value: value, Path: "/remote/", HttpOnly: mode != "no-http-only", Secure: true}
			if mode == "expired" {
				cookie.MaxAge = -1
			}
			http.SetCookie(w, cookie)
		}
		if mode == "ready-redirect" && r.URL.Path == "/remote/saml/start" {
			http.Redirect(w, r, "/remote/portal", http.StatusFound)
			return
		}
		fmt.Fprint(w, "Authenticated")
	}))
	defer server.Close()
	gateway, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(gateway.Port())
	options := map[string]any{"Host": "127.0.0.1", "Port": port, "UseSingleSignOn": true, "TrustServerCertificate": true}
	field := "SvpnCookie"
	if callbackMode {
		options["UseSamlCallback"] = true
		field = "SamlAuthId"
	} else {
		options["Realm"] = "staff/a"
	}
	configuration, _ := json.Marshal(options)
	defer vault.Wipe(configuration)
	b := sealedTunnelBinding()
	b.Kind = 2
	b.RowVersion = 9223372036854775807
	b.ConfigurationVersion = 9223372036854775806
	a, err := newSealedTunnelCookie(b, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go func() {
		var envelope vault.SealedBundle
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32768))
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
	if !strings.HasPrefix(mode, "ready") {
		if err == nil {
			t.Fatal("unproven cookie accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		settings, _ := decodeVaultTunnelSettings(result)
		defer clearTunnelSettingsMap(settings)
		if tunnelSettingString(settings, field) != value {
			t.Fatal("wrong opaque cookie")
		}
		launch := context.WithValue(context.Background(), sealedTunnelBrowserKey{}, sealedTunnelBrowserPermit{b, sha256.Sum256(result)})
		_, sidecar, e := sealedTunnelBrowserConfig(launch, b, result)
		defer vault.Wipe(sidecar)
		if e != nil {
			t.Fatal(e)
		}
	}
	if callbackMode && (!callbackSent.Load() || loopbackReached.Load()) {
		t.Fatal("gateway callback must be observed without a loopback HTTP request")
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack")
	}
}
