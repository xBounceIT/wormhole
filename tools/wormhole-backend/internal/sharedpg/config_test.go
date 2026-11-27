package sharedpg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func settings() Settings {
	return Settings{Endpoints: []Endpoint{{"db.example.test", 5432}, {"127.0.0.1", 5433}}, Database: "workspace", DeviceRole: "device_1", TLS: TLSOff, Profile: vault.Default}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConfigPolicyAndFallbacks(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []TLSMode{TLSOff, TLSEncrypted, TLSVerified} {
		for _, profile := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
			s := settings()
			s.TLS = mode
			s.Profile = profile
			if mode == TLSVerified {
				s.CAPEM = testCA(t)
			}
			c, err := Config(s)
			if profile != vault.Default && mode != TLSVerified {
				if err != ErrConfiguration {
					t.Fatal("accepted insecure profile")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.RequireAuth != "scram-sha-256" || c.Password != "" || c.ValidateConnect == nil || c.MaxProtocolMessageBodyLen != 16*1024*1024 || c.ConnectTimeout != 10*time.Second || len(c.Fallbacks) != 1 {
				t.Fatalf("invalid transport policy")
			}
			for i, tc := range []*tls.Config{c.TLSConfig, c.Fallbacks[0].TLSConfig} {
				if mode == TLSOff {
					if tc != nil || c.ChannelBinding != "disable" {
						t.Fatal("unexpected TLS")
					}
					continue
				}
				if tc == nil || tc.MinVersion != tls.VersionTLS12 || tc.ServerName != s.Endpoints[i].Host || tc.InsecureSkipVerify != (mode == TLSEncrypted) || c.ChannelBinding != "require" {
					t.Fatal("TLS policy drift")
				}
				if mode == TLSVerified && tc.RootCAs == nil {
					t.Fatal("missing roots")
				}
			}
		}
	}
}

func TestConfigRejectsInvalidSettings(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	mutations := []func(*Settings){
		func(s *Settings) { s.Endpoints = nil }, func(s *Settings) { s.Endpoints = make([]Endpoint, 9) },
		func(s *Settings) { s.Database = "" }, func(s *Settings) { s.DeviceRole = strings.Repeat("a", 64) },
		func(s *Settings) { s.Database = "db options=evil" }, func(s *Settings) { s.Profile = "unknown" },
		func(s *Settings) { s.TLS = "prefer" }, func(s *Settings) { s.CAPEM = []byte("unexpected") },
		func(s *Settings) { s.TLS = TLSVerified }, func(s *Settings) { s.TLS = TLSVerified; s.CAPEM = []byte("bad") },
		func(s *Settings) { s.TLS = TLSVerified; s.CAPEM = make([]byte, 256*1024+1) },
		func(s *Settings) { s.Endpoints[0].Port = 0 }, func(s *Settings) { s.Endpoints[1] = s.Endpoints[0] },
	}
	for i, mutate := range mutations {
		s := settings()
		mutate(&s)
		if _, err := Config(s); err != ErrConfiguration {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	for _, host := range []string{"", "/tmp", "a,b", "db:5432", "-db", "db-", "a..b", "db.", "db_name", "[::1]", "::1%zone", strings.Repeat("a", 64), strings.Repeat("a", 254)} {
		s := settings()
		s.Endpoints[0].Host = host
		if _, err := Config(s); err != ErrConfiguration {
			t.Fatalf("accepted host %q", host)
		}
	}
	for _, host := range []string{"localhost", "::1", "2001:db8::1", "DB-1.example.test"} {
		s := settings()
		s.Endpoints[0].Host = host
		if _, err := Config(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigIgnoresAmbientConnectionOptions(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, key := range []string{"PGHOST", "PGPORT", "PGUSER", "PGDATABASE", "PGPASSWORD", "PGPASSFILE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLROOTCERT", "PGSSLCERTMODE", "PGSSLNEGOTIATION", "PGCONNECT_TIMEOUT", "PGTARGETSESSIONATTRS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGREQUIREAUTH", "PGCHANNELBINDING", "PGOPTIONS", "PGAPPNAME", "PGTZ"} {
		t.Setenv(key, "hostile-value")
	}
	c, err := Config(settings())
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "db.example.test" || c.Port != 5432 || c.User != "device_1" || c.Database != "workspace" || c.Password != "" || len(c.RuntimeParams) != 3 || c.RuntimeParams["search_path"] != "pg_catalog" || c.RuntimeParams["application_name"] != "wormhole" || c.RuntimeParams["client_encoding"] != "UTF8" || c.RequireAuth != "scram-sha-256" || c.SSLNegotiation != "postgres" || c.SSLCertMode != "disable" {
		t.Fatal("ambient configuration leaked")
	}
	t.Setenv("PGSERVICE", "untrusted")
	if _, err := Config(settings()); err != ErrConfiguration {
		t.Fatal("accepted service file")
	}
}

// Exercise the actual pgx wire handshake, not a mock of its auth policy.
func TestRejectsAuthenticationDowngrades(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, attack := range []string{"cleartext", "md5", "early-ok", "missing-final"} {
		t.Run(attack, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if _, err = b.ReceiveStartupMessage(); err != nil {
					done <- err
					return
				}
				switch attack {
				case "cleartext":
					b.Send(&pgproto3.AuthenticationCleartextPassword{})
				case "md5":
					b.Send(&pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}})
				case "early-ok":
					b.Send(&pgproto3.AuthenticationOk{})
					b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				case "missing-final":
					b.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
					if err = b.Flush(); err != nil {
						done <- err
						return
					}
					b.SetAuthType(pgproto3.AuthTypeSASL)
					msg, e := b.Receive()
					if e != nil {
						done <- e
						return
					}
					initial, ok := msg.(*pgproto3.SASLInitialResponse)
					if !ok {
						done <- fmt.Errorf("expected SASL initial, got %T", msg)
						return
					}
					parts := strings.Split(string(initial.Data), ",r=")
					if len(parts) != 2 {
						done <- fmt.Errorf("missing nonce")
						return
					}
					b.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte("r=" + parts[1] + "server,s=c2FsdA==,i=4096")})
					if err = b.Flush(); err != nil {
						done <- err
						return
					}
					b.SetAuthType(pgproto3.AuthTypeSASLContinue)
					if _, err = b.Receive(); err != nil {
						done <- err
						return
					}
					b.Send(&pgproto3.AuthenticationOk{})
				}
				if err := b.Flush(); err != nil {
					done <- err
					return
				}
				if attack == "cleartext" || attack == "md5" {
					var response [1]byte
					n, err := conn.Read(response[:])
					if n != 0 || err != io.EOF {
						done <- fmt.Errorf("client sent authentication data or did not close: bytes=%d error=%v", n, err)
						return
					}
				}
				done <- nil
			}()
			s := settings()
			s.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			c, err := Config(s)
			if err != nil {
				t.Fatal(err)
			}
			c.Password = "test-only-device-secret"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := pgconn.ConnectConfig(ctx, c)
			if conn != nil {
				_ = conn.Close(ctx)
			}
			if err == nil {
				t.Fatal("accepted authentication downgrade")
			}
			want := "require_auth"
			if attack == "missing-final" {
				want = "expected AuthenticationSASLFinal"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("failed for wrong reason: %v", err)
			}
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
			if strings.Contains(err.Error(), "test-only-device-secret") {
				t.Fatal("password leaked")
			}
		})
	}
}

func TestTLSRefusalCannotFallBackToPlaintext(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []TLSMode{TLSEncrypted, TLSVerified} {
		t.Run(string(mode), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				msg, err := b.ReceiveStartupMessage()
				if err != nil {
					done <- err
					return
				}
				if _, ok := msg.(*pgproto3.SSLRequest); !ok {
					done <- fmt.Errorf("expected SSL request, got %T", msg)
					return
				}
				_, err = conn.Write([]byte{'N'})
				if err != nil {
					done <- err
					return
				}
				var response [1]byte
				n, err := conn.Read(response[:])
				if n != 0 || err != io.EOF {
					done <- fmt.Errorf("plaintext continuation: bytes=%d error=%v", n, err)
					return
				}
				done <- nil
			}()
			s := settings()
			s.TLS = mode
			s.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			if mode == TLSVerified {
				s.CAPEM = testCA(t)
			}
			c, err := Config(s)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Fallbacks) != 0 {
				t.Fatal("unexpected fallback")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := pgconn.ConnectConfig(ctx, c)
			if conn != nil {
				_ = conn.Close(ctx)
			}
			if err == nil || !strings.Contains(err.Error(), "server refused TLS connection") {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
