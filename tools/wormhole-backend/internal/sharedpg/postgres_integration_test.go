package sharedpg

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/crypto/pbkdf2"
)

// Opt-in real-server tests. Binaries are supplied by the operator, never
// downloaded or installed automatically by the test suite. The cluster listens
// only on loopback and stores synthetic data beneath the requested scratch root.
func postgresTestCluster(t *testing.T) (Settings, []byte) {
	return postgresTestClusterTLS(t, false)
}

func postgresTestClusterTLS(t *testing.T, enableTLS bool) (Settings, []byte) {
	t.Helper()
	bin := os.Getenv("WORMHOLE_TEST_POSTGRES_BIN")
	if bin == "" {
		t.Skip("set WORMHOLE_TEST_POSTGRES_BIN for real PostgreSQL integration tests")
	}
	root := os.Getenv("WORMHOLE_TEST_POSTGRES_SCRATCH")
	if !filepath.IsAbs(bin) || !filepath.IsAbs(root) {
		t.Fatal("PostgreSQL test binary/scratch directories must be absolute")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	cluster, err := os.MkdirTemp(root, "postgres-integration-")
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(cluster, "data")
	logPath := filepath.Join(cluster, "server.log")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(secret))
	clear(secret)
	t.Cleanup(func() { clear(password) })
	tool := func(name string) string {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		return filepath.Join(bin, name)
	}
	run := func(ctx context.Context, name string, input []byte, args ...string) error {
		cmd := exec.CommandContext(ctx, tool(name), args...)
		hidePostgresTestProcess(cmd)
		cmd.WaitDelay = 5 * time.Second
		if runtime.GOOS == "windows" && name == "initdb" {
			// PostgreSQL's Windows simple_prompt explicitly uses stdin under
			// OSTYPE=msys. Otherwise it opens CONIN$ even with redirected stdin.
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(strings.ToUpper(entry), "OSTYPE=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "OSTYPE=msys")
		}
		cmd.Stdin = bytes.NewReader(input)
		// Leave output on the null device. pg_ctl's detached server can inherit
		// pipe handles and prevent an otherwise successful start from completing.
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	input := append(append(append([]byte{}, password...), '\n'), password...)
	input = append(input, '\n')
	err = run(ctx, "initdb", input, "-D", data, "-U", "wormhole_test_admin", "--encoding=UTF8", "--no-locale", "--auth=scram-sha-256", "--pwprompt", "--no-instructions")
	clear(input)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	// Use only loopback TCP. Packaged Unix servers otherwise create a socket in a system directory.
	config := "\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = ''\nport = " + strconv.Itoa(int(port)) + "\n"
	// Keep statement text and parameters out of the log, including failed test statements.
	config += "log_statement = 'none'\nlog_min_error_statement = 'panic'\nlog_error_verbosity = 'terse'\n"
	var ca []byte
	if enableTLS {
		ca = postgresTestCertificate(t, data)
		config += "ssl = on\nssl_min_protocol_version = 'TLSv1.2'\n"
	}
	f, err := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString(config)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cannot configure test PostgreSQL")
	}
	t.Cleanup(func() {
		stopCtx, done := context.WithTimeout(context.Background(), 40*time.Second)
		defer done()
		if err := run(stopCtx, "pg_ctl", nil, "-D", data, "-m", "fast", "-w", "-t", "30", "stop"); err != nil {
			t.Errorf("test cluster retained because stop is unconfirmed: %v", err)
			return
		}
		log, err := os.ReadFile(logPath)
		if err != nil {
			t.Error(err)
		} else if bytes.Contains(log, password) {
			t.Error("test password appeared in server log")
		}
		// cluster was generated directly under root; never delete a supplied
		// data directory or a cluster whose process has not confirmed shutdown.
		if filepath.Dir(cluster) != filepath.Clean(root) {
			t.Error("unexpected scratch directory")
			return
		}
		if err := os.RemoveAll(cluster); err != nil {
			t.Error(err)
		}
	})
	if err := run(ctx, "pg_ctl", nil, "-D", data, "-l", logPath, "-w", "-t", "30", "start"); err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.Endpoints = []Endpoint{{"127.0.0.1", port}}
	s.Database = "postgres"
	s.DeviceRole = "wormhole_test_admin"
	if enableTLS {
		s.TLS = TLSVerified
		s.CAPEM = ca
	}
	return s, password
}

func TestPostgresStatementLoggingAdmission(t *testing.T) {
	s, adminPassword := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin := NewSession()
	defer admin.Close(context.Background())
	if err := admin.Open(ctx, s, adminPassword, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(secret))
	clear(secret)
	defer clear(password)
	if _, err := admin.Query(ctx, "CREATE ROLE wh_test_device LOGIN PASSWORD '"+postgresTestVerifier(password)+"'", nil); err != nil {
		t.Fatal(err)
	}
	s.DeviceRole = "wh_test_device"
	for _, logging := range []string{"ddl", "none", "all"} {
		if _, err := admin.Query(ctx, "ALTER ROLE wh_test_device SET log_statement='"+logging+"'", nil); err != nil {
			t.Fatal(err)
		}
		for _, profile := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
			s.Profile = profile
			conn, err := Connect(ctx, s, password)
			if profile == vault.Default || logging == "none" {
				if err != nil {
					t.Fatalf("profile %s, role logging %s: %v", profile, logging, err)
				}
				if err := conn.Close(ctx); err != nil {
					t.Fatal(err)
				}
			} else if conn != nil || err != ErrConnection {
				t.Fatalf("profile %s accepted role logging %s", profile, logging)
			}
		}
	}
}

func TestPostgresNativeTransportIntegration(t *testing.T) {
	s, adminSecret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := NewSession()
	defer admin.Close(context.Background())
	if err := admin.Open(ctx, s, adminSecret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	listeners, err := admin.Query(ctx, "SELECT current_setting('listen_addresses'), current_setting('unix_socket_directories')", nil)
	if err != nil || len(listeners) != 1 || len(listeners[0]) != 2 || string(listeners[0][0]) != "127.0.0.1" || len(listeners[0][1]) != 0 {
		t.Fatal("test cluster must listen only on loopback TCP", err)
	}
	rows, err := admin.Query(ctx, "show server_version_num", nil)
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 {
		t.Fatal("cannot read PostgreSQL version")
	}
	version, err := strconv.Atoi(string(rows[0][0]))
	if err != nil || version < 160000 {
		t.Fatal("PostgreSQL 16+ required")
	}
	deviceSecret := make([]byte, 32)
	if _, err := rand.Read(deviceSecret); err != nil {
		t.Fatal(err)
	}
	devicePassword := []byte(hex.EncodeToString(deviceSecret))
	clear(deviceSecret)
	defer clear(devicePassword)
	verifier := postgresTestVerifier(devicePassword)
	_, err = admin.Query(ctx, "CREATE ROLE wh_test_device LOGIN CONNECTION LIMIT 3 PASSWORD '"+verifier+"'", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.DeviceRole = "wh_test_device"
	device := NewSession()
	defer device.Close(context.Background())
	if err := device.Open(ctx, s, devicePassword, ChangePolicy{}); err != nil {
		t.Fatal(err)
	}
	rows, err = device.Query(ctx, "SELECT $1::text, NULL::text, ''::text", [][]byte{[]byte("Connessione — 東京")})
	if err != nil || len(rows) != 1 || len(rows[0]) != 3 || string(rows[0][0]) != "Connessione — 東京" || rows[0][1] != nil || rows[0][2] == nil {
		t.Fatal("real PostgreSQL text/null binding failed")
	}
	if err := device.SubscribeChanges(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Query(ctx, "SELECT pg_catalog.pg_notify('wormhole_changes',$1::text)", [][]byte{[]byte(testHintID)}); err != nil {
		t.Fatal(err)
	}
	if id, err := device.NextChangeHint(ctx); err != nil || id != testHintID {
		t.Fatalf("real notification failed: %v", err)
	}
	third, err := Connect(ctx, s, devicePassword)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close(context.Background())
	if fourth, err := Connect(ctx, s, devicePassword); err != ErrConnectionLimit {
		if fourth != nil {
			_ = fourth.Close(ctx)
		}
		t.Fatalf("real role connection limit not enforced: %v", err)
	}
	_ = third.Close(ctx)
	if wrong, err := Connect(ctx, s, []byte("incorrect-native-test-password")); err != ErrAuthentication {
		if wrong != nil {
			_ = wrong.Close(ctx)
		}
		t.Fatalf("real authentication error not sanitized: %v", err)
	}
	if err := device.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func postgresTestVerifier(password []byte) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	salted := pbkdf2.Key(password, salt, 4096, 32, sha256.New)
	defer clear(salted)
	mac := func(label string) []byte {
		h := hmac.New(sha256.New, salted)
		_, _ = h.Write([]byte(label))
		return h.Sum(nil)
	}
	client := mac("Client Key")
	stored := sha256.Sum256(client)
	clear(client)
	server := mac("Server Key")
	defer clear(server)
	return "SCRAM-SHA-256$4096:" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(stored[:]) + ":" + base64.StdEncoding.EncodeToString(server)
}
