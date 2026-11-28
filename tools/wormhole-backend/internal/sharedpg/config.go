// Package sharedpg owns the native PostgreSQL transport policy. It does not yet
// implement workspace provisioning or authorization.
package sharedpg

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type TLSMode string

const maxProtocolBodyBytes = 16 * 1024 * 1024

const (
	TLSOff       TLSMode = "off"
	TLSEncrypted TLSMode = "encrypted"
	TLSVerified  TLSMode = "verified"
)

var ErrConfiguration = errors.New("invalid shared PostgreSQL transport configuration")

type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// Settings contains public transport metadata only. The caller must authenticate
// the effective profile and CA bundle before using it. Proxy exceptions are not
// supported yet: every TLS connection requires SCRAM channel binding.
type Settings struct {
	Endpoints  []Endpoint
	Database   string
	DeviceRole string
	TLS        TLSMode
	Profile    vault.Profile
	CAPEM      []byte
	// TLSBundle is a native verified snapshot. Its high-water state must be
	// durably accepted before opening a session; never populate it from JSON.
	TLSBundle *VerifiedTLSBundle `json:"-"`
	// Changes is native deployment policy, persisted only in protected setup.
	Changes        ChangePolicy `json:"-"`
	deploymentLeaf *[32]byte
}

// Config builds a native-only pgx configuration without a password. Callers must
// keep it in Go, supply the derived device secret immediately before connecting,
// and never log driver errors or serialize the resulting configuration.
func Config(s Settings) (*pgconn.Config, error) {
	if s.TLSBundle != nil {
		return s.TLSBundle.Config(s)
	}
	roots, err := validateTransportSettings(s)
	if err != nil {
		return nil, err
	}
	// pgx must initialize its private parser marker. A constant DSN overrides
	// ambient connection/authentication choices; a nonempty dummy password stops
	// pgpass reads. PGSERVICE must be rejected before parsing (even an empty
	// service DSN option would attempt to load a service file).
	if os.Getenv("PGSERVICE") != "" {
		return nil, ErrConfiguration
	}
	c, err := pgconn.ParseConfig("host=127.0.0.1 port=5432 user=wormhole dbname=wormhole password=unused sslmode=disable sslrootcert='' sslcert='' sslkey='' sslpassword='' sslsni=1 connect_timeout=10 target_session_attrs=read-write sslcertmode=disable channel_binding=disable require_auth=scram-sha-256 sslnegotiation=postgres min_protocol_version=3.0 max_protocol_version=3.0")
	if err != nil {
		return nil, ErrConfiguration
	}
	c.Database, c.User, c.Password = s.Database, s.DeviceRole, ""
	c.RuntimeParams = map[string]string{"application_name": "wormhole", "search_path": "pg_catalog", "client_encoding": "UTF8"}
	c.MaxProtocolMessageBodyLen = maxProtocolBodyBytes
	c.ConnectTimeout = 10 * time.Second
	c.Fallbacks = nil
	query := readWriteQuery
	if s.Profile != vault.Default {
		query = privateReadWriteQuery
	}
	c.ValidateConnect = func(ctx context.Context, conn *pgconn.PgConn) error {
		return validateServerState(ctx, conn, query)
	}
	if s.TLS != TLSOff {
		c.ChannelBinding = "require"
	}
	for i, endpoint := range s.Endpoints {
		var tc *tls.Config
		if s.TLS != TLSOff {
			tc = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Host, RootCAs: roots, InsecureSkipVerify: s.TLS == TLSEncrypted} // Explicit encrypted-only mode; SCRAM channel binding remains mandatory.
			if pin := s.deploymentLeaf; pin != nil {
				tc.VerifyConnection = func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != *pin {
						return ErrServerCertificate
					}
					return nil
				}
			}
		}
		if i == 0 {
			c.Host, c.Port, c.TLSConfig = endpoint.Host, endpoint.Port, tc
		} else {
			c.Fallbacks = append(c.Fallbacks, &pgconn.FallbackConfig{Host: endpoint.Host, Port: endpoint.Port, TLSConfig: tc})
		}
	}
	return c, nil
}

// validateTransportSettings performs no I/O and ignores ambient driver settings.
func validateTransportSettings(s Settings) (*x509.CertPool, error) {
	if len(s.Endpoints) == 0 || len(s.Endpoints) > 8 || !identifier(s.Database) || !identifier(s.DeviceRole) {
		return nil, ErrConfiguration
	}
	switch s.Profile {
	case vault.Default:
	case vault.Standard, vault.Hardened, vault.Paranoid:
		if s.TLS != TLSVerified {
			return nil, ErrConfiguration
		}
	default:
		return nil, ErrConfiguration
	}
	var roots *x509.CertPool
	switch s.TLS {
	case TLSOff, TLSEncrypted:
		if len(s.CAPEM) != 0 {
			return nil, ErrConfiguration
		}
	case TLSVerified:
		if len(s.CAPEM) == 0 || len(s.CAPEM) > 256*1024 {
			return nil, ErrConfiguration
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(s.CAPEM) {
			return nil, ErrConfiguration
		}
	default:
		return nil, ErrConfiguration
	}
	seen := make(map[Endpoint]bool)
	for _, endpoint := range s.Endpoints {
		if !hostname(endpoint.Host) || endpoint.Port == 0 || seen[endpoint] {
			return nil, ErrConfiguration
		}
		seen[endpoint] = true
	}
	return roots, nil
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func hostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
