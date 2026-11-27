package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVerifiedTLSBundleFlowsThroughNativeConnect(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	b, pin, _ := tlsTrustFixture(t)
	v, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = TLSVerified
	s.TLSBundle = v
	var captured *pgconn.Config
	marker := new(pgconn.PgConn)
	got, err := connect(context.Background(), s, []byte("native-secret"), func(_ context.Context, c *pgconn.Config) (*pgconn.PgConn, error) {
		captured = c
		if c.TLSConfig.VerifyConnection == nil || c.Fallbacks[0].TLSConfig.VerifyConnection == nil || c.TLSConfig.InsecureSkipVerify || c.ChannelBinding != "require" || c.Password != "native-secret" {
			t.Fatal("verified transport bypassed")
		}
		return marker, nil
	})
	if err != nil || got != marker || captured.Password != "" {
		t.Fatal("connection ownership", err)
	}
	encoded, err := json.Marshal(s)
	if err != nil || bytes.Contains(encoded, []byte("TLSBundle")) {
		t.Fatal("native bundle serialized")
	}
	never := func(context.Context, *pgconn.Config) (*pgconn.PgConn, error) {
		t.Fatal("dial before validation")
		return nil, nil
	}
	for _, mutate := range []func(*Settings){
		func(s *Settings) { s.TLSBundle = &VerifiedTLSBundle{} },
		func(s *Settings) { s.Endpoints = []Endpoint{{"evil.test", 5432}} },
		func(s *Settings) { s.TLS = TLSEncrypted },
		func(s *Settings) { s.CAPEM = testCA(t) },
	} {
		bad := s
		mutate(&bad)
		if _, err := connect(context.Background(), bad, []byte("native-secret"), never); err != ErrConfiguration {
			t.Fatal("invalid bundle transport", err)
		}
	}
	other, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSBundle = other
	if _, err := v.Config(s); err != ErrConfiguration {
		t.Fatal("ambiguous bundle accepted")
	}
}

func TestCachedPolicyBindsTLSBundleToOrganisation(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	_, _, old, a, r, org := trustFixture(t)
	signer := vault.KeyRef{ID: uuid.New(), Version: old.SignerKeyVersion}
	signed, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed, err = vault.SignPolicy(signed.Policy, signer.ID.String(), signer.Version, org)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewTrustState(a, r, PolicyTrust{WorkspaceID: r.WorkspaceID, SignerKeyID: signer.ID.String(), SignerKeyVersion: signer.Version, PublicKey: old.PublicKey, MinimumSequence: old.PolicySequence})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := tlsTrustFixture(t)
	b.WorkspaceID = state.WorkspaceID
	b.Signer = signer
	b, err = SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	pin := TLSTrustPin{WorkspaceID: state.WorkspaceID, Signer: signer, Organisation: state.PublicKey, MinimumSequence: 1}
	v, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = TLSVerified
	s.TLSBundle = v
	prepared, err := state.PrepareTransport(s, vault.Default, vault.Default, 1)
	if err != nil || prepared.TLSBundle != v || prepared.Profile != vault.Standard {
		t.Fatal("bundle lost in preflight", err)
	}
	if _, err := Config(prepared); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TLSTrustBundle){
		func(b *TLSTrustBundle) { b.WorkspaceID = uuid.New() },
		func(b *TLSTrustBundle) { b.Signer.ID = uuid.New() },
		func(b *TLSTrustBundle) { b.Signer.Version++ },
	} {
		foreign := b
		mutate(&foreign)
		foreign, err = SignTLSTrustBundle(foreign, org)
		if err != nil {
			t.Fatal(err)
		}
		foreignPin := pin
		foreignPin.WorkspaceID = foreign.WorkspaceID
		foreignPin.Signer = foreign.Signer
		s.TLSBundle, err = VerifyTLSTrustBundle(foreign, foreignPin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.PrepareTransport(s, vault.Default, vault.Default, 1); err != ErrConfiguration {
			t.Fatal("foreign identity accepted", err)
		}
	}
	_, differentPin, differentKey := tlsTrustFixture(t)
	different, err := SignTLSTrustBundle(b, differentKey)
	if err != nil {
		t.Fatal(err)
	}
	pin.Organisation = differentPin.Organisation
	s.TLSBundle, err = VerifyTLSTrustBundle(different, pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PrepareTransport(s, vault.Default, vault.Default, 1); err != ErrConfiguration {
		t.Fatal("foreign organisation accepted", err)
	}
}

func TestPostgresVerifiedBundleSessionTransport(t *testing.T) {
	s, secret := postgresTestClusterTLS(t, true)
	b, pin, key := tlsTrustFixture(t)
	block, _ := pem.Decode(s.CAPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	b.CAs = [][]byte{block.Bytes}
	b.Hosts = []string{"127.0.0.1"}
	b, err = SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	s.CAPEM = nil
	s.TLSBundle, err = VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner := NewSession()
	defer owner.Close(context.Background())
	if err := owner.Open(ctx, s, secret, ChangePolicy{}); err != nil {
		t.Fatal(err)
	}
	for _, slot := range owner.slots {
		conn, ok := slot.conn.(*pgconn.PgConn)
		if !ok {
			t.Fatal("missing query/notification connection")
		}
		result, err := conn.Exec(ctx, "SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()").ReadAll()
		if err != nil || len(result) != 1 || len(result[0].Rows) != 1 || string(result[0].Rows[0][0]) != "t" {
			t.Fatal("connection not TLS", err)
		}
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	b.Sequence++
	fingerprint := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	b.Revoked = []TLSRevocation{{IssuerSPKI: hex.EncodeToString(fingerprint[:]), Serial: cert.SerialNumber.Text(16)}}
	b, err = SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSBundle, err = s.TLSBundle.Advance(b)
	if err != nil {
		t.Fatal(err)
	}
	rejected := NewSession()
	defer rejected.Close(context.Background())
	if err := rejected.Open(ctx, s, secret, ChangePolicy{}); err != ErrConnection {
		t.Fatal("revoked TLS session opened", err)
	}
	if err := rejected.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
