package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func tlsTrustFixture(t *testing.T) (TLSTrustBundle, TLSTrustPin, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := serverIssuer(t, nil)
	b := TLSTrustBundle{FormatVersion: 1, WorkspaceID: uuid.New(), Signer: vault.KeyRef{ID: uuid.New(), Version: 1}, Sequence: 1, CAs: [][]byte{ca}, Hosts: []string{"127.0.0.1", "db.example.test"}, Revoked: []TLSRevocation{}}
	signed, err := SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, TLSTrustPin{WorkspaceID: b.WorkspaceID, Signer: b.Signer, Organisation: pub, MinimumSequence: 1}, key
}

func TestTLSTrustSignatureSnapshotAndRollback(t *testing.T) {
	b, pin, key := tlsTrustFixture(t)
	v, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	raw := v.Encode()
	decoded, err := DecodeTLSTrustBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTLSTrustBundle(decoded, pin); err != nil {
		t.Fatal(err)
	}
	decoded.Hosts[1] = "evil.test"
	if _, err := VerifyTLSTrustBundle(decoded, pin); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("tamper", err)
	}
	// Caller mutation of original input, pin, and exported bytes cannot affect v.
	b.CAs[0][0] ^= 1
	b.Hosts[0] = "evil.test"
	pin.Organisation[0] ^= 1
	raw[0] ^= 1
	current, err := DecodeTLSTrustBundle(v.Encode())
	if err != nil {
		t.Fatal("snapshot aliased", err)
	}
	if _, err := v.Advance(current); err != nil {
		t.Fatal("idempotent", err)
	}
	current.Hosts = []string{"db.example.test"}
	same, err := SignTLSTrustBundle(current, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Advance(same); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("equivocation", err)
	}
	current.Sequence++
	next, err := SignTLSTrustBundle(current, key)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := v.Advance(next)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := DecodeTLSTrustBundle(v.Encode())
	if _, err := advanced.Advance(old); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("rollback", err)
	}
	if advanced.pin.MinimumSequence != 2 || len(advanced.pin.Digest) != 32 {
		t.Fatal("floor not advanced")
	}
	exported := advanced.Pin()
	exported.Digest[0] ^= 1
	exported.Organisation[0] ^= 1
	if _, err := advanced.Advance(next); err != nil {
		t.Fatal("exported pin aliased", err)
	}
	var nilBundle *VerifiedTLSBundle
	if nilBundle.Pin().MinimumSequence != 0 {
		t.Fatal("nil pin")
	}
	if nilBundle.Encode() != nil {
		t.Fatal("nil encode")
	}
	if _, err := nilBundle.Advance(next); err == nil {
		t.Fatal("nil advance")
	}
	if _, err := (&VerifiedTLSBundle{}).Advance(next); err == nil {
		t.Fatal("zero advance")
	}
}

func TestTLSTrustRejectsInvalidDocuments(t *testing.T) {
	b, _, key := tlsTrustFixture(t)
	mutations := map[string]func(*TLSTrustBundle){
		"future format":     func(b *TLSTrustBundle) { b.FormatVersion = 3 },
		"missing CA state":  func(b *TLSTrustBundle) { b.FormatVersion = 2 },
		"old format":        func(b *TLSTrustBundle) { b.FormatVersion = 0 },
		"workspace":         func(b *TLSTrustBundle) { b.WorkspaceID = uuid.Nil },
		"signer":            func(b *TLSTrustBundle) { b.Signer.ID = uuid.Nil },
		"key version":       func(b *TLSTrustBundle) { b.Signer.Version = math.MaxUint32 },
		"zero sequence":     func(b *TLSTrustBundle) { b.Sequence = 0 },
		"sequence overflow": func(b *TLSTrustBundle) { b.Sequence = math.MaxUint64 },
		"no CA":             func(b *TLSTrustBundle) { b.CAs = nil },
		"too many CA":       func(b *TLSTrustBundle) { b.CAs = make([][]byte, 9) },
		"bad CA":            func(b *TLSTrustBundle) { b.CAs = [][]byte{{1}} },
		"large CA":          func(b *TLSTrustBundle) { b.CAs = [][]byte{make([]byte, 32769)} },
		"duplicate CA":      func(b *TLSTrustBundle) { b.CAs = [][]byte{b.CAs[0], b.CAs[0]} },
		"no hosts":          func(b *TLSTrustBundle) { b.Hosts = nil },
		"bad host":          func(b *TLSTrustBundle) { b.Hosts = []string{"*.test"} },
		"host case":         func(b *TLSTrustBundle) { b.Hosts = []string{"DB.example.test"} },
		"host order":        func(b *TLSTrustBundle) { b.Hosts = []string{"z.test", "a.test"} },
		"duplicate host":    func(b *TLSTrustBundle) { b.Hosts = []string{"a.test", "a.test"} },
		"IP alias":          func(b *TLSTrustBundle) { b.Hosts = []string{"::ffff:127.0.0.1"} },
		"null revocations":  func(b *TLSTrustBundle) { b.Revoked = nil },
		"many revocations":  func(b *TLSTrustBundle) { b.Revoked = make([]TLSRevocation, 4097) },
		"bad issuer":        func(b *TLSTrustBundle) { b.Revoked = []TLSRevocation{{IssuerSPKI: "bad", Serial: "1"}} },
		"nonhex issuer": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("g", 64), Serial: "1"}}
		},
		"issuer case": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("A", 64), Serial: "1"}}
		},
		"zero serial": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("a", 64), Serial: "0"}}
		},
		"leading zero": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("a", 64), Serial: "01"}}
		},
		"negative serial": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("a", 64), Serial: "-1"}}
		},
		"serial case": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("a", 64), Serial: "A"}}
		},
		"serial overflow": func(b *TLSTrustBundle) {
			b.Revoked = []TLSRevocation{{IssuerSPKI: strings.Repeat("a", 64), Serial: strings.Repeat("f", 41)}}
		},
		"duplicate revocation": func(b *TLSTrustBundle) {
			r := TLSRevocation{IssuerSPKI: strings.Repeat("a", 64), Serial: "1"}
			b.Revoked = []TLSRevocation{r, r}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := EncodeTLSTrustBundle(b)
			bad, _ := DecodeTLSTrustBundle(raw)
			mutate(&bad)
			if _, err := SignTLSTrustBundle(bad, key); err == nil {
				t.Fatal("signed invalid bundle")
			}
		})
	}
	if _, err := SignTLSTrustBundle(b, nil); err == nil {
		t.Fatal("bad signing key")
	}
	b.Signature = nil
	if _, err := EncodeTLSTrustBundle(b); err == nil {
		t.Fatal("missing signature")
	}
}

func TestTLSTrustPinAndCanonicalCodec(t *testing.T) {
	b, pin, _ := tlsTrustFixture(t)
	for _, mutate := range []func(*TLSTrustPin){
		func(p *TLSTrustPin) { p.WorkspaceID = uuid.Nil }, func(p *TLSTrustPin) { p.WorkspaceID = uuid.New() },
		func(p *TLSTrustPin) { p.Signer.ID = uuid.New() }, func(p *TLSTrustPin) { p.Signer.Version = 0 },
		func(p *TLSTrustPin) { p.Organisation = nil }, func(p *TLSTrustPin) { p.Organisation = make([]byte, 32) },
		func(p *TLSTrustPin) { p.MinimumSequence = 0 }, func(p *TLSTrustPin) { p.MinimumSequence = 2 },
		func(p *TLSTrustPin) { p.Digest = []byte{1} }, func(p *TLSTrustPin) { p.Digest = make([]byte, 32) },
	} {
		bad := pin
		mutate(&bad)
		if _, err := VerifyTLSTrustBundle(b, bad); err == nil {
			t.Fatal("bad pin")
		}
	}
	raw, _ := EncodeTLSTrustBundle(b)
	for _, bad := range [][]byte{nil, []byte("{"), make([]byte, MaxTLSTrustBundleBytes+1), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...), bytes.Replace(raw, []byte("{\"formatVersion\":"), []byte("{\"unknown\":1,\"formatVersion\":"), 1), bytes.Replace(raw, []byte("{\"formatVersion\":"), []byte("{\"sequence\":1,\"formatVersion\":"), 1)} {
		if _, err := DecodeTLSTrustBundle(bad); err == nil {
			t.Fatal("noncanonical input accepted")
		}
	}
	bad := b
	bad.FormatVersion = 3
	encoded, _ := json.Marshal(bad)
	if _, err := DecodeTLSTrustBundle(encoded); !errors.Is(err, vault.ErrNewerFormat) {
		t.Fatal("future format", err)
	}
	if _, err := VerifyTLSTrustBundle(bad, pin); !errors.Is(err, vault.ErrNewerFormat) {
		t.Fatal("future verify", err)
	}
}

func TestTLSTrustConfigAndRealHandshake(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	b, pin, key := tlsTrustFixture(t)
	ca, signer := serverIssuer(t, nil)
	b.CAs = [][]byte{ca}
	csr := serverRequest(t, signer, nil)
	leafPEM, err := IssueWorkspaceServerCertificate(ca, signer, csr, b.Hosts, serverCertNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	issuer, _ := x509.ParseCertificate(ca)
	b, err = SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = TLSVerified
	backing := bytes.Repeat([]byte{0x7f}, 4096)
	s.CAPEM = backing[:0]
	s.Endpoints = []Endpoint{{Host: "DB.EXAMPLE.TEST", Port: 5432}, {Host: "127.0.0.1", Port: 5433}}
	c, err := v.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	if s.Endpoints[0].Host != "DB.EXAMPLE.TEST" || c.Host != "db.example.test" || c.ChannelBinding != "require" || c.TLSConfig.InsecureSkipVerify {
		t.Fatal("config policy or caller mutation")
	}
	if !bytes.Equal(backing, bytes.Repeat([]byte{0x7f}, len(backing))) {
		t.Fatal("caller CA buffer overwritten")
	}
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: signer}}, MinVersion: tls.VersionTLS12, Time: func() time.Time { return serverCertNow }}
	for _, tc := range []*tls.Config{c.TLSConfig, c.Fallbacks[0].TLSConfig} {
		tc.Time = func() time.Time { return serverCertNow }
		if err := tlsTrustHandshake(tc, server); err != nil {
			t.Fatal("real handshake", err)
		}
		if tc.VerifyConnection(tls.ConnectionState{}) == nil || tc.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}) == nil {
			t.Fatal("unverified chain accepted")
		}
	}
	fingerprint := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	b.Sequence++
	b.Revoked = []TLSRevocation{{IssuerSPKI: hex.EncodeToString(fingerprint[:]), Serial: leaf.SerialNumber.Text(16)}}
	b, err = SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := v.Advance(b)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := revoked.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []*tls.Config{rc.TLSConfig, rc.Fallbacks[0].TLSConfig} {
		tc.Time = func() time.Time { return serverCertNow }
		if err := tlsTrustHandshake(tc, server); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("revoked certificate did not fail at revocation check", err)
		}
	}
	// Renewing an issuer certificate without changing its key cannot erase a
	// serial revocation. Certificate fingerprints would incorrectly allow this.
	renewedTemplate := *issuer
	renewedTemplate.SerialNumber = big.NewInt(99)
	renewedDER, err := x509.CreateCertificate(rand.Reader, &renewedTemplate, &renewedTemplate, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	b.Sequence++
	b.CAs = [][]byte{renewedDER}
	b, err = SignTLSTrustBundle(b, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := revoked.Advance(b)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := renewed.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	nc.TLSConfig.Time = func() time.Time { return serverCertNow }
	if err := tlsTrustHandshake(nc.TLSConfig, server); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("renewal bypassed revocation", err)
	}
	// The same serial under another issuer is not this certificate's revocation.
	b.Sequence++
	b.Revoked[0].IssuerSPKI = strings.Repeat("a", 64)
	b, _ = SignTLSTrustBundle(b, key)
	other, _ := revoked.Advance(b)
	oc, err := other.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	oc.TLSConfig.Time = func() time.Time { return serverCertNow }
	if err := tlsTrustHandshake(oc.TLSConfig, server); err != nil {
		t.Fatal("wrong issuer matched", err)
	}
	for _, mutate := range []func(*Settings){
		func(s *Settings) { s.TLS = TLSOff }, func(s *Settings) { s.CAPEM = ca },
		func(s *Settings) { s.Endpoints = nil }, func(s *Settings) { s.Database = "" },
		func(s *Settings) { s.Endpoints = make([]Endpoint, 9) },
		func(s *Settings) { s.Endpoints = []Endpoint{{"child.db.example.test", 5432}} },
		func(s *Settings) { s.Endpoints = []Endpoint{{"evil.test", 5432}} },
		func(s *Settings) { s.Endpoints = []Endpoint{{"*.test", 5432}} },
	} {
		bad := s
		mutate(&bad)
		if _, err := v.Config(bad); err == nil {
			t.Fatal("bad settings")
		}
	}
	if _, err := (*VerifiedTLSBundle)(nil).Config(s); err == nil {
		t.Fatal("nil config")
	}
	if _, err := (&VerifiedTLSBundle{}).Config(s); err == nil {
		t.Fatal("zero config")
	}
	// An externally supplied CA cannot authorize an Ed25519 server certificate.
	pub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(10), NotBefore: serverCertNow, NotAfter: serverCertNow.Add(time.Hour), DNSNames: []string{"db.example.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	server.Certificates = []tls.Certificate{{Certificate: [][]byte{edDER}, PrivateKey: edKey}}
	if err := tlsTrustHandshake(c.TLSConfig, server); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("Ed25519 server did not fail at key policy check", err)
	}
}

func TestTLSTrustCARotationWithoutRepinning(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	b, pin, org := tlsTrustFixture(t)
	ca1, key1 := serverIssuer(t, nil)
	ca2, key2 := serverIssuer(t, nil)
	b.CAs = [][]byte{ca1}
	b, _ = SignTLSTrustBundle(b, org)
	v, err := VerifyTLSTrustBundle(b, pin)
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := IssueWorkspaceServerCertificate(ca1, key1, serverRequest(t, key1, nil), b.Hosts, serverCertNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := IssueWorkspaceServerCertificate(ca2, key2, serverRequest(t, key2, nil), b.Hosts, serverCertNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block1, _ := pem.Decode(leaf1)
	block2, _ := pem.Decode(leaf2)
	servers := []*tls.Config{
		{Certificates: []tls.Certificate{{Certificate: [][]byte{block1.Bytes}, PrivateKey: key1}}, MinVersion: tls.VersionTLS12},
		{Certificates: []tls.Certificate{{Certificate: [][]byte{block2.Bytes}, PrivateKey: key2}}, MinVersion: tls.VersionTLS12},
	}
	s := settings()
	s.TLS = TLSVerified
	s.Endpoints = []Endpoint{{"db.example.test", 5432}}
	b.Sequence++
	b.CAs = [][]byte{ca1, ca2}
	sort.Slice(b.CAs, func(i, j int) bool { return bytes.Compare(b.CAs[i], b.CAs[j]) < 0 })
	b, err = SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	overlap, err := v.Advance(b)
	if err != nil {
		t.Fatal(err)
	}
	c, err := overlap.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSConfig.Time = func() time.Time { return serverCertNow }
	for _, server := range servers {
		if err := tlsTrustHandshake(c.TLSConfig, server); err != nil {
			t.Fatal("rotation overlap", err)
		}
	}
	b.Sequence++
	b.CAs = [][]byte{ca2}
	b, err = SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := overlap.Advance(b)
	if err != nil {
		t.Fatal(err)
	}
	c, err = rotated.Config(s)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSConfig.Time = func() time.Time { return serverCertNow }
	if err := tlsTrustHandshake(c.TLSConfig, servers[1]); err != nil {
		t.Fatal("rotated CA", err)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if err := tlsTrustHandshake(c.TLSConfig, servers[0]); !errors.As(err, &unknownAuthority) {
		t.Fatal("removed CA did not fail chain verification", err)
	}
	if rotated.Pin().Signer != pin.Signer || !bytes.Equal(rotated.Pin().Organisation, pin.Organisation) {
		t.Fatal("rotation changed organisation pin")
	}
	if _, err := rotated.Advance(v.bundle); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("old CA bundle replay", err)
	}
}

func tlsTrustHandshake(client, server *tls.Config) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		b, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer b.Close()
		_ = b.SetDeadline(time.Now().Add(5 * time.Second))
		done <- tls.Server(b, server).Handshake()
	}()
	a, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		return err
	}
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	err = tls.Client(a, client).Handshake()
	_ = a.Close()
	serverErr := <-done
	if err != nil {
		return err
	}
	return serverErr
}
