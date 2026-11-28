package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceCAWrappedRoundTripAndIdentity(t *testing.T) {
	org, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := vault.KeyCopyBinding{WorkspaceID: uuid.New(), Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: vault.KeyRef{ID: uuid.New(), Version: 1}, Issuer: vault.KeyRef{ID: uuid.New(), Version: 1}}
	_, serverKey := serverIssuer(t, nil)
	for _, hosts := range [][]string{{"db.example.test", "127.0.0.1", "2001:db8::1"}, {"db.example.test"}, {"127.0.0.1"}} {
		ca, err := CreateWorkspaceCA(b, org.PublicKey().Bytes(), sign.Seed(), hosts, serverCertNow, serverCertNow.Add(2*365*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(ca.CertificateDER)
		if err != nil || !cert.IsCA || !cert.MaxPathLenZero || !cert.PermittedDNSDomainsCritical || cert.Subject.CommonName != b.WorkspaceID.String()+" server CA" {
			t.Fatal("CA constraints", err)
		}
		dns, ips, _ := serverCertificateNames(hosts)
		csr := serverRequest(t, serverKey, func(c *x509.CertificateRequest) { c.DNSNames = dns; c.IPAddresses = ips })
		out, err := ca.IssueServerCertificate(b, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour)
		if err != nil || len(out) == 0 {
			t.Fatal("issuance", err)
		}
		block, _ := pem.Decode(out)
		leaf, _ := x509.ParseCertificate(block.Bytes)
		for _, host := range hosts {
			if leaf.VerifyHostname(host) != nil {
				t.Fatal("host missing")
			}
		}
		encoded, err := json.Marshal(ca)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.OpenKeyCopy(org.Bytes(), b, ca.KeyCopy, pub)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(raw))) || bytes.Contains(encoded, []byte("PRIVATE KEY")) {
			t.Fatal("plaintext key export")
		}
		vault.Wipe(raw)
		var loaded WrappedWorkspaceCA
		if err := json.Unmarshal(encoded, &loaded); err != nil {
			t.Fatal(err)
		}
		if _, err := loaded.IssueServerCertificate(b, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour); err != nil {
			t.Fatal("reload", err)
		}
		foreign := b
		foreign.WorkspaceID = uuid.New()
		if _, err := ca.IssueServerCertificate(foreign, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("foreign workspace")
		}
		wrong := bytes.Repeat([]byte{42}, 32)
		if _, err := ca.IssueServerCertificate(b, wrong, pub, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("wrong organisation key")
		}
		if _, err := ca.IssueServerCertificate(b, org.Bytes(), ed25519.PublicKey(wrong), csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("wrong signing pin")
		}
		loaded.CertificateDER, _ = serverIssuer(t, nil)
		if _, err := loaded.IssueServerCertificate(b, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("substituted CA")
		}
		loaded = *ca
		loaded.KeyCopy.Signature = bytes.Clone(ca.KeyCopy.Signature)
		loaded.KeyCopy.Signature[0] ^= 1
		if _, err := loaded.IssueServerCertificate(b, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("tampered wrapped key")
		}
		loaded.KeyCopy, err = vault.SealKeyCopy(make([]byte, 32), b, org.PublicKey().Bytes(), sign.Seed())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loaded.IssueServerCertificate(b, org.Bytes(), pub, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("zero scalar")
		}
	}
	for _, test := range []struct {
		hosts        []string
		now, expires time.Time
	}{
		{nil, serverCertNow, serverCertNow.Add(time.Hour)},
		{[]string{"db.test"}, time.Time{}, serverCertNow},
		{[]string{"db.test"}, serverCertNow, serverCertNow},
		{[]string{"db.test"}, serverCertNow, serverCertNow.Add(-time.Hour)},
		{[]string{"db.test"}, serverCertNow, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if ca, err := CreateWorkspaceCA(b, org.PublicKey().Bytes(), sign.Seed(), test.hosts, test.now, test.expires); err == nil || ca != nil {
			t.Fatal("invalid creation arguments")
		}
	}
	if _, err := CreateWorkspaceCA(vault.KeyCopyBinding{}, org.PublicKey().Bytes(), sign.Seed(), []string{"db.test"}, serverCertNow, serverCertNow.Add(time.Hour)); err == nil {
		t.Fatal("invalid key binding")
	}
	var absent *WrappedWorkspaceCA
	if _, err := absent.IssueServerCertificate(b, org.Bytes(), pub, nil, nil, serverCertNow, time.Hour); err == nil {
		t.Fatal("nil CA")
	}
	wipeWorkspaceCAKey(serverKey)
	if serverKey.D.Sign() != 0 {
		t.Fatal("scalar not wiped")
	}
}
