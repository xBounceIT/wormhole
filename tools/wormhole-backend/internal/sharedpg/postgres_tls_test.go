package sharedpg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func postgresFixtureCSR(t *testing.T, data string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(data, "server.key"))
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	block, _ := pem.Decode(raw)
	clear(raw)
	if block == nil {
		t.Fatal("fixture key is invalid")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	key, ok := private.(crypto.Signer)
	if err != nil || !ok {
		t.Fatal("fixture key could not be opened")
	}
	return serverRequest(t, key, nil)
}

// This synthetic server identity exists only in the disposable test cluster.
// It is never reused for application trust or user credentials.
func postgresTestCertificate(t *testing.T, data string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(encoded)
	if err := os.WriteFile(filepath.Join(data, "server.crt"), certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "server.key"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return certificate
}
