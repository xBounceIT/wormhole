package ipsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestFortinetCertificateConfiguration(t *testing.T) {
	for _, version := range []int{1, 2} {
		options := DefaultFortinetOptions()
		options.UserAuth = 3
		options.IkeVersion = version
		if version == 2 {
			options.AuthMethod = 1
		}
		if _, err := ConfigureFortinet(Config{}, options, "", "", ""); err == nil {
			t.Fatal("invalid SAML authentication combination accepted")
		}
	}
	auto := DefaultFortinetOptions()
	auto.AutoProposals = true
	cfg, err := ConfigureFortinet(Config{}, auto, "", "", "")
	if err != nil || len(cfg.IKECipherSuites) != 0 || len(cfg.DHGroups) != 0 {
		t.Fatal("legacy automatic proposals were restricted", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, kind := range []string{"dns", "email", "dn", "ecdsa"} {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if kind == "dns" {
			template.DNSNames = []string{"client.test"}
		}
		if kind == "email" {
			template.EmailAddresses = []string{"user@example.test"}
		}
		var key any = rsaKey
		var public any = &rsaKey.PublicKey
		if kind == "ecdsa" {
			key = ecKey
			public = &ecKey.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
		if err != nil {
			t.Fatal(err)
		}
		private, _ := x509.MarshalPKCS8PrivateKey(key)
		cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		secret := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		options := DefaultFortinetOptions()
		options.AuthMethod = 1
		cfg, err := ConfigureFortinet(Config{}, options, cert, secret, cert)
		if err != nil || cfg.ClientCertificate == nil || cfg.LocalID.IsZero() || cfg.RootCAs == nil {
			t.Fatal("certificate configuration invalid", err)
		}
		if err := cfg.LocalID.check(); err != nil {
			t.Fatal(err)
		}
		mixed := cfg
		mixed.PSK = "secret"
		if mixed.validate() == nil {
			t.Fatal("ambiguous certificate/PSK authentication accepted")
		}
		mixed.PSK = ""
		mixed.EAP = EAPMSCHAPv2{Username: "user", Password: "password"}
		if mixed.validate() == nil {
			t.Fatal("ambiguous certificate/EAP authentication accepted")
		}
		if _, err := ConfigureFortinet(Config{}, options, cert, secret, "invalid"); err == nil {
			t.Fatal("invalid CA accepted")
		}
		options.UserAuth = 2
		if configured, err := ConfigureFortinet(Config{}, options, cert, secret, ""); err != nil || !configured.FortinetSAML {
			t.Fatal("certificate EAP configuration rejected", err)
		}
		options.IkeVersion = 1
		_, err = ConfigureFortinet(Config{}, options, cert, secret, "")
		if (err != nil) != (kind == "ecdsa") {
			t.Fatal("incorrect IKEv1 certificate validation", err)
		}
	}
	var options FortinetOptions
	if err := json.Unmarshal([]byte(`{"IkeVersion":1,"Phase1Encryption":3}`), &options); err != nil || options.NatTraversal != true || options.Phase1Encryption != 3 {
		t.Fatal("profile defaults lost")
	}
	if json.Unmarshal([]byte(`{"IkeVersion":"bad"}`), &options) == nil {
		t.Fatal("invalid profile accepted")
	}
}
