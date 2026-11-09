package ikev1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestFortinetProposalMatrix(t *testing.T) {
	for _, mode := range []Mode{ModeMain, ModeAggressive} {
		for _, encryption := range []uint16{7, 5} {
			for _, hash := range []uint16{1, 2, 4, 5, 6} {
				t.Run(fmt.Sprintf("%d-%d-%d", mode, encryption, hash), func(t *testing.T) {
					init, resp := remoteAccessConfigs("alice", "password", []byte("group-secret"))
					init.Mode = mode
					resp.Mode = mode
					resp.PSK = []byte("group-secret")
					p := Proposal{Encryption: encryption, KeyBits: 256, Hash: hash}
					espHash := hash
					if hash >= 4 {
						espHash++
					}
					for _, cfg := range []*Config{&init, &resp} {
						cfg.Proposals = []Proposal{p}
						p2 := p
						p2.Hash = espHash
						cfg.ESPProposals = []Proposal{p2}
						cfg.Groups = []uint16{2}
						cfg.Lifetime = 2800
						cfg.ESPLifetime = 3600
						cfg.PFS = 19
					}
					pair := newPair(t, init, resp)
					defer pair.initiator.Close()
					defer pair.responder.Close()
					pair.run(t)
					if pair.initErr != nil || pair.respErr != nil || pair.initRes == nil {
						t.Fatalf("handshake failed: %v / %v", pair.initErr, pair.respErr)
					}
					mirror(t, "outbound encryption", pair.initRes.OutEncKey, pair.respRes.InEncKey)
					mirror(t, "outbound integrity", pair.initRes.OutIntegKey, pair.respRes.InIntegKey)
					if len(pair.initiator.qmShared) == 0 {
						t.Fatal("PFS was not performed")
					}
				})
			}
		}
	}
}

func TestFortinetCertificateHandshake(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn.test"}, DNSNames: []string{"vpn.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	pairCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, mode := range []Mode{ModeMain, ModeAggressive} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			init, resp := remoteAccessConfigs("alice", "password", nil)
			for _, cfg := range []*Config{&init, &resp} {
				cfg.Mode = mode
				cfg.Certificate = pairCert
				cfg.RootCAs = roots
			}
			pair := newPair(t, init, resp)
			defer pair.initiator.Close()
			defer pair.responder.Close()
			pair.run(t)
			if pair.initErr != nil || pair.respErr != nil || pair.initRes == nil {
				t.Fatalf("certificate handshake failed: %v / %v", pair.initErr, pair.respErr)
			}
			mirror(t, "certificate keys", pair.initRes.OutEncKey, pair.respRes.InEncKey)
		})
	}
}

func TestFortinetAESKeySizes(t *testing.T) {
	for _, bits := range []uint16{128, 192} {
		init, resp := remoteAccessConfigs("alice", "password", []byte("secret"))
		for _, cfg := range []*Config{&init, &resp} {
			cfg.Proposals = []Proposal{{Encryption: 7, KeyBits: bits, Hash: 2}}
			cfg.ESPProposals = []Proposal{{Encryption: 7, KeyBits: bits, Hash: 2}}
			cfg.Groups = []uint16{14}
		}
		pair := newPair(t, init, resp)
		defer pair.initiator.Close()
		defer pair.responder.Close()
		pair.run(t)
		if pair.initErr != nil || pair.respErr != nil || pair.initRes == nil {
			t.Fatal("AES handshake failed", pair.initErr, pair.respErr)
		}
		if len(pair.initRes.OutEncKey) != int(bits/8) {
			t.Fatal("incorrect AES key size")
		}
	}
}

func TestFortinetVolumeOnlyProposal(t *testing.T) {
	p := espProposal{transformID: espTransform3DES, keyBits: 192, authAlg: authHMACSHA, encap: encapUDPTunnel, lifeKb: 5120}
	attrs, err := parseAttrs(p.attrs())
	if err != nil {
		t.Fatal(err)
	}
	life, ok := basicAttrOf(attrs, ipsecAttrLifeType)
	if !ok || life != 2 {
		t.Fatal("volume-only proposal enabled a time lifetime")
	}
	if _, ok := findAttr(attrs, ipsecAttrKeyLength); ok {
		t.Fatal("fixed-size 3DES carried a key length attribute")
	}
}
