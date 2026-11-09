package ipsec

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikev1"
)

// FortinetOptions is a public, secret-free profile. Credentials remain in Config.
type FortinetOptions struct {
	AutoProposals                                                                                                 bool
	AuthMethod, UserAuth, IkeVersion, ExchangeMode, AddressAssignment                                             int
	RemoteGateways, ManualAddress, ManualDns, DhGroups                                                            string
	Phase1Encryption, Phase1Authentication, Phase1Encryption2, Phase1Authentication2                              int
	Phase2Encryption, Phase2Authentication, Phase2Encryption2, Phase2Authentication2                              int
	Phase1Lifetime, Phase2Lifetime, Phase2LifetimeKb                                                              int
	DeadPeerDetection, NatTraversal, EnableLocalLan, Phase2TimeLifetime, Phase2ByteLifetime, ReplayDetection, Pfs bool
	PfsGroup                                                                                                      int
}

func DefaultFortinetOptions() FortinetOptions {
	return FortinetOptions{IkeVersion: 2, Phase1Encryption: 2, Phase1Authentication: 2, Phase1Encryption2: 2, Phase1Authentication2: 2, Phase2Encryption: 2, Phase2Authentication: 2, Phase2Encryption2: 2, Phase2Authentication2: 2, DhGroups: "14,19,20", Phase1Lifetime: 14400, Phase2Lifetime: 3600, Phase2LifetimeKb: 5120, DeadPeerDetection: true, NatTraversal: true, Phase2TimeLifetime: true, ReplayDetection: true, PfsGroup: 14}
}

func (o *FortinetOptions) UnmarshalJSON(raw []byte) error {
	type plain FortinetOptions
	defaults := plain(DefaultFortinetOptions())
	if err := json.Unmarshal(raw, &defaults); err != nil {
		return err
	}
	*o = FortinetOptions(defaults)
	return nil
}

type FortinetClient interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Resolver(string) *net.Resolver
	Close() error
}

// ConfigureFortinet translates only options the IKEv2 implementation can honor.
// IKEv1 uses its independently negotiated Phase 1 / Quick Mode proposals.
func ConfigureFortinet(c Config, o FortinetOptions, certPEM, keyPEM, caPEM string) (Config, error) {
	if o.UserAuth == 3 && (o.AuthMethod != 0 || o.IkeVersion != 2) {
		return c, errors.New("SAML requires IKEv2 and a gateway PSK")
	}
	if o.AuthMethod < 0 || o.AuthMethod > 1 || o.UserAuth < 0 || o.UserAuth > 3 || o.IkeVersion < 1 || o.IkeVersion > 2 || o.ExchangeMode < 0 || o.ExchangeMode > 1 || o.AddressAssignment < 0 || o.AddressAssignment > 2 {
		return c, errors.New("invalid IPsec authentication or VPN mode")
	}
	for _, p := range [][2]int{{o.Phase1Encryption, o.Phase1Authentication}, {o.Phase1Encryption2, o.Phase1Authentication2}, {o.Phase2Encryption, o.Phase2Authentication}, {o.Phase2Encryption2, o.Phase2Authentication2}} {
		if p[0] < 0 || p[0] > 3 || p[1] < 0 || p[1] > 4 {
			return c, errors.New("invalid IPsec proposal")
		}
	}
	if o.Phase1Lifetime < 1 || o.Phase2Lifetime < 1 || o.Phase2LifetimeKb < 1 {
		return c, errors.New("invalid IPsec key lifetime")
	}
	c.FortinetOptions = &o
	if o.AuthMethod == 1 {
		pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return c, errors.New("invalid IPsec client certificate or key")
		}
		c.ClientCertificate = &pair
		if caPEM != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(caPEM)) {
				return c, errors.New("invalid IPsec CA certificate")
			}
			c.RootCAs = pool
		}
		c.PSK = ""
		c.ServerPSK = ""
		c.FortinetSAML = false
		if o.UserAuth != 0 && o.IkeVersion != 1 {
			return c, errors.New("client certificate authentication currently requires user authentication disabled")
		}
		if o.IkeVersion == 1 {
			if _, ok := pair.PrivateKey.(*rsa.PrivateKey); !ok {
				return c, errors.New("IKEv1 requires an RSA client certificate")
			}
		}
		if c.LocalID.IsZero() {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return c, errors.New("invalid IPsec client certificate")
			}
			if len(leaf.DNSNames) > 0 {
				c.LocalID = FQDN(leaf.DNSNames[0])
			} else if len(leaf.EmailAddresses) > 0 {
				c.LocalID = Email(leaf.EmailAddresses[0])
			} else {
				c.LocalID = Identity{Kind: 9, Data: leaf.RawSubject}
			}
		}
	}
	if o.IkeVersion == 1 {
		return c, nil
	}
	if o.AddressAssignment == 2 {
		return c, errors.New("DHCP over IPsec requires IKEv1")
	}
	if !o.AutoProposals {
		groups, err := fortinetGroups(o.DhGroups)
		if err != nil {
			return c, err
		}
		for _, group := range groups {
			if group != 14 && group != 19 && group != 20 {
				return c, errors.New("IKEv2 supports DH groups 14, 19 and 20; select IKEv1 for other groups")
			}
		}
		c.DHGroups = groups
		// These checks prevent accepting a profile while silently using other transforms.
		for _, phase := range [][4]int{{o.Phase1Encryption, o.Phase1Authentication, o.Phase1Encryption2, o.Phase1Authentication2}, {o.Phase2Encryption, o.Phase2Authentication, o.Phase2Encryption2, o.Phase2Authentication2}} {
			if phase[0] != 2 || phase[1] != 2 || phase[2] != 2 || phase[3] != 2 {
				return c, errors.New("this IKEv2 engine currently requires AES-256 / SHA-256 proposals; select IKEv1 for legacy proposals")
			}
		}
		c.IKECipherSuites = []CipherSuite{CipherSuiteAESCBC256SHA256}
		c.ESPCipherSuites = []CipherSuite{CipherSuiteAESCBC256SHA256}
	}
	c.IKERekeyLifetime = time.Duration(o.Phase1Lifetime) * time.Second
	c.RekeyLifetime = time.Duration(o.Phase2Lifetime) * time.Second
	c.ChildSAPFS = o.Pfs
	c.DisableDPD = !o.DeadPeerDetection
	if o.Pfs && o.PfsGroup != 14 {
		return c, errors.New("this IKEv2 engine requires PFS group 14")
	}
	if !o.ReplayDetection || !o.NatTraversal || o.Phase2ByteLifetime || !o.Phase2TimeLifetime || o.EnableLocalLan || o.AddressAssignment != 0 {
		return c, errors.New("this IKEv2 engine cannot honor the selected routing, lifetime or replay options")
	}
	return c, nil
}

func fortinetGroups(value string) ([]uint16, error) {
	if value == "" {
		return []uint16{14}, nil
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, part := range strings.Split(value, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || !(n == 1 || n == 2 || n == 5 || n >= 14 && n <= 21) || seen[uint16(n)] {
			return nil, errors.New("invalid IPsec DH groups")
		}
		out = append(out, uint16(n))
		seen[uint16(n)] = true
	}
	return out, nil
}

func fortinetProposal(encryption, authentication int, esp bool) ikev1.Proposal {
	p := ikev1.Proposal{Encryption: 7, KeyBits: uint16(128 + 64*encryption)}
	if encryption == 3 {
		p.Encryption = 5
		p.KeyBits = 192
	}
	p.Hash = []uint16{1, 2, 4, 5, 6}[authentication]
	if esp {
		p.Hash = []uint16{1, 2, 5, 6, 7}[authentication]
	}
	return p
}
