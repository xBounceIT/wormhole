package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikev1"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	tun2net "github.com/n0madic/go-tun2net"
)

// DialFortinet keeps both IKE versions behind the same userspace-only API.
func DialFortinet(ctx context.Context, cfg Config) (FortinetClient, error) {
	if cfg.FortinetOptions != nil && cfg.FortinetOptions.IkeVersion == 1 {
		return dialLegacy(ctx, cfg)
	}
	client, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err = client.Net(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

type legacyClient struct {
	cfg           Config
	conn          *net.UDPConn
	peer          *net.UDPAddr
	nattPort      int
	session       *ikev1.Session
	ready         chan ikev1.Result
	failed        chan error
	done          chan struct{}
	once          sync.Once
	mu            sync.RWMutex
	sa            *esp.SA
	previousSA    *esp.SA
	previousUntil time.Time
	rekey         chan struct{}
	tun           *tunnel.Tunnel
	stack         *tun2net.Net
	dns           []netip.Addr
	volume        uint64
}

func dialLegacy(ctx context.Context, cfg Config) (*legacyClient, error) {
	o := cfg.FortinetOptions
	if !o.NatTraversal {
		return nil, errors.New("the userspace IKEv1 engine requires NAT traversal")
	}
	if o.AddressAssignment == 2 {
		return nil, errors.New("DHCP over IPsec is not available in this engine; use Mode Config or a manual address")
	}
	if o.EnableLocalLan {
		return nil, errors.New("local LAN bypass is not available for isolated application tunnels")
	}
	groups, err := fortinetGroups(o.DhGroups)
	if err != nil {
		return nil, err
	}
	peer, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		return nil, err
	}
	probe, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, err
	}
	local := probe.LocalAddr().(*net.UDPAddr).IP
	probe.Close()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	c := &legacyClient{cfg: cfg, conn: conn, peer: peer, ready: make(chan ikev1.Result, 1), failed: make(chan error, 1), done: make(chan struct{})}
	c.rekey = make(chan struct{}, 1)
	c.nattPort = cfg.NATTPort
	if c.nattPort == 0 {
		c.nattPort = 4500
	}
	if c.nattPort < 1 || c.nattPort > 65535 {
		conn.Close()
		return nil, errors.New("invalid NAT-T port")
	}
	psk := cfg.PSK
	if psk == "" {
		psk = cfg.ServerPSK
	}
	localID, remoteID := "", ""
	if !cfg.LocalID.IsZero() {
		localID = cfg.LocalID.String()
	}
	if !cfg.RemoteID.IsZero() {
		remoteID = cfg.RemoteID.String()
	}
	sc := ikev1.Config{Role: ikev1.Initiator, Mode: ikev1.Mode(o.ExchangeMode), Phase2: ikev1.Phase2RemoteAccess, PSK: []byte(psk), GroupName: localID, RemoteID: remoteID, Groups: groups, Lifetime: uint32(o.Phase1Lifetime), ESPLifetime: uint32(o.Phase2Lifetime), LocalIP: local, PeerIP: peer.IP, LocalPort: uint16(conn.LocalAddr().(*net.UDPAddr).Port), PeerPort: uint16(peer.Port), ModeCfg: o.AddressAssignment == 0, Handler: c, Send: c.sendIKE}
	sc.Certificate = cfg.ClientCertificate
	if !o.Phase2TimeLifetime {
		sc.ESPLifetime = 0
	}
	if o.Phase2ByteLifetime {
		sc.ESPLifetimeKb = uint32(o.Phase2LifetimeKb)
	}
	sc.RootCAs = cfg.RootCAs
	if !cfg.LocalID.IsZero() {
		sc.GroupName = string(cfg.LocalID.Data)
		sc.IdentityType = uint8(cfg.LocalID.Kind)
	}
	sc.Proposals = []ikev1.Proposal{fortinetProposal(o.Phase1Encryption, o.Phase1Authentication, false), fortinetProposal(o.Phase1Encryption2, o.Phase1Authentication2, false)}
	sc.ESPProposals = []ikev1.Proposal{fortinetProposal(o.Phase2Encryption, o.Phase2Authentication, true), fortinetProposal(o.Phase2Encryption2, o.Phase2Authentication2, true)}
	if o.Pfs {
		sc.PFS = uint16(o.PfsGroup)
	}
	if o.UserAuth == 1 || o.UserAuth == 2 {
		sc.XAuth = &ikev1.XAuthConfig{Username: cfg.EAP.Username, Password: cfg.EAP.Password}
	}
	if o.AddressAssignment == 1 {
		sc.ManualIP = net.ParseIP(o.ManualAddress)
		if sc.ManualIP.To4() == nil {
			c.Close()
			return nil, errors.New("invalid manual IPv4 address")
		}
	}
	c.session = ikev1.NewSession(sc)
	go c.receive()
	c.session.Start()
	select {
	case r := <-c.ready:
		if err = c.install(r); err != nil {
			c.Close()
			return nil, err
		}
	case err = <-c.failed:
		c.Close()
		return nil, err
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
	go c.lifecycle()
	return c, nil
}

func (c *legacyClient) Established(r ikev1.Result) {
	select {
	case c.ready <- r:
	case <-c.done:
	}
}
func (c *legacyClient) Failed(err error) {
	select {
	case c.failed <- err:
	default:
	}
}

func (c *legacyClient) sendIKE(message []byte, natt bool) error {
	peer := *c.peer
	if natt {
		peer.Port = c.nattPort
		message = append([]byte{0, 0, 0, 0}, message...)
	}
	_, err := c.conn.WriteToUDP(message, &peer)
	return err
}

func (c *legacyClient) receive() {
	buffer := make([]byte, 65536)
	for {
		n, from, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			c.Failed(errors.New("IPsec transport closed"))
			return
		}
		if !from.IP.Equal(c.peer.IP) || (from.Port != c.peer.Port && from.Port != c.nattPort) {
			continue
		}
		packet := buffer[:n]
		if n == 1 && packet[0] == 255 {
			continue
		}
		if from.Port == c.peer.Port {
			c.session.HandleInbound(packet)
			continue
		}
		if n >= 4 && packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 0 {
			c.session.HandleInbound(packet[4:])
			continue
		}
		c.mu.RLock()
		sa, tun, previous, until := c.sa, c.tun, c.previousSA, c.previousUntil
		c.mu.RUnlock()
		if sa != nil && tun != nil {
			plain, err := sa.Decrypt(packet)
			if err != nil && previous != nil && time.Now().Before(until) {
				plain, err = previous.Decrypt(packet)
			}
			if err == nil {
				tun.DeliverInbound(plain)
			}
		}
	}
}

func (c *legacyClient) install(r ikev1.Result) error {
	defer clear(r.OutEncKey)
	defer clear(r.InEncKey)
	defer clear(r.OutIntegKey)
	defer clear(r.InIntegKey)
	sa, err := esp.NewLegacySA(r.EncrID, r.IntegID, r.OutSPI, r.InSPI, r.OutEncKey, r.OutIntegKey, r.InEncKey, r.InIntegKey, c.cfg.FortinetOptions.ReplayDetection)
	if err != nil {
		return err
	}
	o := c.cfg.FortinetOptions
	address := netip.Addr{}
	var dns []netip.Addr
	if r.ModeCfg != nil {
		address, _ = netip.AddrFromSlice(r.ModeCfg.Address.To4())
		for _, ip := range r.ModeCfg.DNS {
			if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
				dns = append(dns, addr)
			}
		}
	}
	if o.AddressAssignment == 1 {
		address, _ = netip.ParseAddr(o.ManualAddress)
		for _, ip := range strings.Split(o.ManualDns, ",") {
			if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
				dns = append(dns, addr)
			}
		}
	}
	if !address.IsValid() {
		return errors.New("IPsec gateway did not assign an IPv4 address")
	}
	tc := tun2net.TunConfig{LocalIP: address, Netmask: netip.MustParseAddr("255.255.255.255"), DNS: dns, MTU: 1400}
	c.mu.Lock()
	if c.tun != nil {
		c.previousSA = c.sa
		c.previousUntil = time.Now().Add(30 * time.Second)
		c.sa = sa
		c.volume = 0
		c.dns = dns
		existing := c.tun
		c.mu.Unlock()
		existing.SwapSA(sa)
		return nil
	}
	c.mu.Unlock()
	tun := tunnel.New(sa, func(ctx context.Context, p []byte) error {
		select {
		case <-c.done:
			return net.ErrClosed
		default:
		}
		peer := *c.peer
		peer.Port = c.nattPort
		c.mu.Lock()
		c.volume += uint64(len(p))
		volume := c.volume
		c.mu.Unlock()
		if o.Phase2ByteLifetime && volume >= uint64(o.Phase2LifetimeKb)*1024 {
			c.Failed(errors.New("IPsec key volume expired"))
			return errors.New("IPsec key volume expired")
		}
		if o.Phase2ByteLifetime && volume >= uint64(o.Phase2LifetimeKb)*1024*9/10 {
			select {
			case c.rekey <- struct{}{}:
			default:
			}
		}
		_, err := c.conn.WriteToUDP(p, &peer)
		return err
	}, tc)
	stack, err := tun2net.New(tun, nil)
	if err != nil {
		tun.Close()
		return err
	}
	c.mu.Lock()
	c.sa = sa
	c.tun = tun
	c.stack = stack
	c.dns = dns
	c.mu.Unlock()
	return nil
}

func (c *legacyClient) lifecycle() {
	o := c.cfg.FortinetOptions
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	var expiry <-chan time.Time
	seconds := o.Phase1Lifetime
	if seconds > 0 {
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		defer timer.Stop()
		expiry = timer.C
	}
	soft := time.NewTimer(time.Hour)
	hard := time.NewTimer(time.Hour)
	defer soft.Stop()
	defer hard.Stop()
	var softCh, hardCh <-chan time.Time
	resetChild := func() {
		if o.Phase2TimeLifetime {
			ttl := time.Duration(o.Phase2Lifetime) * time.Second
			soft.Reset(ttl * 9 / 10)
			hard.Reset(ttl)
			softCh = soft.C
			hardCh = hard.C
		} else {
			soft.Stop()
			hard.Stop()
			softCh = nil
			hardCh = nil
		}
	}
	resetChild()
	pending := false
	requestRekey := func() error {
		if pending {
			return nil
		}
		pending = true
		return c.session.Rekey()
	}
	defer func() {
		c.Close()
		if c.cfg.OnDead != nil {
			c.cfg.OnDead()
		}
	}()
	for {
		select {
		case <-c.done:
			return
		case <-c.failed:
			return
		case <-expiry:
			return
		case <-hardCh:
			return
		case <-softCh:
			if err := requestRekey(); err != nil {
				return
			}
		case <-c.rekey:
			if err := requestRekey(); err != nil {
				return
			}
		case result := <-c.ready:
			if err := c.install(result); err != nil {
				return
			}
			pending = false
			resetChild()
		case <-ticker.C:
			peer := *c.peer
			peer.Port = c.nattPort
			_, _ = c.conn.WriteToUDP([]byte{255}, &peer)
			c.mu.RLock()
			volume := c.volume
			c.mu.RUnlock()
			if o.Phase2ByteLifetime && volume >= uint64(o.Phase2LifetimeKb)*1024 {
				return
			}
			if o.DeadPeerDetection {
				ack, err := c.session.Ping()
				if err != nil {
					return
				}
				timer := time.NewTimer(15 * time.Second)
				select {
				case <-ack:
					timer.Stop()
				case <-timer.C:
					return
				case <-c.done:
					timer.Stop()
					return
				}
			}
		}
	}
}

func (c *legacyClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	return c.stack.DialContext(ctx, network, address)
}
func (c *legacyClient) Resolver(server string) *net.Resolver {
	if server == "" {
		c.mu.RLock()
		server = resolverServer(c.dns, nil)
		c.mu.RUnlock()
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return c.DialContext(ctx, network, server)
	}}
}
func (c *legacyClient) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.conn.Close()
		if c.session != nil {
			c.session.Close()
		}
		c.mu.Lock()
		stack, tun := c.stack, c.tun
		c.mu.Unlock()
		if stack != nil {
			stack.Close()
		}
		if tun != nil {
			tun.Close()
		}
	})
	return nil
}
