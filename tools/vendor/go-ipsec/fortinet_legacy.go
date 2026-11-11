package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/n0madic/go-ipsec/internal/dhcp"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikev1"
	"github.com/n0madic/go-ipsec/internal/transport"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	tun2net "github.com/n0madic/go-tun2net"
)

// DialFortinet keeps both IKE versions behind the same userspace-only API.
func DialFortinet(ctx context.Context, cfg Config) (FortinetClient, error) {
	if cfg.FortinetOptions != nil && cfg.FortinetOptions.IkeVersion == 1 {
		client, err := dialLegacy(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return withLocalLAN(client, cfg.FortinetOptions.EnableLocalLan), nil
	}
	client, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err = client.Net(); err != nil {
		client.Close()
		return nil, err
	}
	return withLocalLAN(client, cfg.FortinetOptions != nil && cfg.FortinetOptions.EnableLocalLan), nil
}

type legacyClient struct {
	cfg           Config
	conn          *net.UDPConn
	rawESP        transport.Conn
	peer          *net.UDPAddr
	nattPort      int
	control       *legacyControl
	renewing      *legacyControl
	controlConfig ikev1.Config
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
	dialContext   context.Context
	volume        uint64
	dhcp          *dhcp.Client
	lease         *dhcp.Lease
	leaseCancel   context.CancelFunc
}

func dialLegacy(ctx context.Context, cfg Config) (*legacyClient, error) {
	o := cfg.FortinetOptions
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
	c := &legacyClient{cfg: cfg, conn: conn, peer: peer, failed: make(chan error, 1), done: make(chan struct{})}
	if !o.NatTraversal {
		c.rawESP, err = transport.DialESP(ctx, peer)
		if err != nil {
			conn.Close()
			return nil, err
		}
		go c.receiveRaw()
	}
	c.dialContext = ctx
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
	sc := ikev1.Config{Role: ikev1.Initiator, Mode: ikev1.Mode(o.ExchangeMode), Phase2: ikev1.Phase2RemoteAccess, PSK: []byte(psk), GroupName: localID, RemoteID: remoteID, Groups: groups, Lifetime: uint32(o.Phase1Lifetime), ESPLifetime: uint32(o.Phase2Lifetime), LocalIP: local, PeerIP: peer.IP, LocalPort: uint16(conn.LocalAddr().(*net.UDPAddr).Port), PeerPort: uint16(peer.Port), ModeCfg: o.AddressAssignment == 0, Send: c.sendIKE}
	sc.DisableNATT = !o.NatTraversal
	sc.DHCP = o.AddressAssignment == 2
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
	c.controlConfig = sc
	c.control = newLegacyControl(sc)
	go c.receive()
	c.control.session.Start()
	select {
	case r := <-c.control.ready:
		if err = c.install(r); err != nil {
			c.Close()
			return nil, err
		}
	case err = <-c.control.failed:
		c.Close()
		return nil, err
	case err = <-c.failed:
		c.Close()
		return nil, err
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
	if c.dhcp != nil {
		leaseCtx, cancel := context.WithCancel(context.Background())
		c.leaseCancel = cancel
		d, l := c.dhcp, *c.lease
		go func() {
			err := d.Maintain(leaseCtx, l, func(next dhcp.Lease) {
				c.mu.Lock()
				c.lease = &next
				c.dns = next.DNS
				tun := c.tun
				c.mu.Unlock()
				tun.UpdateConfig(leaseConfig(next, 1400))
			})
			if err != nil && leaseCtx.Err() == nil {
				c.Failed(errors.New("DHCP lease expired or revoked"))
			}
		}()
	}
	go c.lifecycle()
	return c, nil
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
			c.handleIKE(packet)
			continue
		}
		if n >= 4 && packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 0 {
			c.handleIKE(packet[4:])
			continue
		}
		c.deliverESP(packet)
	}
}

func (c *legacyClient) install(r ikev1.Result) error {
	defer clearLegacyResult(r)
	sa, err := esp.NewLegacySA(r.EncrID, r.IntegID, r.OutSPI, r.InSPI, r.OutEncKey, r.OutIntegKey, r.InEncKey, r.InIntegKey, c.cfg.FortinetOptions.ReplayDetection)
	if err != nil {
		return err
	}
	o := c.cfg.FortinetOptions
	ttl := time.Duration(0)
	if o.Phase2TimeLifetime {
		ttl = time.Duration(o.Phase2Lifetime) * time.Second
	}
	max := uint64(0)
	if o.Phase2ByteLifetime {
		max = uint64(o.Phase2LifetimeKb) * 1024
	}
	sa.ConfigurePolicy(o.ReplayDetection, ttl, max)
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
	if o.AddressAssignment == 2 {
		c.mu.RLock()
		existing := c.tun
		currentLease := c.lease
		c.mu.RUnlock()
		if existing != nil && currentLease != nil {
			address = currentLease.IP
			dns = currentLease.DNS
		} else {
			c.mu.Lock()
			c.sa = sa
			c.mu.Unlock()
			d, err := dhcp.New(func(ctx context.Context, plain []byte) error {
				c.mu.RLock()
				current := c.sa
				c.mu.RUnlock()
				p, err := current.Encrypt(plain)
				if err != nil {
					return err
				}
				return c.sendESP(ctx, p)
			})
			if err != nil {
				return err
			}
			c.mu.Lock()
			c.dhcp = d
			c.mu.Unlock()
			bounded, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			stop := context.AfterFunc(c.dialContext, cancel)
			l, err := d.Acquire(bounded)
			stop()
			cancel()
			if err != nil {
				return errors.New("DHCP over IPsec did not assign an address")
			}
			address = l.IP
			dns = l.DNS
			c.mu.Lock()
			c.lease = &l
			c.mu.Unlock()
		}
	}
	if !address.IsValid() {
		return errors.New("IPsec gateway did not assign an IPv4 address")
	}
	c.mu.RLock()
	existingTunnel := c.tun
	c.mu.RUnlock()
	if existingTunnel != nil && existingTunnel.Config().LocalIP != address {
		return errors.New("IPsec renewal changed the client address")
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
		c.mu.RLock()
		l := c.lease
		c.mu.RUnlock()
		if l != nil && !time.Now().Before(l.Expires) {
			return net.ErrClosed
		}
		return c.sendESP(ctx, p)
	}, tc)
	stack, err := tun2net.New(tun, nil)
	if err != nil {
		tun.Close()
		return err
	}
	if c.lease != nil {
		tun.UpdateConfig(leaseConfig(*c.lease, 1400))
	}
	c.mu.Lock()
	c.sa = sa
	c.tun = tun
	c.stack = stack
	c.dns = dns
	c.mu.Unlock()
	return nil
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
		if c.leaseCancel != nil {
			c.leaseCancel()
		}
		c.conn.Close()
		if c.rawESP != nil {
			c.rawESP.Close()
		}
		c.mu.Lock()
		control, renewing := c.control, c.renewing
		c.renewing = nil
		clear(c.controlConfig.PSK)
		stack, tun := c.stack, c.tun
		c.mu.Unlock()
		control.close()
		renewing.close()
		if stack != nil {
			stack.Close()
		}
		if tun != nil {
			tun.Close()
		}
	})
	return nil
}

func (c *legacyClient) receiveRaw() {
	for {
		packet, err := c.rawESP.Recv(context.Background())
		if err != nil {
			c.Failed(errors.New("ESP transport closed"))
			return
		}
		c.deliverESP(packet)
	}
}
func (c *legacyClient) deliverESP(packet []byte) {
	c.mu.RLock()
	sa, previous, until := c.sa, c.previousSA, c.previousUntil
	c.mu.RUnlock()
	if sa == nil {
		return
	}
	if len(packet) < 4 {
		return
	}
	current := binary.BigEndian.Uint32(packet[:4]) == sa.InSPI()
	if !current {
		if previous == nil || !time.Now().Before(until) || binary.BigEndian.Uint32(packet[:4]) != previous.InSPI() {
			return
		}
		sa = previous
	}
	plain, err := sa.Decrypt(packet)
	if err == nil {
		if current && c.cfg.FortinetOptions.Phase2ByteLifetime && sa.Bytes() >= uint64(c.cfg.FortinetOptions.Phase2LifetimeKb)*1024*9/10 {
			select {
			case c.rekey <- struct{}{}:
			default:
			}
		}
		c.deliverIP(plain)
	} else if current && errors.Is(err, esp.ErrLifetimeExpired) {
		c.Failed(errors.New("IPsec key lifetime expired"))
	}

}

func (c *legacyClient) sendESP(ctx context.Context, p []byte) error {
	if c.rawESP != nil {
		return c.rawESP.Send(ctx, p)
	}
	peer := *c.peer
	peer.Port = c.nattPort
	_, err := c.conn.WriteToUDP(p, &peer)
	return err
}
