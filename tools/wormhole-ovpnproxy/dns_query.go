package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"golang.org/x/net/dns/dnsmessage"
)

// Use DNS wire messages directly: net.Resolver also reads host files, consults
// system lookup policy and probes OS routes when sorting multi-address answers.
func lookupTunnelDNS(ctx context.Context, tunnel sockstun.Dialer, server, host string, types []dnsmessage.Type) ([]string, error) {
	type result struct {
		addrs []string
		err   error
	}
	results := make(chan result, len(types))
	for _, qtype := range types {
		go func() {
			addrs, err := lookupTunnelDNSFamily(ctx, tunnel, server, host, qtype)
			results <- result{addrs, err}
		}()
	}
	var addrs []string
	var lookupErr error
	for range types {
		result := <-results
		addrs = append(addrs, result.addrs...)
		lookupErr = errors.Join(lookupErr, result.err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	return nil, lookupErr
}

func lookupTunnelDNSFamily(ctx context.Context, tunnel sockstun.Dialer, server, host string, qtype dnsmessage.Type) ([]string, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	var id [2]byte
	rand.Read(id[:])
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{question}}
	wire, err := request.Pack()
	if err != nil {
		return nil, err
	}
	response, err := exchangeTunnelDNS(ctx, tunnel, server, request, wire, "udp")
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		response, err = exchangeTunnelDNS(ctx, tunnel, server, request, wire, "tcp")
		if err != nil {
			return nil, err
		}
	}
	if response.Truncated || response.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS server %s returned %v (truncated=%v)", server, response.RCode, response.Truncated)
	}
	// Follow only records belonging to the requested name/CNAME chain. Public
	// recursive DNS must include the final addresses; never query an alias that
	// might name a private host. Unrelated answer records cannot redirect traffic.
	for range 9 {
		var addrs []string
		var alias string
		for _, answer := range response.Answers {
			if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), name.String()) {
				continue
			}
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				if qtype == dnsmessage.TypeA {
					addrs = append(addrs, netip.AddrFrom4(body.A).String())
				}
			case *dnsmessage.AAAAResource:
				if qtype == dnsmessage.TypeAAAA {
					addrs = append(addrs, netip.AddrFrom16(body.AAAA).String())
				}
			case *dnsmessage.CNAMEResource:
				alias = body.CNAME.String()
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		if alias == "" {
			return nil, errors.New("DNS response contains no addresses for the requested name")
		}
		name, _ = dnsmessage.NewName(alias)
	}
	return nil, errors.New("DNS response CNAME chain exceeded eight hops")
}

func exchangeTunnelDNS(ctx context.Context, tunnel sockstun.Dialer, server string, request dnsmessage.Message, wire []byte, network string) (dnsmessage.Message, error) {
	conn, err := tunnel.DialContext(ctx, network, server)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return dnsmessage.Message{}, err
		}
	}
	_, datagram := conn.(net.PacketConn)
	if !datagram {
		framed := make([]byte, len(wire)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(wire)))
		copy(framed[2:], wire)
		wire = framed
	}
	if n, err := conn.Write(wire); err != nil {
		return dnsmessage.Message{}, err
	} else if n != len(wire) {
		return dnsmessage.Message{}, io.ErrShortWrite
	}
	packet := make([]byte, 512) // No EDNS: larger UDP answers must set TC and use TCP.
	for {
		var size int
		if datagram {
			size, err = conn.Read(packet)
		} else {
			if _, err = io.ReadFull(conn, packet[:2]); err == nil {
				size = int(binary.BigEndian.Uint16(packet[:2]))
				if size > len(packet) {
					packet = make([]byte, size) // Bounded by the uint16 DNS TCP length.
				}
				_, err = io.ReadFull(conn, packet[:size])
			}
		}
		if err != nil {
			return dnsmessage.Message{}, err
		}
		var parser dnsmessage.Parser
		header, parseErr := parser.Start(packet[:size])
		question, questionErr := parser.Question()
		if parseErr != nil || questionErr != nil || !header.Response || header.ID != request.ID || header.OpCode != 0 ||
			question.Class != request.Questions[0].Class || question.Type != request.Questions[0].Type ||
			!strings.EqualFold(question.Name.String(), request.Questions[0].Name.String()) || parser.SkipQuestion() != dnsmessage.ErrSectionDone {
			if !datagram {
				return dnsmessage.Message{}, errors.New("DNS response does not match the request")
			}
			continue // Ignore stray, malformed or forged datagrams within the deadline.
		}
		if header.Truncated {
			return dnsmessage.Message{Header: header}, nil
		}
		var response dnsmessage.Message
		err := response.Unpack(packet[:size])
		return response, err
	}
}
