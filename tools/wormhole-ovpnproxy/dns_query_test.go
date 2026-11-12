package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestTunnelDNSValidatesAnswerOwnershipAndCNAMEs(t *testing.T) {
	for _, test := range []string{"alias", "empty", "owner", "class", "family", "loop", "private alias"} {
		t.Run(test, func(t *testing.T) {
			queries := 0
			peer := tunnelDNSPeer(t, func(_ string, q dnsmessage.Question) dnsmessage.Message {
				queries++
				response := tunnelDNSAnswer(q)
				switch test {
				case "empty":
					response.Answers = nil
				case "owner":
					response.Answers[0].Header.Name, _ = dnsmessage.NewName("unrelated.example.com.")
				case "class":
					response.Answers[0].Header.Class = dnsmessage.ClassCHAOS
				case "family":
					response.Answers[0].Body = &dnsmessage.AAAAResource{}
				default:
					target, _ := dnsmessage.NewName("alias.example.com.")
					if test == "loop" {
						target = q.Name
					} else if test == "private alias" {
						target, _ = dnsmessage.NewName("secret.internal.")
					}
					response.Answers[0].Header.Name = target
					alias := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET},
						Body: &dnsmessage.CNAMEResource{CNAME: target}}
					if test == "alias" {
						response.Answers = append([]dnsmessage.Resource{alias}, response.Answers...)
					} else {
						response.Answers = []dnsmessage.Resource{alias}
					}
				}
				return response
			})
			addrs, err := lookupTunnelDNSFamily(context.Background(), peer, "1.1.1.1:53", "images.example.com", dnsmessage.TypeA)
			if test == "alias" {
				if err != nil || !reflect.DeepEqual(addrs, []string{"192.0.2.20"}) {
					t.Fatalf("CNAME addresses = %v, %v", addrs, err)
				}
			} else if err == nil || len(addrs) != 0 {
				t.Fatalf("invalid DNS answer accepted: %v, %v", addrs, err)
			}
			if queries != 1 {
				t.Fatalf("queried a CNAME target outside the original public name: %d queries", queries)
			}
		})
	}
}

func TestTunnelDNSRejectsInvalidQueryNames(t *testing.T) {
	for _, host := range []string{strings.Repeat("x", 256), "images..example.com"} {
		if _, err := lookupTunnelDNSFamily(context.Background(), nil, "1.1.1.1:53", host, dnsmessage.TypeA); err == nil {
			t.Fatalf("invalid name %q accepted", host)
		}
	}
}

type scriptedDNSConn struct {
	net.Conn
	read        func([]byte) (int, error)
	write       func([]byte) (int, error)
	deadlineErr error
}

func (c *scriptedDNSConn) Read(p []byte) (int, error)  { return c.read(p) }
func (c *scriptedDNSConn) Write(p []byte) (int, error) { return c.write(p) }
func (c *scriptedDNSConn) Close() error                { return nil }
func (c *scriptedDNSConn) SetDeadline(time.Time) error { return c.deadlineErr }

type scriptedDNSDatagram struct{ *scriptedDNSConn }

func (c scriptedDNSDatagram) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, nil, err
}
func (c scriptedDNSDatagram) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func dnsExchangeFixture(t *testing.T) (dnsmessage.Message, []byte, []byte) {
	t.Helper()
	name, _ := dnsmessage.NewName("images.example.com.")
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	response := tunnelDNSAnswer(request.Questions[0])
	response.ID, response.Response, response.Questions = request.ID, true, request.Questions
	answer, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return request, wire, answer
}

func TestTunnelDNSIgnoresMalformedOrUnmatchedUDPReplies(t *testing.T) {
	request, wire, answer := dnsExchangeFixture(t)
	for _, fault := range []string{"malformed", "question", "id", "query", "opcode", "type", "class"} {
		t.Run(fault, func(t *testing.T) {
			bad := append([]byte(nil), answer...)
			switch fault {
			case "malformed":
				bad = []byte{1}
			case "question":
				bad[5] = 0
			case "id":
				bad[1]++
			case "query":
				bad[2] = 0
			case "opcode":
				bad[2] |= 8
			case "type":
				bad[len(wire)-3] = 28
			case "class":
				bad[len(wire)-1] = 3
			}
			packets := [][]byte{bad, answer}
			conn := scriptedDNSDatagram{&scriptedDNSConn{
				write: func(p []byte) (int, error) { return len(p), nil },
				read: func(p []byte) (int, error) {
					if len(packets) == 0 {
						return 0, io.EOF
					}
					n := copy(p, packets[0])
					packets = packets[1:]
					return n, nil
				},
			}}
			peer := tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
			response, err := exchangeTunnelDNS(context.Background(), peer, "1.1.1.1:53", request, wire, "udp")
			if err != nil || len(response.Answers) != 1 || len(packets) != 0 {
				t.Fatalf("stray reply broke valid DNS answer: %v, %v", response, err)
			}
		})
	}
}

func TestTunnelDNSTCPFramingAndTransportErrors(t *testing.T) {
	request, wire, answer := dnsExchangeFixture(t)
	failure := errors.New("broken tunnel transport")
	for _, fault := range []string{"deadline", "write", "short write", "length", "payload", "malformed answer", "invalid answer"} {
		t.Run(fault, func(t *testing.T) {
			payload := append([]byte{byte(len(answer) >> 8), byte(len(answer))}, answer...)
			switch fault {
			case "length":
				payload = payload[:1]
			case "payload":
				payload = payload[:len(payload)-1]
			case "invalid answer":
				payload[3]++
			case "malformed answer":
				payload[9]++ // Valid header/question, answer count exceeds payload.
			}
			conn := &scriptedDNSConn{read: bytes.NewReader(payload).Read,
				write: func(p []byte) (int, error) {
					if fault == "write" {
						return 0, failure
					}
					if fault == "short write" {
						return len(p) - 1, nil
					}
					return len(p), nil
				}}
			if fault == "deadline" {
				conn.deadlineErr = failure
			}
			peer := tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := exchangeTunnelDNS(ctx, peer, "1.1.1.1:53", request, wire, "tcp"); err == nil {
				t.Fatalf("%s accepted", fault)
			}
		})
	}
}

func TestTunnelDNSRetriesTruncatedReplyWithIncompleteAnswerOverTCP(t *testing.T) {
	request, wire, answer := dnsExchangeFixture(t)
	truncated := append([]byte(nil), wire...)
	truncated[2] |= 0x82 // QR + TC, with an answer count but missing answer bytes.
	truncated[7] = 1
	conn := scriptedDNSDatagram{&scriptedDNSConn{
		write: func(p []byte) (int, error) { return len(p), nil }, read: bytes.NewReader(truncated).Read,
	}}
	peer := tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
	response, err := exchangeTunnelDNS(context.Background(), peer, "1.1.1.1:53", request, wire, "udp")
	if err != nil || !response.Truncated {
		t.Fatalf("truncated DNS response was discarded before TCP retry: %v, %v", response, err)
	}
	// A legitimate TCP response can exceed the 512-byte UDP limit.
	var message dnsmessage.Message
	if err := message.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	for len(message.Answers) < 80 {
		message.Answers = append(message.Answers, message.Answers[0])
	}
	large, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	framed := make([]byte, 2+len(large))
	binary.BigEndian.PutUint16(framed, uint16(len(large)))
	copy(framed[2:], large)
	stream := &scriptedDNSConn{read: bytes.NewReader(framed).Read, write: func(p []byte) (int, error) { return len(p), nil }}
	peer = tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return stream, nil })
	response, err = exchangeTunnelDNS(context.Background(), peer, "1.1.1.1:53", request, wire, "tcp")
	if err != nil || len(response.Answers) != 80 {
		t.Fatalf("large DNS TCP response = %d answers, %v", len(response.Answers), err)
	}
}

func TestTunnelDNSClosesBlockedSocketOnCancellation(t *testing.T) {
	request, wire, _ := dnsExchangeFixture(t)
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		io.CopyN(io.Discard, peer, int64(len(wire)+2))
		cancel()
	}()
	tunnel := tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return client, nil })
	finished := make(chan error, 1)
	go func() {
		_, err := exchangeTunnelDNS(ctx, tunnel, "1.1.1.1:53", request, wire, "tcp")
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled DNS query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DNS query left its socket blocked")
	}
}
