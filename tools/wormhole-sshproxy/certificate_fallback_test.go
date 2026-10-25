package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCertificateAuthenticationOffersRawKeyFallback(t *testing.T) {
	for _, requireCertificate := range []bool{false, true} {
		t.Run(fmt.Sprint(requireCertificate), func(t *testing.T) {
			keySigner, key := testSigner(t)
			ca, _ := testSigner(t)
			cert := &ssh.Certificate{Key: keySigner.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
			if err := cert.SignCert(rand.Reader, ca); err != nil {
				t.Fatal(err)
			}
			host, _ := testSigner(t)
			var offered []string
			cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				offered = append(offered, key.Type())
				_, isCertificate := key.(*ssh.Certificate)
				if isCertificate != requireCertificate {
					return nil, fmt.Errorf("credential not authorized")
				}
				if !isCertificate && !bytes.Equal(key.Marshal(), keySigner.PublicKey().Marshal()) {
					return nil, fmt.Errorf("unknown public key")
				}
				return nil, nil
			}}
			cfg.AddHostKey(host)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			handshake := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					handshake <- err
					return
				}
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				handshake <- err
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.Prohibited, "authentication fixture")
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request := serverConfig(testServer{address: listener.Addr().String(), pin: ssh.FingerprintSHA256(host.PublicKey())})
			request.Password = ""
			request.PrivateKey = string(key)
			request.Certificate = string(ssh.MarshalAuthorizedKey(cert))
			client, _, err := connect(ctx, request, func(string) (string, error) {
				return "", fmt.Errorf("unexpected interactive authentication")
			})
			if err != nil {
				t.Fatalf("saved certificate/key credential could not authenticate: %v", err)
			}
			defer client.Close()
			select {
			case err := <-handshake:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if len(offered) == 0 || offered[0] != cert.Type() {
				t.Fatal("certificate was not offered first")
			}
			if !requireCertificate && (len(offered) < 2 || offered[len(offered)-1] != keySigner.PublicKey().Type()) {
				t.Fatal("underlying public key was not offered after the rejected certificate")
			}
		})
	}
}
