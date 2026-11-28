package sharedpg

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/crypto/pbkdf2"
)

func TestGeneratedServerKeyOpensAsEncryptedPKCS8AndMatchesLeaf(t *testing.T) {
	ctx := context.Background()
	scope := WorkspaceBootstrapScope{uuid.New(), "testscope", sha256.Sum256([]byte("server kit scope"))}
	now := time.Now()
	password := []byte("synthetic-first-administrator")
	passphrase := []byte("synthetic-independent-passphrase")
	hosts := []string{"127.0.0.1", "db.example.test"}
	call := func(ctx context.Context, host string, hosts []string, pass []byte) (*WorkspaceTLSDraft, []byte, error) {
		return GenerateWorkspaceServerTLS(ctx, scope, host, hosts, password, nil, pass, now)
	}
	for _, pass := range [][]byte{nil, []byte("short"), password, []byte("synthetic-passphrase\nextra")} {
		if _, _, err := call(ctx, hosts[0], hosts, pass); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsuitable passphrase was accepted", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := call(cancelled, hosts[0], hosts, passphrase); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled key generation proceeded", err)
	}
	if _, _, err := call(ctx, hosts[0], []string{}, passphrase); !errors.Is(err, ErrServerCertificate) {
		t.Fatal("missing SANs proceeded", err)
	}
	if _, _, err := call(ctx, "unapproved.example.test", hosts, passphrase); !errors.Is(err, ErrServerCertificate) {
		t.Fatal("unapproved endpoint proceeded", err)
	}
	draft, raw, err := call(ctx, hosts[0], hosts, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	key, remaining := pem.Decode(raw)
	if key == nil || key.Type != "ENCRYPTED PRIVATE KEY" || len(remaining) != 0 {
		t.Fatal("unexpected private key PEM")
	}
	decode := func(raw []byte, target any) {
		t.Helper()
		if rest, err := asn1.Unmarshal(raw, target); err != nil || len(rest) != 0 {
			t.Fatal("unexpected PKCS#8 parameters", err)
		}
	}
	var info encryptedServerPrivateKeyInfo
	decode(key.Bytes, &info)
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		t.Fatal("unexpected encryption scheme")
	}
	var pbes serverKeyPBES2Parameters
	decode(info.Algorithm.Parameters.FullBytes, &pbes)
	var kdf serverKeyPBKDF2Parameters
	decode(pbes.KDF.Parameters.FullBytes, &kdf)
	if !pbes.KDF.Algorithm.Equal(oidPBKDF2) || !pbes.Cipher.Algorithm.Equal(oidAES256CBC) ||
		!kdf.PRF.Algorithm.Equal(oidHMACSHA256) || kdf.Iterations != serverKeyKDFIterations {
		t.Fatal("unexpected password derivation or cipher")
	}
	var iv []byte
	decode(pbes.Cipher.Parameters.FullBytes, &iv)
	secret := pbkdf2.Key(passphrase, kdf.Salt, kdf.Iterations, 32, sha256.New)
	defer vault.Wipe(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Clone(info.Data)
	defer vault.Wipe(plain)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, plain)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize {
		t.Fatal("invalid PKCS#8 padding")
	}
	value, err := x509.ParsePKCS8PrivateKey(plain[:len(plain)-padding])
	private, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		t.Fatal("password did not unlock an EC server key", err)
	}
	defer wipeWorkspaceCAKey(private)
	cert, _ := pem.Decode([]byte(draft.ServerPEM))
	leaf, err := x509.ParseCertificate(cert.Bytes)
	if err != nil || !private.PublicKey.Equal(leaf.PublicKey) || bytes.Contains(raw, plain[:len(plain)-padding]) {
		t.Fatal("encrypted key does not match the issued certificate", err)
	}
}
