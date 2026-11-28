package sharedpg

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"time"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/crypto/pbkdf2"
)

const (
	MaxEncryptedServerKeyBytes = 16 * 1024
	MinServerKeyPassphrase     = 16
	serverKeyKDFIterations     = 600_000
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// GenerateWorkspaceServerTLS is the workstation-generated key path for Default
// and Standard setup. Callers enforce the effective OS profile before issuing.
// The only returned server key is OpenSSL-compatible encrypted PKCS#8.
func GenerateWorkspaceServerTLS(ctx context.Context, scope WorkspaceBootstrapScope, endpoint string, hosts []string, password, ask, passphrase []byte, now time.Time) (*WorkspaceTLSDraft, []byte, error) {
	if ctx == nil || !scope.valid() || !validWorkspaceBootstrapFactors(password, ask) ||
		len(passphrase) > 1024 || !utf8.Valid(passphrase) || utf8.RuneCount(passphrase) < MinServerKeyPassphrase ||
		bytes.ContainsAny(passphrase, "\x00\r\n") || bytes.Equal(passphrase, password) {
		return nil, nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	dns, ips, err := serverCertificateNames(hosts)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, ErrServerCertificate
	}
	defer wipeWorkspaceCAKey(key)
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: dns, IPAddresses: ips,
	}, key)
	if err != nil {
		return nil, nil, ErrServerCertificate
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
	draft, err := PrepareWorkspaceTLS(ctx, scope, endpoint, hosts, csr, password, ask, now)
	if err != nil {
		return nil, nil, err
	}
	protected, err := encryptServerPKCS8(key, passphrase)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return draft, protected, nil
}

type serverKeyPBKDF2Parameters struct {
	Salt       []byte
	Iterations int
	PRF        pkix.AlgorithmIdentifier
}

type serverKeyPBES2Parameters struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

type encryptedServerPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

func serverKeyAlgorithm(oid asn1.ObjectIdentifier, parameters any) (pkix.AlgorithmIdentifier, error) {
	der, err := asn1.Marshal(parameters)
	return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: der}}, err
}

func encryptServerPKCS8(key *ecdsa.PrivateKey, passphrase []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrServerCertificate
	}
	defer vault.Wipe(der)
	var salt [32]byte
	var iv [aes.BlockSize]byte
	rand.Read(salt[:])
	rand.Read(iv[:])
	secret := pbkdf2.Key(passphrase, salt[:], serverKeyKDFIterations, 32, sha256.New)
	defer vault.Wipe(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, ErrServerCertificate
	}
	padding := aes.BlockSize - len(der)%aes.BlockSize
	buffer := make([]byte, len(der)+padding)
	defer vault.Wipe(buffer)
	copy(buffer, der)
	for i := len(der); i < len(buffer); i++ {
		buffer[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(buffer, buffer)

	prf := pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}
	kdf, err := serverKeyAlgorithm(oidPBKDF2, serverKeyPBKDF2Parameters{salt[:], serverKeyKDFIterations, prf})
	if err != nil {
		return nil, err
	}
	cipherAlgorithm, err := serverKeyAlgorithm(oidAES256CBC, iv[:])
	if err != nil {
		return nil, err
	}
	pbes2, err := serverKeyAlgorithm(oidPBES2, serverKeyPBES2Parameters{kdf, cipherAlgorithm})
	if err != nil {
		return nil, err
	}
	result, err := asn1.Marshal(encryptedServerPrivateKeyInfo{pbes2, buffer})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: result}), nil
}
