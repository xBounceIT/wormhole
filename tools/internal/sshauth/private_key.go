package sshauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

var ErrUnsupportedKey = errors.New("the selected file is not a supported SSH private key")

// ParsePrivateKey is shared by credential import, SSH sessions and the jump-host sidecar.
func ParsePrivateKey(key, passphrase []byte) (ssh.Signer, error) {
	if len(key) == 0 || len(key) > MaxKeyBytes {
		return nil, ErrUnsupportedKey
	}
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("PuTTY-User-Key-File-")) {
		return nil, errors.New("PuTTY .ppk keys are not supported yet. Convert with puttygen key.ppk -O private-openssh")
	}
	block, _ := pem.Decode(key)
	if block != nil {
		defer clear(block.Bytes)
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			der, err := decryptSSHPKCS8(block.Bytes, passphrase)
			if err != nil {
				return nil, err
			}
			defer clear(der)
			private, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, x509.IncorrectPasswordError
			}
			return ssh.NewSignerFromKey(private)
		}
	}
	signer, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
	}
	if err != nil && !errors.As(err, &missing) {
		if len(passphrase) > 0 && (errors.Is(err, x509.IncorrectPasswordError) || strings.Contains(err.Error(), "incorrect passphrase")) {
			return nil, x509.IncorrectPasswordError
		}
		return nil, ErrUnsupportedKey
	}
	return signer, err
}

type sshPKCS8Envelope struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

type sshPBES2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

func decodeSSHASN1(der []byte, value any) error {
	rest, err := asn1.Unmarshal(der, value)
	if err != nil || len(rest) != 0 {
		return errors.New("invalid encrypted PKCS#8 parameters")
	}
	return nil
}

func decryptSSHPKCS8(der, passphrase []byte) ([]byte, error) {
	var envelope sshPKCS8Envelope
	if err := decodeSSHASN1(der, &envelope); err != nil {
		return nil, err
	}
	if envelope.Algorithm.Algorithm.String() != "1.2.840.113549.1.5.13" {
		return nil, errors.New("encrypted PKCS#8 key requires PBES2 encryption")
	}
	var params sshPBES2Params
	if err := decodeSSHASN1(envelope.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	keySize, gcm := 0, false
	switch params.Cipher.Algorithm.String() {
	case "2.16.840.1.101.3.4.1.2":
		keySize = 16
	case "2.16.840.1.101.3.4.1.22":
		keySize = 24
	case "2.16.840.1.101.3.4.1.42", "1.2.840.113549.3.7":
		keySize = 32
		if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
			keySize = 24
		}
	case "2.16.840.1.101.3.4.1.6":
		keySize, gcm = 16, true
	case "2.16.840.1.101.3.4.1.26":
		keySize, gcm = 24, true
	case "2.16.840.1.101.3.4.1.46":
		keySize, gcm = 32, true
	default:
		return nil, errors.New("unsupported encrypted PKCS#8 cipher (use AES or 3DES PBES2)")
	}
	// Cipher parameters are public. Reject malformed files before treating a
	// missing password as a supported key or spending time on the KDF.
	var iv []byte
	var parameters struct {
		Nonce   []byte
		TagSize int `asn1:"optional,default:12"`
	}
	if gcm {
		if err := decodeSSHASN1(params.Cipher.Parameters.FullBytes, &parameters); err != nil {
			return nil, err
		}
		if len(parameters.Nonce) != 12 || parameters.TagSize < 12 || parameters.TagSize > 16 || len(envelope.Data) < parameters.TagSize {
			return nil, errors.New("invalid encrypted PKCS#8 GCM parameters")
		}
	} else {
		if err := decodeSSHASN1(params.Cipher.Parameters.FullBytes, &iv); err != nil {
			return nil, err
		}
		blockSize := aes.BlockSize
		if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
			blockSize = des.BlockSize
		}
		if len(iv) != blockSize || len(envelope.Data) == 0 || len(envelope.Data)%blockSize != 0 {
			return nil, errors.New("invalid encrypted PKCS#8 CBC parameters")
		}
	}
	// Check the KDF even without a password; an unsupported key must not be saved.
	key, err := deriveSSHPKCS8Key(params.KDF, passphrase, keySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if gcm {
		block, _ := aes.NewCipher(key)
		aead, err := cipher.NewGCMWithTagSize(block, parameters.TagSize)
		if err != nil {
			return nil, errors.New("invalid encrypted PKCS#8 GCM parameters")
		}
		plain, err := aead.Open(nil, parameters.Nonce, envelope.Data, nil)
		if err != nil {
			return nil, x509.IncorrectPasswordError
		}
		return plain, nil
	}
	var block cipher.Block
	if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(envelope.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, envelope.Data)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > block.BlockSize() || !bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		clear(plain)
		return nil, x509.IncorrectPasswordError
	}
	return plain[:len(plain)-padding], nil
}

func deriveSSHPKCS8Key(algorithm pkix.AlgorithmIdentifier, password []byte, size int) ([]byte, error) {
	switch algorithm.Algorithm.String() {
	case "1.2.840.113549.1.5.12":
		var params struct {
			Salt       []byte
			Iterations int
			KeyLength  int                      `asn1:"optional"`
			PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
		}
		if err := decodeSSHASN1(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		if len(params.Salt) < 1 || len(params.Salt) > 1024 || params.Iterations < 1 || params.Iterations > 10000000 || (params.KeyLength != 0 && params.KeyLength != size) {
			return nil, errors.New("encrypted PKCS#8 PBKDF2 parameters exceed safety limits")
		}
		var digest func() hash.Hash
		switch params.PRF.Algorithm.String() {
		case "", "1.2.840.113549.2.7":
			digest = sha1.New
		case "1.2.840.113549.2.8":
			digest = sha256.New224
		case "1.2.840.113549.2.9":
			digest = sha256.New
		case "1.2.840.113549.2.10":
			digest = sha512.New384
		case "1.2.840.113549.2.11":
			digest = sha512.New
		default:
			return nil, errors.New("unsupported encrypted PKCS#8 PBKDF2 digest")
		}
		if len(password) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
		return pbkdf2.Key(password, params.Salt, params.Iterations, size, digest), nil
	case "1.3.6.1.4.1.11591.4.11":
		var params struct {
			Salt      []byte
			N, R, P   int
			KeyLength int `asn1:"optional"`
		}
		if err := decodeSSHASN1(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		// Bounds make the products below safe on 32-bit platforms as well.
		if len(params.Salt) < 1 || len(params.Salt) > 1024 || params.N < 2 || params.N > 1<<20 || params.N&(params.N-1) != 0 || params.R < 1 || params.R > 32 || params.P < 1 || params.P > 32 || uint64(params.N)*uint64(params.R)*128 > 256<<20 || uint64(params.N)*uint64(params.R)*uint64(params.P) > 1<<25 || (params.KeyLength != 0 && params.KeyLength != size) {
			return nil, errors.New("encrypted PKCS#8 scrypt parameters exceed safety limits")
		}
		if len(password) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
		return scrypt.Key(password, params.Salt, params.N, params.R, params.P, size)
	default:
		return nil, errors.New("unsupported encrypted PKCS#8 key derivation (use PBKDF2 or scrypt)")
	}
}
