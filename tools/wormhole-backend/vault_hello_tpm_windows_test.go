//go:build windows && (amd64 || arm64)

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

func TestVaultHelloDecodesWindowsAttestationCertificateContainers(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic attestation certificate"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, rejected := range [][]byte{nil, make([]byte, (128<<10)+1), []byte("invalid certificate container"), bytes.Repeat(der, 9)} {
		if _, err := decodeWindowsHelloCertificates(rejected); !errors.Is(err, vault.ErrFormat) {
			t.Fatal("bad certificate container was accepted", err)
		}
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(store, windows.CERT_CLOSE_STORE_CHECK_FLAG)
	context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(context)
	if err := windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) {
		t.Helper()
		certificates, err := decodeWindowsHelloCertificates(data)
		if err != nil || len(certificates) != 1 || !bytes.Equal(certificates[0].Raw, der) {
			t.Fatal("Windows chain did not preserve the exact certificate", err)
		}
	}
	decode(der)
	save := windows.NewLazySystemDLL("crypt32.dll").NewProc("CertSaveStore")
	for _, encoding := range []uintptr{1, 2} { // Store serialization and PKCS #7.
		var blob windows.CryptDataBlob
		write := func() {
			ok, _, err := save.Call(uintptr(store), windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, encoding, 2, uintptr(unsafe.Pointer(&blob)), 0)
			if ok == 0 {
				t.Fatal(err)
			}
		}
		write()
		if blob.Size == 0 || blob.Size > 128<<10 {
			t.Fatal("bad fixture store size")
		}
		data := make([]byte, blob.Size)
		blob.Data = &data[0]
		write()
		decode(data[:blob.Size])
	}
}
