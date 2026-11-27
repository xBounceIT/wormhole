//go:build windows && (amd64 || arm64)

package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
)

func decodeWindowsHelloCertificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 || len(data) > 128<<10 {
		return nil, vault.ErrFormat
	}
	if certificates, err := x509.ParseCertificates(data); err == nil {
		if len(certificates) == 0 || len(certificates) > 8 {
			return nil, vault.ErrFormat
		}
		return certificates, nil
	}
	// These are in-memory containers for issuer hints, never a trust store.
	for _, provider := range []uintptr{windows.CERT_STORE_PROV_PKCS7, windows.CERT_STORE_PROV_SERIALIZED} {
		certificates, err := certificatesFromWindowsHelloStore(data, provider)
		if err == nil {
			return certificates, nil
		}
	}
	return nil, vault.ErrFormat
}

func certificatesFromWindowsHelloStore(data []byte, provider uintptr) ([]*x509.Certificate, error) {
	blob := windows.CryptDataBlob{Size: uint32(len(data)), Data: &data[0]}
	var pinned runtime.Pinner
	pinned.Pin(&blob)
	pinned.Pin(&data[0])
	defer pinned.Unpin()
	store, err := windows.CertOpenStore(provider, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG, uintptr(unsafe.Pointer(&blob)))
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)
	var certificates []*x509.Certificate
	var context *windows.CertContext
	defer func() {
		if context != nil {
			_ = windows.CertFreeCertificateContext(context)
		}
	}()
	for {
		// The enumerator releases the previous context including at end of store.
		context, err = windows.CertEnumCertificatesInStore(store, context)
		if context == nil {
			if len(certificates) == 0 || !errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil, vault.ErrFormat
			}
			return certificates, nil
		}
		if len(certificates) >= 8 || context.EncodedCert == nil || context.Length == 0 || context.Length > 32<<10 {
			return nil, vault.ErrFormat
		}
		der := bytes.Clone(unsafe.Slice(context.EncodedCert, context.Length))
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, vault.ErrFormat
		}
		certificates = append(certificates, certificate)
	}
}
