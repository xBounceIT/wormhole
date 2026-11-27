package updateauth

import (
	"crypto/sha256"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust                = windows.NewLazySystemDLL("wintrust.dll")
	providerDataFromState   = wintrust.NewProc("WTHelperProvDataFromStateData")
	providerSignerFromChain = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	providerCertFromChain   = wintrust.NewProc("WTHelperGetProvCertFromChain")
	reopenInstallerFile     = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")
)

// LockWindowsInstaller reopens the existing file object with read sharing only.
// Manifest hashing and Authenticode then see the same bytes while it is held.
func LockWindowsInstaller(file *os.File) (*os.File, error) {
	if reopenInstallerFile.Find() != nil {
		return nil, ErrPublisherUnavailable
	}
	handle, _, _ := reopenInstallerFile.Call(file.Fd(), windows.GENERIC_READ, windows.FILE_SHARE_READ, 0)
	runtime.KeepAlive(file)
	if windows.Handle(handle) == windows.InvalidHandle || handle == 0 {
		return nil, ErrArtifact
	}
	return os.NewFile(handle, file.Name()), nil
}

const (
	verifyPrimarySignature = 1 // WSS_VERIFY_SPECIFIC, with index zero.
	strongSigningOIDChoice = 2 // CERT_STRONG_SIGN_OID_INFO_CHOICE.
	maxPublisherCertBytes  = 64 * 1024
)

// VerifyWindowsPublisher asks Windows to validate the primary Authenticode
// signature, then pins the leaf certificate Windows used for that signature.
// The caller retains the same file handle it used to verify the manifest hash.
func VerifyWindowsPublisher(file *os.File, pin PublisherPin) error {
	if pin == (PublisherPin{}) {
		return ErrPublisherUnavailable
	}
	actual, err := windowsPublisherPin(file)
	if err != nil {
		return err
	}
	if actual != pin {
		return ErrPublisherUntrusted
	}
	return nil
}

func windowsPublisherPin(file *os.File) (_ PublisherPin, err error) {
	for _, proc := range []*windows.LazyProc{providerDataFromState, providerSignerFromChain, providerCertFromChain} {
		if proc.Find() != nil {
			return PublisherPin{}, ErrPublisherUnavailable
		}
	}
	path, err := filepath.Abs(file.Name())
	if err != nil {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	fileInfo := windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path16, File: windows.Handle(file.Fd()),
	}
	strongOID := []byte("1.3.6.1.4.1.311.72.1.1\x00") // Microsoft SHA-2 strong-signing policy.
	strongSigning := windows.CertStrongSignPara{
		Size: uint32(unsafe.Sizeof(windows.CertStrongSignPara{})), InfoChoice: strongSigningOIDChoice,
		InfoOrSerializedInfoOrOID: unsafe.Pointer(&strongOID[0]),
	}
	signature := windows.WinTrustSignatureSettings{
		Size: uint32(unsafe.Sizeof(windows.WinTrustSignatureSettings{})), Flags: verifyPrimarySignature, CryptoPolicy: &strongSigning,
	}
	trust := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo), StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_DISABLE_MD2_MD4 | windows.WTD_MOTW,
		UIContext: windows.WTD_UICONTEXT_INSTALL, SignatureSettings: &signature,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust)
	defer func() {
		if trust.StateData != 0 {
			trust.StateAction = windows.WTD_STATEACTION_CLOSE
			if closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust); closeErr != nil && err == nil {
				err = ErrPublisherUntrusted
			}
		}
		runtime.KeepAlive(file)
	}()
	if verifyErr != nil || trust.StateData == 0 || signature.VerifiedSigIndex != 0 {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	provider, _, _ := providerDataFromState.Call(uintptr(trust.StateData))
	if provider == 0 {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	signer, _, _ := providerSignerFromChain.Call(provider, 0, 0, 0)
	if signer == 0 {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	certAddress, _, _ := providerCertFromChain.Call(signer, 0)
	if certAddress == 0 {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	// Prefix of CRYPT_PROVIDER_CERT. Windows owns this pointer until STATEACTION_CLOSE.
	type providerCert struct {
		Size uint32
		Cert *windows.CertContext
	}
	cert := *(**providerCert)(unsafe.Pointer(&certAddress))
	if cert.Size < uint32(unsafe.Sizeof(providerCert{})) || cert.Cert == nil {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	return pinWindowsCertificate(cert.Cert)
}

func pinWindowsCertificate(cert *windows.CertContext) (PublisherPin, error) {
	if cert.EncodingType&windows.X509_ASN_ENCODING == 0 || cert.EncodedCert == nil || cert.Length == 0 || cert.Length > maxPublisherCertBytes {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	x509cert, err := x509.ParseCertificate(unsafe.Slice(cert.EncodedCert, cert.Length))
	if err != nil || !slices.Contains(x509cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return PublisherPin{}, ErrPublisherUntrusted
	}
	return sha256.Sum256(x509cert.RawSubjectPublicKeyInfo), nil
}
