//go:build windows

package ospolicy

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type registryReader interface {
	GetValue(string, []byte) (int, uint32, error)
	Close() error
}

func readFloor(ctx context.Context) (vault.Profile, error) {
	return readRegistryFloor(ctx, openMachinePolicy)
}

func openMachinePolicy() (registryReader, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Wormhole`, registry.QUERY_VALUE|registry.WOW64_64KEY)
}

// ReadHelloTPMAttestationRoots loads administrator-selected AIK roots only.
// The user's certificate stores and the certificate chain carried by Windows
// Hello cannot add trust anchors.
func ReadHelloTPMAttestationRoots(ctx context.Context) (*x509.CertPool, error) {
	return readRegistryHelloRoots(ctx, openMachinePolicy)
}

func readRegistryHelloRoots(ctx context.Context, open func() (registryReader, error)) (roots *x509.CertPool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := open()
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, vault.ErrPolicy
	}
	defer func() {
		if key.Close() != nil {
			roots, err = nil, vault.ErrPolicy
		}
	}()
	var raw [64 << 10]byte
	n, kind, err := key.GetValue("HelloTPMAttestationRoots", raw[:])
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil || kind != registry.BINARY || n <= 0 || n > len(raw) {
		return nil, vault.ErrPolicy
	}
	certificates, err := x509.ParseCertificates(raw[:n])
	if err != nil || len(certificates) < 1 || len(certificates) > 8 {
		return nil, vault.ErrPolicy
	}
	pool := x509.NewCertPool()
	for _, cert := range certificates {
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, vault.ErrPolicy
		}
		pool.AddCert(cert)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pool, nil
}

func readManagedUpdate(ctx context.Context) (ManagedUpdate, error) {
	return readRegistryManagedUpdate(ctx, openMachinePolicy)
}

func readRegistryManagedUpdate(ctx context.Context, open func() (registryReader, error)) (ManagedUpdate, error) {
	var buf [132]byte // 64 hex digits and a UTF-16 NUL, with one spare code unit.
	value, err := readRegistryPolicyString(ctx, open, "ManagedUpdateManifestSHA256", buf[:])
	if value == "" || err != nil {
		return ManagedUpdate{}, err
	}
	digest, err := parseManagedUpdateDigest([]byte(value))
	if err != nil {
		return ManagedUpdate{}, err
	}
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(dir) {
		return ManagedUpdate{}, vault.ErrPolicy
	}
	return ManagedUpdate{Directory: filepath.Join(dir, "Wormhole", "Updates"), Digest: digest}, nil
}

func readRegistryFloor(ctx context.Context, open func() (registryReader, error)) (vault.Profile, error) {
	var buf [64]byte
	value, err := readRegistryPolicyString(ctx, open, "Profile", buf[:])
	if err != nil {
		return "", err
	}
	if value == "" {
		return vault.Default, nil
	}
	return profile(value)
}

func readRegistryPolicyString(ctx context.Context, open func() (registryReader, error), name string, buf []byte) (value string, err error) {
	key, err := open()
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", vault.ErrPolicy
	}
	defer func() {
		if closeErr := key.Close(); closeErr != nil {
			value, err = "", vault.ErrPolicy
		}
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Fixed storage and no environment expansion. Policy strings are ASCII.
	n, kind, err := key.GetValue(name, buf)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil || kind != registry.SZ || n < 4 || n > len(buf) || n%2 != 0 || buf[n-1] != 0 || buf[n-2] != 0 {
		return "", vault.ErrPolicy
	}
	decoded := make([]byte, n/2-1)
	for i := range decoded {
		c := binary.LittleEndian.Uint16(buf[i*2:])
		if c == 0 || c > 127 {
			return "", vault.ErrPolicy
		}
		decoded[i] = byte(c)
	}
	return string(decoded), nil
}
