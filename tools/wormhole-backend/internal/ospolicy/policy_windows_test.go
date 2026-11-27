//go:build windows

package ospolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/windows/registry"
)

type fakeRegistry struct {
	raw               []byte
	kind              uint32
	readErr, closeErr error
	closed            int
}

type fakeHelloRootsRegistry struct{ fakeRegistry }

type fakeUpdateRegistry struct{ fakeRegistry }

func (k *fakeUpdateRegistry) GetValue(name string, buf []byte) (int, uint32, error) {
	if name != "ManagedUpdateManifestSHA256" || len(buf) != 132 {
		panic("unexpected managed update policy read")
	}
	copy(buf, k.raw)
	return len(k.raw), k.kind, k.readErr
}

func TestRegistryManagedManifestPolicy(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		key  fakeRegistry
		want string
		err  error
	}{
		{key: fakeRegistry{raw: registryString(strings.ToUpper(digest)), kind: registry.SZ}, want: digest},
		{key: fakeRegistry{readErr: registry.ErrNotExist}},
		{key: fakeRegistry{raw: registryString(digest), kind: registry.EXPAND_SZ}, err: vault.ErrPolicy},
		{key: fakeRegistry{raw: registryString("invalid"), kind: registry.SZ}, err: vault.ErrPolicy},
		{key: fakeRegistry{raw: registryString(digest), kind: registry.SZ, closeErr: errors.New("close failed")}, err: vault.ErrPolicy},
	} {
		key := &fakeUpdateRegistry{tc.key}
		got, err := readRegistryManagedUpdate(context.Background(), func() (registryReader, error) { return key, nil })
		if err != tc.err || got.Digest != tc.want || key.closed != 1 {
			t.Fatalf("unexpected policy result: %+v %v", got, err)
		}
		if tc.want != "" && (!filepath.IsAbs(got.Directory) || filepath.Base(got.Directory) != "Updates") {
			t.Fatal("invalid system staging directory", got.Directory)
		}
	}
}

func (k *fakeHelloRootsRegistry) GetValue(name string, buf []byte) (int, uint32, error) {
	if name != "HelloTPMAttestationRoots" || len(buf) != 64<<10 {
		panic("unbounded or wrong attestation roots read")
	}
	copy(buf, k.raw)
	return len(k.raw), k.kind, k.readErr
}

func TestRegistryHelloRootsAreBoundedCertificateAuthorityRecords(t *testing.T) {
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key := &fakeHelloRootsRegistry{fakeRegistry{raw: der, kind: registry.BINARY}}
	pool, err := readRegistryHelloRoots(ctx, func() (registryReader, error) { return key, nil })
	expected := x509.NewCertPool()
	if cert, err := x509.ParseCertificate(der); err == nil {
		expected.AddCert(cert)
	} else {
		t.Fatal(err)
	}
	if err != nil || pool == nil || !pool.Equal(expected) || key.closed != 1 {
		t.Fatal("machine AIK root was not loaded intact", err)
	}
	ca.IsCA = false
	nonCA, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []fakeRegistry{
		{raw: nonCA, kind: registry.BINARY}, {raw: der, kind: registry.SZ}, {raw: []byte{1}, kind: registry.BINARY},
		{raw: make([]byte, (64<<10)+1), kind: registry.BINARY}, {readErr: registry.ErrShortBuffer},
		{raw: der, kind: registry.BINARY, closeErr: errors.New("fixture")},
	} {
		k := &fakeHelloRootsRegistry{bad}
		if roots, err := readRegistryHelloRoots(ctx, func() (registryReader, error) { return k, nil }); roots != nil || !errors.Is(err, vault.ErrPolicy) || k.closed != 1 {
			t.Fatal("invalid trust policy was accepted", err)
		}
	}
	for _, startErr := range []error{registry.ErrNotExist, errors.New("fixture")} {
		roots, err := readRegistryHelloRoots(ctx, func() (registryReader, error) { return nil, startErr })
		if roots != nil || (startErr == registry.ErrNotExist && err != nil) || (startErr != registry.ErrNotExist && !errors.Is(err, vault.ErrPolicy)) {
			t.Fatal("unexpected query outcome", err)
		}
	}
	key = &fakeHelloRootsRegistry{fakeRegistry{readErr: registry.ErrNotExist}}
	if roots, err := readRegistryHelloRoots(ctx, func() (registryReader, error) { return key, nil }); roots != nil || err != nil || key.closed != 1 {
		t.Fatal("absent value became trust policy", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := readRegistryHelloRoots(canceled, func() (registryReader, error) { t.Fatal("opened after cancellation"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func (k *fakeRegistry) GetValue(name string, buf []byte) (int, uint32, error) {
	if name != "Profile" || len(buf) != 64 {
		panic("unbounded or wrong registry read")
	}
	copy(buf, k.raw)
	return len(k.raw), k.kind, k.readErr
}
func (k *fakeRegistry) Close() error { k.closed++; return k.closeErr }
func registryString(value string) []byte {
	raw := make([]byte, 2*len(value)+2)
	for i, c := range []byte(value) {
		binary.LittleEndian.PutUint16(raw[i*2:], uint16(c))
	}
	return raw
}

func TestRegistryPolicyBoundedNativeContract(t *testing.T) {
	ctx := context.Background()
	for _, p := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid} {
		key := &fakeRegistry{raw: registryString(string(p)), kind: registry.SZ}
		got, err := readRegistryFloor(ctx, func() (registryReader, error) { return key, nil })
		if err != nil || got != p || key.closed != 1 {
			t.Fatal(got, err, key.closed)
		}
	}
	for _, err := range []error{registry.ErrNotExist, errors.New("private failure")} {
		p, got := readRegistryFloor(ctx, func() (registryReader, error) { return nil, err })
		if err == registry.ErrNotExist {
			if p != vault.Default || got != nil {
				t.Fatal(p, got)
			}
		} else if p != "" || got != vault.ErrPolicy {
			t.Fatal(p, got)
		}
	}
	for _, key := range []*fakeRegistry{
		{kind: registry.SZ}, {raw: []byte{1}, kind: registry.SZ}, {raw: make([]byte, 66), kind: registry.SZ},
		{raw: registryString("future"), kind: registry.SZ}, {raw: registryString("default"), kind: registry.EXPAND_SZ},
		{raw: registryString("default"), kind: registry.MULTI_SZ}, {raw: []byte{1, 1, 0, 0}, kind: registry.SZ},
		{raw: registryString("de\x00fault"), kind: registry.SZ}, {raw: []byte{'a', 0, 'b', 0}, kind: registry.SZ},
		{readErr: registry.ErrShortBuffer}, {readErr: errors.New("private")},
		{raw: registryString("default"), kind: registry.SZ, closeErr: errors.New("private")},
	} {
		p, err := readRegistryFloor(ctx, func() (registryReader, error) { return key, nil })
		if p != "" || err != vault.ErrPolicy || key.closed != 1 {
			t.Fatal(p, err, key.closed)
		}
	}
	key := &fakeRegistry{readErr: registry.ErrNotExist}
	if p, err := readRegistryFloor(ctx, func() (registryReader, error) { return key, nil }); p != vault.Default || err != nil || key.closed != 1 {
		t.Fatal(p, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	key = &fakeRegistry{}
	if _, err := readRegistryFloor(canceled, func() (registryReader, error) { return key, nil }); err != context.Canceled || key.closed != 1 {
		t.Fatal(err)
	}
}
