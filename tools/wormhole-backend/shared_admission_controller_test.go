package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedAdmissionProbe struct {
	ctx                context.Context
	cancel             context.CancelFunc
	response           *sharedpg.UnverifiedAdmission
	open               func(context.Context, sharedpg.Settings) error
	start              func(context.Context) error
	closeFailure       atomic.Bool
	opens              atomic.Int32
	starts             atomic.Int32
	closes             atomic.Int32
	loginMaterial      []byte
	accountState       func(context.Context) (*vault.UserKeyState, error)
	accountMaterial    func(context.Context) (*sharedpg.UnverifiedAccountKeys, error)
	enrollmentMaterial func(context.Context) (*sharedpg.UnverifiedAccountKeys, error)
	changePassword     func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error)
	tlsBundle          *sharedpg.VerifiedTLSBundle
	tlsRead            func(context.Context) (*sharedpg.TLSTrustBundle, error)
	subscribe          func(context.Context) error
	hint               func(context.Context) (string, error)
}

func (p *sharedAdmissionProbe) SubscribeChanges(ctx context.Context) error {
	if p.subscribe != nil {
		return p.subscribe(ctx)
	}
	return ctx.Err()
}
func (p *sharedAdmissionProbe) NextChangeHint(ctx context.Context) (string, error) {
	if p.hint != nil {
		return p.hint(ctx)
	}
	<-ctx.Done()
	return "", ctx.Err()
}

func (p *sharedAdmissionProbe) TLSTrustBundle(ctx context.Context) (*sharedpg.TLSTrustBundle, error) {
	if p.tlsRead != nil {
		return p.tlsRead(ctx)
	}
	if p.tlsBundle == nil {
		return nil, sharedpg.ErrTLSMetadata
	}
	raw := p.tlsBundle.Encode()
	bundle, err := sharedpg.DecodeTLSTrustBundle(raw)
	return &bundle, err
}

func (p *sharedAdmissionProbe) ChangePassword(ctx context.Context, plan *sharedpg.PreparedPasswordChange, source string) (*sharedpg.PasswordChangeReceipt, error) {
	if p.changePassword == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return p.changePassword(ctx, plan, source)
}

func (p *sharedAdmissionProbe) expectedMaterial() []byte {
	if p.loginMaterial != nil {
		return p.loginMaterial
	}
	return bytes.Repeat([]byte{7}, 32)
}
func (p *sharedAdmissionProbe) AccountKeyState(ctx context.Context) (*vault.UserKeyState, error) {
	if p.accountState == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return p.accountState(ctx)
}
func (p *sharedAdmissionProbe) AccountUnlockMaterial(ctx context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
	if p.accountMaterial == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return p.accountMaterial(ctx)
}

func (p *sharedAdmissionProbe) AccountEnrollmentMaterial(ctx context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
	if p.enrollmentMaterial == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return p.enrollmentMaterial(ctx)
}

func (p *sharedAdmissionProbe) Open(ctx context.Context, s sharedpg.Settings, login []byte, changes sharedpg.ChangePolicy) error {
	if changes != s.Changes {
		return sharedpg.ErrConfiguration
	}
	expected, _ := sharedpg.EncodeLoginSecret(p.expectedMaterial())
	defer vault.Wipe(expected)
	if !bytes.Equal(login, expected) {
		return sharedpg.ErrConfiguration
	}
	p.opens.Add(1)
	p.tlsBundle = s.TLSBundle
	if p.open != nil {
		return p.open(ctx, s)
	}
	return ctx.Err()
}
func (p *sharedAdmissionProbe) AuthenticateSession(ctx context.Context, _ sharedpg.AdmissionRequest, material []byte) (*sharedpg.UnverifiedAdmission, error) {
	if !bytes.Equal(material, p.expectedMaterial()) {
		return nil, sharedpg.ErrConfiguration
	}
	p.starts.Add(1)
	if p.start != nil {
		if err := p.start(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.response, nil
}
func (p *sharedAdmissionProbe) Close(context.Context) error {
	p.closes.Add(1)
	p.cancel()
	if p.closeFailure.Load() {
		return sharedpg.ErrSessionCleanup
	}
	return nil
}
func (p *sharedAdmissionProbe) Done() <-chan struct{} { return p.ctx.Done() }

func sharedControllerCA(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func sharedControllerFixture(t *testing.T, profile vault.Profile, initialProfile ...vault.Profile) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, sharedpg.TrustState, sharedpg.TrustState) {
	t.Helper()
	t.Setenv("PGSERVICE", "")
	root, b, current, next := sharedTrustFileFixtureWithProfile(t, profile, initialProfile...)
	path := filepath.Join(t.TempDir(), "device.trust")
	if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	probe := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: &sharedpg.UnverifiedAdmission{SessionID: uuid.New(), WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1, Epoch: 1, SignedProfile: bytes.Clone(next.SignedProfile)}}
	c := newSharedAdmissionControllerWithSession(probe)
	t.Cleanup(func() {
		probe.closeFailure.Store(false)
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	options := sharedAdmissionOptions{TrustPath: path, Binding: b, MinimumRevision: 1, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID}, Settings: sharedpg.Settings{Endpoints: []sharedpg.Endpoint{{Host: "localhost", Port: 5432}}, Database: "workspace", DeviceRole: "device_1", TLS: sharedpg.TLSVerified, Profile: vault.Default, CAPEM: sharedControllerCA(t)}, OSFloor: vault.Default, UserFloor: vault.Default}
	return c, probe, options, root, current, next
}

func TestSharedAdmissionPersistsBeforeSuccessAndOwnsRoot(t *testing.T) {
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	p.open = func(_ context.Context, s sharedpg.Settings) error {
		if s.Profile != vault.Standard {
			t.Error("workspace floor lost")
		}
		return nil
	}
	original := bytes.Clone(root)
	if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if !c.Admitted() {
		t.Fatal("admission not published")
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 2)
	if err != nil || state.PolicySequence != 2 {
		t.Fatal("admission preceded persistence")
	}
	memory := c.root
	clear(root)
	if err := memory.With(func(key []byte) error {
		if !bytes.Equal(key, original) {
			t.Error("root aliases caller")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Open(context.Background(), o, original, bytes.Repeat([]byte{7}, 32)); err != sharedpg.ErrSessionStarted {
		t.Fatal("owner opened twice")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Admitted() {
		t.Fatal("closed owner admitted")
	}
	if err := memory.With(func([]byte) error { return nil }); err != securemem.ErrClosed {
		t.Fatal("root survived close")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedAdmissionRefusesBeforeLogin(t *testing.T) {
	for _, scenario := range []string{"missing", "corrupt", "plaintext", "unsupported", "invalid-request"} {
		t.Run(scenario, func(t *testing.T) {
			c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
			switch scenario {
			case "missing":
				if err := os.Remove(o.TrustPath); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(o.TrustPath, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "plaintext":
				o.Settings.TLS = sharedpg.TLSOff
				o.Settings.CAPEM = nil
			case "unsupported":
				o.UserFloor = vault.Hardened
			case "invalid-request":
				o.Request.AppVersion = "bad"
			}
			if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err == nil {
				t.Fatal("unsafe admission accepted")
			}
			if p.opens.Load() != 0 || c.Admitted() {
				t.Fatal("login sent before validation")
			}
		})
	}
}

func TestSharedAdmissionReconnectsWhenLoginRaisesTransportPolicy(t *testing.T) {
	ctx := context.Background()
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard, vault.Default)
	p.open = func(_ context.Context, settings sharedpg.Settings) error {
		if settings.Profile != vault.Default {
			t.Fatal("unexpected initial transport policy")
		}
		return nil
	}
	login := bytes.Repeat([]byte{7}, 32)
	if err := c.Open(ctx, o, root, login); err != sharedpg.ErrProfileChanged || c.Admitted() {
		t.Fatal(err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	freshProbe := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: p.response, open: func(_ context.Context, settings sharedpg.Settings) error {
		if settings.Profile != vault.Standard {
			t.Fatal("did not check the new connection under Standard")
		}
		return nil
	}}
	fresh := newSharedAdmissionControllerWithSession(freshProbe)
	defer fresh.Close(ctx)
	if err := fresh.Open(ctx, o, root, login); err != nil || !fresh.Admitted() {
		t.Fatal(err)
	}
}

func TestSharedAdmissionUsesSignedConnectionBudget(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		initial, next         *uint32
		wantListen, reconnect bool
	}{
		{"legacy enrollment polls", nil, nil, false, false},
		{"direct at threshold", new(uint32(300)), new(uint32(1)), true, false},
		{"direct over threshold", new(uint32(301)), new(uint32(600)), false, false},
		{"transaction pooler", new(uint32(0)), new(uint32(0)), false, false},
		{"direct to pooler", new(uint32(30)), new(uint32(0)), true, true},
		{"back to unknown topology", new(uint32(50)), nil, true, true},
		{"new direct deployment", nil, new(uint32(300)), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, probe, options, root, current, _ := sharedControllerFixture(t, vault.Standard)
			options.Settings.Changes = sharedpg.ChangePolicy{TransactionPooler: true}
			options.TrustPath = filepath.Join(t.TempDir(), "device.trust")
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pin := current.PolicyTrust()
			pin.PublicKey = pub
			policy, err := current.Policy()
			if err != nil {
				t.Fatal(err)
			}
			sign := func(devices *uint32) {
				t.Helper()
				policy.DirectConnectionDevices = devices
				doc, err := vault.SignPolicy(policy, pin.SignerKeyID, pin.SignerKeyVersion, private)
				if err != nil {
					t.Fatal(err)
				}
				probe.response.SignedProfile, err = vault.EncodeSignedPolicy(doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			sign(tc.initial)
			enrolled, err := sharedpg.NewTrustState(probe.response, options.Request, pin)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSharedTrustFile(options.TrustPath, root, options.Binding, enrolled, 0); err != nil {
				t.Fatal(err)
			}
			policy.Sequence++
			sign(tc.next)
			probe.open = func(_ context.Context, settings sharedpg.Settings) error {
				if settings.Changes.UseNotifications() != tc.wantListen {
					t.Fatal("incorrect connection count before authentication")
				}
				return nil
			}
			subscribed := false
			probe.subscribe = func(context.Context) error { subscribed = true; return nil }
			err = c.Open(t.Context(), options, root, bytes.Repeat([]byte{7}, 32))
			if tc.reconnect {
				if err != sharedpg.ErrProfileChanged || c.Admitted() || subscribed {
					t.Fatal("published a session under stale topology", err)
				}
				saved, err := readSharedTrustFile(options.TrustPath, root, options.Binding, 2)
				if err != nil || !bytes.Equal(saved.SignedProfile, probe.response.SignedProfile) {
					t.Fatal("new topology was not persisted", err)
				}
			} else if err != nil || !c.Admitted() || subscribed != tc.wantListen {
				t.Fatal("incorrect notification subscription", err)
			}
		})
	}
}

func TestSharedAdmissionPreservesUnsupportedNewFloor(t *testing.T) {
	for _, profile := range []vault.Profile{vault.Hardened, vault.Paranoid} {
		t.Run(string(profile), func(t *testing.T) {
			c, _, o, root, _, _ := sharedControllerFixture(t, profile)
			if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != errSharedRuntimeUnsupported {
				t.Fatalf("unsupported runtime accepted: %v", err)
			}
			stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 2)
			if err != nil || stored.PolicySequence != 2 {
				t.Fatal("verified new floor forgotten")
			}
			if c.Admitted() {
				t.Fatal("unsupported profile admitted")
			}
			freshCtx, cancel := context.WithCancel(context.Background())
			freshProbe := &sharedAdmissionProbe{ctx: freshCtx, cancel: cancel}
			fresh := newSharedAdmissionControllerWithSession(freshProbe)
			defer fresh.Close(context.Background())
			if err := fresh.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != errSharedRuntimeUnsupported || freshProbe.opens.Load() != 0 {
				t.Fatal("persisted stronger floor was bypassed on next login")
			}
		})
	}
}

func TestSharedAdmissionRejectsInvalidEnrollmentOptions(t *testing.T) {
	for _, material := range [][]byte{nil, []byte("already-encoded"), make([]byte, 31), make([]byte, 33)} {
		c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
		if err := c.Open(context.Background(), o, root, material); err != sharedpg.ErrConfiguration || p.opens.Load() != 0 {
			t.Fatal("malformed login material reached transport")
		}
	}
	for _, change := range []func(*sharedAdmissionOptions){
		func(o *sharedAdmissionOptions) { o.TrustPath = "relative" }, func(o *sharedAdmissionOptions) { o.MinimumRevision = 0 },
		func(o *sharedAdmissionOptions) { o.Binding.UserID = uuid.New() }, func(o *sharedAdmissionOptions) { o.Binding.DeviceID = uuid.New() },
		func(o *sharedAdmissionOptions) { o.Binding.WorkspaceID = uuid.New() },
	} {
		c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
		change(&o)
		if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != sharedpg.ErrConfiguration || p.opens.Load() != 0 {
			t.Fatal("invalid enrollment sent login")
		}
	}
}

func TestSharedAdmissionMemoryLockWarning(t *testing.T) {
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	p.response.MemoryLockWarning = true
	if c.MemoryLockWarning() {
		t.Fatal("warning before admission")
	}
	if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if !c.MemoryLockWarning() {
		t.Fatal("native memory warning was lost")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.MemoryLockWarning() {
		t.Fatal("closed owner exposes stale status")
	}
}

func TestSharedAdmissionDurabilityAndConflicts(t *testing.T) {
	for _, scenario := range []string{"unchanged", "recover", "uncertain", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			c, p, o, root, current, next := sharedControllerFixture(t, vault.Standard)
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			syncs := 0
			privateFileDirectorySync = func(path string) error {
				syncs++
				if scenario == "uncertain" || (scenario == "recover" && syncs == 1) {
					return errors.New("synthetic sync failure")
				}
				return original(path)
			}
			if scenario == "unchanged" {
				p.response.SignedProfile = bytes.Clone(current.SignedProfile)
			}
			if scenario == "conflict" {
				p.start = func(context.Context) error { return writeSharedTrustFile(o.TrustPath, root, o.Binding, next, 1) }
			}
			err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32))
			switch scenario {
			case "uncertain":
				if err != errSharedTrustCommitUncertain || c.Admitted() {
					t.Fatalf("uncertainty accepted: %v", err)
				}
			case "conflict":
				if err != errSharedTrustConflict || c.Admitted() {
					t.Fatalf("conflict accepted: %v", err)
				}
			default:
				if err != nil || !c.Admitted() || syncs == 0 {
					t.Fatalf("durability was not confirmed: %v", err)
				}
			}
		})
	}
}

func TestSharedAdmissionFailuresAndCleanupRetry(t *testing.T) {
	for _, scenario := range []string{"connect", "revoked", "response", "cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
			want := sharedpg.ErrConnection
			switch scenario {
			case "connect":
				p.open = func(context.Context, sharedpg.Settings) error { return want }
			case "revoked":
				want = sharedpg.ErrIdentityUnavailable
				p.start = func(context.Context) error { return want }
			case "response":
				want = sharedpg.ErrProfileAuthentication
				p.response = nil
			case "cleanup":
				want = errSharedAdmissionCleanup
				p.start = func(context.Context) error { return sharedpg.ErrQuery }
				p.closeFailure.Store(true)
			}
			if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != want {
				t.Fatalf("unexpected failure: %v", err)
			}
			if c.Admitted() || p.closes.Load() == 0 {
				t.Fatal("failed admission retained access")
			}
			p.closeFailure.Store(false)
			if err := c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedAdmissionCloseCancelsStartup(t *testing.T) {
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	entered := make(chan struct{})
	p.open = func(ctx context.Context, _ sharedpg.Settings) error { close(entered); <-ctx.Done(); return ctx.Err() }
	result := make(chan error, 1)
	go func() { result <- c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)) }()
	<-entered
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("startup not canceled: %v", err)
	}
	if c.Admitted() {
		t.Fatal("close raced into admitted state")
	}
}

func TestSharedAdmissionTransportInvalidationRetiresRoot(t *testing.T) {
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	if err := c.Open(context.Background(), o, root, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	memory := c.root
	p.cancel()
	if c.Admitted() {
		t.Fatal("dead transport still admitted")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if memory.With(func([]byte) error { return nil }) == securemem.ErrClosed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("invalidation did not retire root")
}

func TestSharedAdmissionContextAndDefaultOwner(t *testing.T) {
	c := newSharedAdmissionController()
	defer c.Close(context.Background())
	if c.Admitted() {
		t.Fatal("unopened default owner admitted")
	}
	if err := c.Close(nil); err != sharedpg.ErrConfiguration {
		t.Fatal("nil close context accepted")
	}
	if err := c.Open(nil, sharedAdmissionOptions{}, nil, nil); err != sharedpg.ErrConfiguration {
		t.Fatal("nil open accepted")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c2, _, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c2.Open(ctx, o, root, bytes.Repeat([]byte{7}, 32)); err != context.Canceled {
		t.Fatal("canceled open accepted")
	}
	c2.gate <- struct{}{}
	short, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if err := c2.Close(short); err != context.DeadlineExceeded {
		t.Fatal("close ignored gate deadline")
	}
	<-c2.gate
	if err := c2.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
