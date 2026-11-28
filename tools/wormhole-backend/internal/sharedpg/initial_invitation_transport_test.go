package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestInitialInvitationTransportEnforcesLocalFloorsBeforeAnyLogin(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, mode := range []TLSMode{TLSOff, TLSEncrypted, TLSVerified} {
		for _, floor := range []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid, "unknown", ""} {
			for _, os := range []bool{false, true} {
				for _, acknowledged := range []bool{false, true} {
					t.Run(string(mode)+"/"+string(floor)+map[bool]string{false: "/user", true: "/os"}[os]+map[bool]string{false: "/unconfirmed", true: "/confirmed"}[acknowledged], func(t *testing.T) {
						i, _ := enrollmentInvitationFixture(t)
						i.TLS = mode
						i.CAPEM = nil
						if mode == TLSVerified {
							i.CAPEM = testCA(t)
						}
						code := bytes.Repeat([]byte{41}, vault.InviteCodeBytes)
						osFloor, userFloor := vault.Default, floor
						if os {
							osFloor, userFloor = floor, vault.Default
						}
						settings, login, err := initialInvitationLogin(i, code, osFloor, userFloor, acknowledged)
						defer vault.Wipe(login)
						allowed := (floor == vault.Default || floor == vault.Standard) && (floor != vault.Standard || mode == TLSVerified) && (mode != TLSOff || acknowledged)
						if !allowed {
							if err == nil || len(login) != 0 || len(settings.Endpoints) != 0 {
								t.Fatal("disallowed invitation returned login material")
							}
							// Rejection must not consume a Session's sole open attempt.
							s := NewSession()
							defer s.Close(context.Background())
							if err := s.OpenInitialInvitation(context.Background(), i, code, osFloor, userFloor, acknowledged); err == nil || s.started {
								t.Fatal("disallowed transport reached session startup")
							}
							return
						}
						if err != nil {
							t.Fatal("allowed invitation transport", err)
						}
						role, _ := i.EnrollmentRole(time.Now())
						_, expected, err := i.EnrollmentLogin(code, time.Now())
						defer vault.Wipe(expected)
						if err != nil || !bytes.Equal(login, expected) || settings.Profile != floor || settings.DeviceRole != role || settings.TLS != mode {
							t.Fatal("native invitation transport changed identity or profile")
						}
						config, err := Config(settings)
						if err != nil || config.RequireAuth != "scram-sha-256" || (mode != TLSOff && config.ChannelBinding != "require") || (mode == TLSVerified && config.TLSConfig.InsecureSkipVerify) {
							t.Fatal("initial enrollment weakened SCRAM or TLS")
						}
						i.Endpoints[0].Host = "changed.invalid"
						if settings.Endpoints[0].Host == i.Endpoints[0].Host || !bytes.Equal(code, bytes.Repeat([]byte{41}, vault.InviteCodeBytes)) {
							t.Fatal("transport retained mutable input or consumed borrowed code")
						}
					})
				}
			}
		}
	}
}

func TestInitialInvitationTransportGuards(t *testing.T) {
	i, _ := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{42}, vault.InviteCodeBytes)
	s := NewSession()
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := (*Session)(nil).OpenInitialInvitation(context.Background(), i, code, vault.Default, vault.Default, true); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil session", err)
	}
	if err := s.OpenInitialInvitation(nil, i, code, vault.Default, vault.Default, true); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil context", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.OpenInitialInvitation(ctx, i, code, vault.Default, vault.Default, true); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context", err)
	}
	if err := s.OpenInitialInvitation(context.Background(), i, nil, vault.Default, vault.Default, true); !errors.Is(err, ErrInvitation) {
		t.Fatal("invalid code", err)
	}
	if err := s.OpenInitialInvitation(context.Background(), i, code, vault.Default, vault.Default, true); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("validated transport must preserve session lifetime", err)
	}
	i.ExpiresAt = 1
	if _, login, err := initialInvitationLogin(i, code, vault.Default, vault.Default, true); err == nil || len(login) != 0 {
		t.Fatal("expired invitation returned login material")
	}
}
