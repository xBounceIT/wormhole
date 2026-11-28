package sharedpg

import (
	"bytes"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestCachedPolicyPreventsPreloginTransportDowngrade(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	_, _, state, a, r, priv := trustFixture(t)
	requested := settings()
	if _, err := state.PrepareTransport(requested, vault.Default, vault.Default, 1); err != ErrConfiguration {
		t.Fatal("standard policy permitted plaintext prelogin")
	}
	requested.TLS = TLSEncrypted
	if _, err := state.PrepareTransport(requested, vault.Default, vault.Default, 1); err != ErrConfiguration {
		t.Fatal("standard policy permitted unverified TLS")
	}
	requested.TLS = TLSVerified
	requested.CAPEM = testCA(t)
	for _, test := range []struct{ os, user, caller, want vault.Profile }{
		{vault.Default, vault.Default, vault.Default, vault.Standard},
		{vault.Hardened, vault.Default, vault.Default, vault.Hardened},
		{vault.Default, vault.Paranoid, vault.Default, vault.Paranoid},
		{vault.Default, vault.Default, vault.Hardened, vault.Hardened},
		{"", vault.Default, vault.Default, vault.Paranoid},
		{vault.Default, "future", vault.Default, vault.Paranoid},
	} {
		requested.Profile = test.caller
		got, err := state.PrepareTransport(requested, test.os, test.user, 1)
		if err != nil || got.Profile != test.want {
			t.Fatalf("floor weakened: %v", err)
		}
	}
	requested.Profile = vault.Default
	prepared, err := state.PrepareTransport(requested, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	originalCA := bytes.Clone(prepared.CAPEM)
	requested.CAPEM[0] ^= 1
	requested.Endpoints[0].Host = "changed.invalid"
	if !bytes.Equal(prepared.CAPEM, originalCA) || prepared.Endpoints[0].Host == requested.Endpoints[0].Host {
		t.Fatal("prepared metadata aliases caller")
	}
	requested = settings()
	resignTrustPolicy(t, a, priv, 8, vault.Default)
	state, err = state.Advance(a, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := state.PrepareTransport(requested, vault.Default, vault.Default, 1); err != nil || got.TLS != TLSOff || got.Profile != vault.Default {
		t.Fatal("signed Default policy could not select plaintext")
	}
}

func TestCachedPolicyPreflightRejectsInvalidInputs(t *testing.T) {
	_, _, state, _, _, _ := trustFixture(t)
	if _, err := state.PrepareTransport(settings(), vault.Default, vault.Default, 0); err != ErrConfiguration {
		t.Fatal("invalid API accepted")
	}
	if _, err := state.PrepareTransport(settings(), vault.Default, vault.Default, 3); err != ErrAPIVersion {
		t.Fatal("unsupported API accepted")
	}
	state.SignedProfile = nil
	if _, err := state.PrepareTransport(settings(), vault.Default, vault.Default, 1); err != ErrTrustState {
		t.Fatal("missing cached profile accepted")
	}
}
