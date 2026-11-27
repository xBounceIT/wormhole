package sharedpg

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresGeneratedSCRAMVerifierIntegration(t *testing.T) {
	s, adminSecret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	// Synthetic test-only role. Supply the verifier as a bound parameter rather
	// than interpolating credentials into the Go-side SQL command text.
	if _, err := admin.Exec(ctx, `CREATE ROLE wh_verifier_device LOGIN CONNECTION LIMIT 3;
CREATE FUNCTION pg_temp.set_verifier(value text) RETURNS void LANGUAGE plpgsql AS $body$
BEGIN EXECUTE pg_catalog.format('ALTER ROLE wh_verifier_device PASSWORD %L',value); END
$body$;`).ReadAll(); err != nil {
		t.Fatal(err)
	}
	setVerifier := func(verifier []byte) {
		t.Helper()
		if ValidateSCRAMVerifier(verifier) != nil {
			t.Fatal("invalid generated verifier")
		}
		if result := admin.ExecParams(ctx, "SELECT pg_temp.set_verifier($1::text)", [][]byte{verifier}, nil, nil, nil).Read(); result.Err != nil {
			t.Fatal("cannot set test verifier")
		}
		result := admin.ExecParams(ctx, "SELECT (rolpassword=$1::text)::text FROM pg_catalog.pg_authid WHERE rolname='wh_verifier_device'", [][]byte{verifier}, nil, nil, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != "true" {
			t.Fatal("server did not store the prehashed verifier verbatim")
		}
	}
	// Exercise the actual native password/ASK derivation before PostgreSQL SCRAM,
	// rather than starting from an arbitrary synthetic 32-byte master.
	d, policy := masterDerivationFixture()
	d.ASKRequired = true
	policy.ASKRequired = true
	owner, err := DeriveAccountMaster(ctx, d, policy, []byte("native-postgres-password"), bytes.Repeat([]byte{73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	var derived []byte
	err = owner.Use(func(master []byte, _ vault.KDFPreset, _ bool) error {
		var e error
		derived, e = vault.DeriveKey(master, nil, vault.PurposeLogin)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(derived)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSCRAMVerifier(derived)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	login, err := EncodeLoginSecret(derived)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	setVerifier(verifier)
	s.DeviceRole = "wh_verifier_device"
	device, err := Connect(ctx, s, login)
	if err != nil {
		t.Fatal("generated verifier did not authenticate")
	}
	defer device.Close(context.Background())
	wrong := append([]byte(nil), login...)
	defer vault.Wipe(wrong)
	wrong[0] ^= 1
	if conn, err := Connect(ctx, s, wrong); err != ErrAuthentication {
		if conn != nil {
			_ = conn.Close(ctx)
		}
		t.Fatal("wrong derived login accepted")
	}
	nextDerived, err := vault.DeriveKey(bytes.Repeat([]byte{8}, 32), nil, vault.PurposeLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(nextDerived)
	nextVerifier, err := NewSCRAMVerifier(nextDerived)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(nextVerifier)
	nextLogin, err := EncodeLoginSecret(nextDerived)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(nextLogin)
	setVerifier(nextVerifier)
	if conn, err := Connect(ctx, s, login); err != ErrAuthentication {
		if conn != nil {
			_ = conn.Close(ctx)
		}
		t.Fatal("old login accepted by new connection after verifier replacement")
	}
	next, err := Connect(ctx, s, nextLogin)
	if err != nil {
		t.Fatal("replacement verifier did not authenticate")
	}
	defer next.Close(context.Background())
	// Verifier replacement only affects authentication of new connections.
	// The eventual password-change API must separately retire admitted sessions.
	if _, err := device.Exec(ctx, "SELECT 1").ReadAll(); err != nil {
		t.Fatal("unexpected PostgreSQL session semantics")
	}
}
