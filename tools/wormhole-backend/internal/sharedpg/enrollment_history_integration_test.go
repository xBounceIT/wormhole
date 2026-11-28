package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Stage two certified generations for an unrelated fixture account. An actual
// enrollment replacement will also update admission and encrypted custody.
func checkEnrollmentHistory(t *testing.T, ctx context.Context, dba *pgconn.PgConn, trust TrustState, actor *vault.UserKeys) {
	t.Helper()
	pin, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := openServerCAOrgCopy(trust, pin.Signer, readRotationFixtureCopy(t, ctx, dba, pin.Signer, trust.Enrollment.Encryption),
		actor.EncryptionPrivate, actor.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(seed)
	pin.UserID = uuid.New()
	pin.MinimumSequence = 2
	old, oldState := historicalEnrollmentFixture(t, pin, seed, "fixture-history", 1)
	next, nextState := historicalEnrollmentFixture(t, pin, seed, "fixture-history", 2)
	user, before, after := []byte(pin.UserID.String()), []byte(old.Rekey.SigningKeyID.String()), []byte(next.Rekey.SigningKeyID.String())
	exec := func(query string, args ...[]byte) {
		t.Helper()
		if result := dba.ExecParams(ctx, query, args, nil, nil, nil).Read(); result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	exec(`INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,$2)`, user, []byte(old.Manifest.Context.LoginName))
	for _, c := range []vault.UserEnrollmentCertificate{old, next} {
		status := "active"
		if c.Rekey.SigningKeyID == old.Rekey.SigningKeyID {
			status = "retired"
		}
		exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key,status)
            VALUES($2::uuid,1,'user-enc',$1::uuid,2,decode($4,'hex'),$6),($3::uuid,1,'user-sign',$1::uuid,1,decode($5,'hex'),$6)`,
			user, []byte(c.Rekey.EncryptionKeyID.String()), []byte(c.Rekey.SigningKeyID.String()),
			hex.AppendEncode(nil, c.Rekey.Public.Encryption), hex.AppendEncode(nil, c.Rekey.Public.Signing), []byte(status))
	}
	writeSelection := func(query string, c vault.UserEnrollmentCertificate, state vault.UserKeyState) {
		t.Helper()
		cert, err := vault.EncodeUserEnrollmentCertificate(c)
		if err != nil {
			t.Fatal(err)
		}
		exec(query, user, []byte(c.Rekey.EncryptionKeyID.String()), []byte(c.Rekey.SigningKeyID.String()), hex.AppendEncode(nil, cert))
		raw, err := vault.EncodeUserKeyState(state)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,$2::bigint,decode($3,'hex'))
            ON CONFLICT(user_id) DO UPDATE SET (state_sequence,signed_state)=(excluded.state_sequence,excluded.signed_state)`,
			user, strconv.AppendUint(nil, state.Sequence, 10), hex.AppendEncode(nil, raw))
	}
	writeSelection(`INSERT INTO wormhole_data.user_enrollments(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,certificate)
        VALUES($1::uuid,$2::uuid,1,$3::uuid,1,decode($4,'hex'))`, old, oldState)
	writeSelection(`UPDATE wormhole_data.user_enrollments SET encryption_key_id=$2::uuid,signing_key_id=$3::uuid,certificate=decode($4,'hex') WHERE user_id=$1::uuid`, next, nextState)
	if result := dba.ExecParams(ctx, `UPDATE wormhole_data.user_enrollments SET signing_key_id=$2::uuid WHERE user_id=$1::uuid`,
		[][]byte{user, before}, nil, nil, nil).Read(); !hasSQLState(result.Err, "WH010", 0) {
		t.Fatal("a historical signing key became the current enrollment", result.Err)
	}
	read := func(account, signer []byte, version string) []byte {
		t.Helper()
		value := readPersonalRotationValue(t, ctx, dba, `SELECT encode(wormhole_data.enrolled_author_certificate($1::uuid,$2::uuid,$3::integer),'hex')`,
			account, signer, []byte(version))
		raw, err := hex.AppendDecode(nil, value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	historical, err := vault.DecodeUserEnrollmentCertificate(read(user, before, "1"))
	if err != nil || !bytes.Equal(historical.Rekey.Public.Signing, old.Rekey.Public.Signing) ||
		vault.VerifyHistoricalUserEnrollmentCertificate(historical, pin) != nil ||
		vault.VerifyUserEnrollmentCertificate(historical, nextState, pin, 1) == nil {
		t.Fatal("the archived certificate must verify only as historical material", err)
	}
	current, err := vault.DecodeUserEnrollmentCertificate(read(user, after, "1"))
	if err != nil || vault.VerifyUserEnrollmentCertificate(current, nextState, pin, 1) != nil {
		t.Fatal("the fresh enrollment was not selected for current use", err)
	}
	if len(read([]byte(trust.UserID.String()), before, "1")) != 0 || len(read(user, before, "2")) != 0 {
		t.Fatal("history returned a certificate for an unrelated account or generation")
	}
}

func historicalEnrollmentFixture(t *testing.T, pin vault.UserKeyTrust, seed []byte, login string, sequence uint64) (vault.UserEnrollmentCertificate, vault.UserKeyState) {
	t.Helper()
	invite := vault.InviteContext{WorkspaceID: pin.WorkspaceID, UserID: pin.UserID, InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: login}
	bootstrap, err := vault.NewInviteBootstrap(pin.Organisation)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	old := vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}
	public, err := old.Public()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: invite, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Bootstrap: public}, seed)
	if err != nil {
		t.Fatal(err)
	}
	org := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(org)
	cert, err := certifyInvitationBootstrap(invite, pin.Signer, public, org)
	if err != nil {
		t.Fatal(err)
	}
	cert.State.Sequence = sequence
	state, err := vault.SignUserKeyState(cert.State, org)
	if err != nil {
		t.Fatal(err)
	}
	keys, rekey, err := vault.PrepareInviteRekey(invite, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	return vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest,
		BootstrapEncryption: cert.Encryption, BootstrapSigning: cert.Signing, Rekey: rekey}, state
}
