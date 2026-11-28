package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func checkPostgresEditSignatures(t *testing.T, ctx context.Context, db *pgconn.PgConn) {
	t.Helper()
	decode := func(s string) []byte {
		t.Helper()
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	check := func(key, msg, sig []byte, want bool) {
		t.Helper()
		r := db.ExecParams(ctx, `SELECT wormhole_data.ed25519_verify(decode($1,'hex'),decode($2,'hex'),decode($3,'hex'))::text`,
			[][]byte{[]byte(hex.EncodeToString(key)), []byte(hex.EncodeToString(msg)), []byte(hex.EncodeToString(sig))}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != strconv.FormatBool(want) {
			t.Fatalf("SQL Ed25519 verification differs from expected %t: %v", want, r.Err)
		}
	}
	// RFC 8032 section 7.1, TEST 1 and TEST 2.
	key := decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	check(key, nil, sig, true)
	check(decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), []byte{0x72},
		decode("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"+"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"), true)
	check(key, []byte{1}, sig, false)
	check(key, nil, sig[:63], false)
	check(key[:31], nil, sig, false)
	check(append([]byte{1}, make([]byte, 31)...), nil, sig, false)
	check(make([]byte, 32), nil, sig, false)
	nonCanonical := bytes.Repeat([]byte{0xff}, 32)
	check(nonCanonical, nil, sig, false)
	check(key, nil, append(nonCanonical, sig[32:]...), false)
	check(key, nil, append(bytes.Clone(sig[:32]), nonCanonical...), false)
	for i := range 12 {
		seed := sha256.Sum256([]byte(strconv.Itoa(i)))
		private := ed25519.NewKeyFromSeed(seed[:])
		message := bytes.Repeat([]byte{byte(i)}, i*37)
		signed := ed25519.Sign(private, message)
		check(private.Public().(ed25519.PublicKey), message, signed, true)
		signed[32+i] ^= 0x40
		check(private.Public().(ed25519.PublicKey), message, signed, false)
	}
}
