package vault

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestPasswordSlotAndRewrap(t *testing.T) {
	ctx := context.Background()
	key := testKey()
	password := []byte("a test password")
	slot, err := CreatePasswordSlot(ctx, "vault", "password", 1, key, password, nil, KDFLow)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPasswordSlot(ctx, "vault", slot, password, nil)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unlock: %v", err)
	}
	Wipe(got)
	if _, err := OpenPasswordSlot(ctx, "vault", slot, []byte("wrong"), nil); err != ErrAuthentication {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := OpenPasswordSlot(ctx, "other", slot, password, nil); err != ErrAuthentication {
		t.Fatalf("vault substitution: %v", err)
	}
	ask := bytes.Repeat([]byte{7}, 32)
	newSlot, err := CreatePasswordSlot(ctx, "vault", "password", 1, key, []byte("new password"), ask, KDFLow)
	if err != nil {
		t.Fatal(err)
	}
	got, err = OpenPasswordSlot(ctx, "vault", newSlot, []byte("new password"), ask)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("ASK unlock: %v", err)
	}
	if _, err := OpenPasswordSlot(ctx, "vault", newSlot, []byte("new password"), nil); err != ErrFormat {
		t.Fatal("missing ASK accepted")
	}
	if bytes.Equal(slot.Salt, newSlot.Salt) {
		t.Fatal("salt reused")
	}
	newSlot.ASKRequired = false
	if _, err := OpenPasswordSlot(ctx, "vault", newSlot, []byte("new password"), nil); err != ErrAuthentication {
		t.Fatal("ASK downgrade accepted")
	}
}

func TestRecoveryRoundTripAndTamper(t *testing.T) {
	key := NewRecoveryKey()
	formatted, err := FormatRecoveryKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecoveryKey(formatted)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("recovery parse length %d: %v", len(formatted), err)
	}
	slot, err := CreateRecoverySlot("vault", "recovery", 2, testKey(), got)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRecoverySlot("vault", slot, key)
	if err != nil || !bytes.Equal(opened, testKey()) {
		t.Fatalf("recovery unlock: %v", err)
	}
	if _, err := OpenRecoverySlot("other", slot, key); err != ErrAuthentication {
		t.Fatal("vault substitution accepted")
	}
	for _, index := range []int{0, 7, 12, 30, 75} {
		corrupt := bytes.Clone(formatted)
		corrupt[index] = '!'
		if _, err := ParseRecoveryKey(corrupt); err == nil {
			t.Fatal("malformed recovery accepted")
		}
	}
	corrupt := bytes.Clone(formatted)
	if corrupt[7] == 'A' {
		corrupt[7] = 'B'
	} else {
		corrupt[7] = 'A'
	}
	if _, err := ParseRecoveryKey(corrupt); err != ErrAuthentication {
		t.Fatalf("checksum: %v", err)
	}
	tail := bytes.Clone(formatted)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	i := strings.IndexByte(alphabet, tail[len(tail)-1])
	tail[len(tail)-1] = alphabet[i+1]
	if _, err := ParseRecoveryKey(tail); err != ErrFormat {
		t.Fatal("noncanonical base32 tail accepted")
	}
	if _, err := ParseRecoveryKey(nil); err != ErrFormat {
		t.Fatal("empty recovery accepted")
	}
	if _, err := FormatRecoveryKey(nil); err != ErrFormat {
		t.Fatal("empty key accepted")
	}
	for _, mutate := range []func(*Slot){func(s *Slot) { s.Kind = SlotPassword }, func(s *Slot) { s.Preset = KDFV1 }, func(s *Slot) { s.ASKRequired = true }, func(s *Slot) { s.FactorIDs = []string{"hardware"} }} {
		s := slot
		mutate(&s)
		if _, err := OpenRecoverySlot("vault", s, key); err != ErrFormat {
			t.Fatal("invalid recovery slot accepted")
		}
	}
}

func TestRecoveryFormatKnownAnswer(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const encoded = "WHREC1-AAAQE-AYEAU-DAOCA-JBIFQ-YDIOB-4IBCE-QTCQK-RMFYY-DENBW-HA5DY-P7W32-THM"
	got, err := FormatRecoveryKey(key)
	if err != nil || string(got) != encoded {
		t.Fatalf("recovery wire format changed: %v", err)
	}
	decoded, err := ParseRecoveryKey([]byte(encoded))
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatalf("known recovery key rejected: %v", err)
	}
	Wipe(decoded)
	Wipe(got)
	for i, value := range key {
		if value != byte(i) {
			t.Fatal("caller key was modified")
		}
	}
}

func TestKDFContractsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		preset             KDFPreset
		memory, iterations uint32
	}{{KDFLow, 65536, 3}, {KDFV1, 262144, 3}, {KDFV2, 524288, 3}, {KDFV3, 1048576, 4}} {
		p, err := Parameters(test.preset)
		if err != nil || p.MemoryKiB != test.memory || p.Iterations != test.iterations || p.Parallelism != 4 {
			t.Fatal("changed KDF preset")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DerivePassword(ctx, []byte("pw"), make([]byte, 32), KDFV1); err != context.Canceled {
		t.Fatal("cancelled derivation ran")
	}
	derivationGate <- struct{}{}
	if _, err := DerivePassword(ctx, []byte("pw"), make([]byte, 32), KDFV1); err != context.Canceled {
		t.Fatal("queued cancellation ignored")
	}
	<-derivationGate
	for _, test := range []struct {
		password, salt []byte
		preset         KDFPreset
	}{{nil, make([]byte, 32), KDFV1}, {[]byte("pw"), nil, KDFV1}, {[]byte("pw"), make([]byte, 32), "future"}, {make([]byte, 1025), make([]byte, 32), KDFV1}} {
		if _, err := DerivePassword(context.Background(), test.password, test.salt, test.preset); err != ErrFormat {
			t.Fatal("unbounded KDF accepted")
		}
	}
}

func TestHKDFKeyCheckAndDomainSeparation(t *testing.T) {
	// RFC 5869 case 1 checks the primitive used by the fixed-purpose wrapper.
	got, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{0x0b}, 22), mustHex(t, "000102030405060708090a0b0c"), string(mustHex(t, "f0f1f2f3f4f5f6f7f8f9")), 42)
	if err != nil || !bytes.Equal(got, mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) {
		t.Fatal("RFC5869 mismatch")
	}
	seen := map[string]bool{}
	for _, purpose := range []KeyPurpose{PurposeLogin, PurposeUnlock, PurposeLocalSeal, PurposeLocalBackup, PurposeKCV, PurposeSQLite, PurposeHello, PurposeTunnelImport, PurposeBrowserState, PurposeSharedTrust, PurposeSharedDeviceRoot, PurposeSharedDeviceSetup} {
		k, err := DeriveKey(testKey(), nil, purpose)
		if err != nil || seen[string(k)] {
			t.Fatal("purpose collision")
		}
		seen[string(k)] = true
	}
	if _, err := DeriveKey(testKey(), nil, "future"); err != ErrFormat {
		t.Fatal("unknown label")
	}
	if _, err := DeriveKey(nil, nil, PurposeKCV); err != ErrFormat {
		t.Fatal("invalid key")
	}
	kcv, err := KeyCheck(testKey(), "vault", "file")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyCheck(testKey(), "vault", "file", kcv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyCheck(testKey(), "vault", "other", kcv); err != ErrAuthentication {
		t.Fatal("file substitution")
	}
	if _, err := KeyCheck(testKey(), "", "file"); err != ErrFormat {
		t.Fatal("empty vault")
	}
	if err := VerifyKeyCheck(nil, "vault", "file", kcv); err != ErrFormat {
		t.Fatal("invalid KCV key")
	}
	if _, err := SharedSalt("11111111-1111-4111-8111-111111111111", "UsEr"); err != ErrFormat {
		t.Fatal("noncanonical name")
	}
	a, err := SharedSalt("11111111-1111-4111-8111-111111111111", "usér")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SharedSalt("22222222-2222-4222-8222-222222222222", "usér")
	if bytes.Equal(a, b) {
		t.Fatal("workspace salt collision")
	}
	if _, err := SharedSalt("11111111-1111-4111-8111-111111111111", "use\u0301r"); err != ErrFormat {
		t.Fatal("non-NFC login accepted")
	}
}

func TestSlotInvalidInputs(t *testing.T) {
	ctx := context.Background()
	if _, err := CreatePasswordSlot(ctx, "v", "id", 1, nil, []byte("pw"), nil, KDFV1); err != ErrFormat {
		t.Fatal("short key")
	}
	if _, err := CreatePasswordSlot(ctx, "v", "", 1, testKey(), []byte("pw"), nil, KDFV1); err != ErrFormat {
		t.Fatal("empty ID")
	}
	if _, err := CreatePasswordSlot(ctx, "v", "id", 1, testKey(), []byte("pw"), nil, "future"); err != ErrFormat {
		t.Fatal("unknown preset")
	}
	if _, err := OpenPasswordSlot(ctx, "v", Slot{}, []byte("pw"), nil); err != ErrFormat {
		t.Fatal("empty slot")
	}
	if _, err := CreateRecoverySlot("v", "id", 1, nil, testKey()); err != ErrFormat {
		t.Fatal("short recovery key")
	}
	if _, err := CreateRecoverySlot(strings.Repeat("x", 1025), "id", 1, testKey(), testKey()); err != ErrFormat {
		t.Fatal("oversized vault")
	}
	if _, err := OpenRecoverySlot("v", Slot{Kind: SlotRecovery}, nil); err != ErrFormat {
		t.Fatal("empty key")
	}
	if _, err := MixAccountSecret(testKey(), []byte{1}, true); err != ErrFormat {
		t.Fatal("short ASK")
	}
	if _, err := MixAccountSecret(testKey(), testKey(), false); err != ErrFormat {
		t.Fatal("unexpected ASK")
	}
	slot := Slot{ID: "id", Kind: SlotRecovery, WrappedKey: Envelope{KeyVersion: 1}}
	slot.WrappedKey, _ = Seal(testKey(), slotBinding("v", slot), []byte("too short"))
	if _, err := openSlot(testKey(), "v", slot); err != ErrFormat {
		t.Fatal("wrong vault key length")
	}
}

func TestMalformedPasswordEnvelopeRejectedBeforeKDF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slot := Slot{ID: "password", Kind: SlotPassword, Preset: KDFV3, Salt: make([]byte, 32), WrappedKey: Envelope{FormatVersion: 1, SuiteID: 1, KeyID: "vault", KeyVersion: 1, Nonce: make([]byte, 12), Ciphertext: make([]byte, 48)}}
	for _, test := range []struct {
		name   string
		mutate func(*Envelope)
		want   error
	}{
		{"newer", func(e *Envelope) { e.FormatVersion = 2 }, ErrNewerFormat},
		{"suite", func(e *Envelope) { e.SuiteID = 99 }, ErrFormat},
		{"nonce", func(e *Envelope) { e.Nonce = nil }, ErrFormat},
		{"length", func(e *Envelope) { e.Ciphertext = make([]byte, 64) }, ErrFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := slot
			test.mutate(&s.WrappedKey)
			if _, err := OpenPasswordSlot(ctx, "vault", s, []byte("password"), nil); err != test.want {
				t.Fatalf("entered KDF before rejecting format: %v", err)
			}
		})
	}
}
