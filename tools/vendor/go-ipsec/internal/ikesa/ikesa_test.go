package ikesa

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestPRF_RFC4231 pins PRF_HMAC_SHA2_256 to RFC 4231 test case 2.
func TestPRF_RFC4231(t *testing.T) {
	got := prf([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want := mustHex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if !bytes.Equal(got, want) {
		t.Fatalf("prf mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestInteg_RFC4868 checks AUTH_HMAC_SHA2_256_128 truncates to the first 128
// bits of the RFC 4231 case-2 HMAC.
func TestInteg_RFC4868(t *testing.T) {
	got := integ([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want := mustHex(t, "5bdcc146bf60754e6a042426089575c7")
	if !bytes.Equal(got, want) {
		t.Fatalf("integ mismatch:\n got %x\nwant %x", got, want)
	}
	if len(got) != integICVLen {
		t.Fatalf("ICV len = %d, want %d", len(got), integICVLen)
	}
}

// TestAESCBC_RFC3602 decrypts the RFC 3602 §4 case-1 vector.
func TestAESCBC_RFC3602(t *testing.T) {
	key := mustHex(t, "06a9214036b8a15b512e03d534120006")
	iv := mustHex(t, "3dafba429d9eb430b422da802c9fac41")
	ct := mustHex(t, "e353779c1079aeb82708942dbe77181a")
	pt, err := aesCBCDecrypt(key, append(iv, ct...))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "Single block msg" {
		t.Fatalf("decrypt = %q, want %q", pt, "Single block msg")
	}
	// And the encrypt direction round-trips (random IV).
	enc, err := aesCBCEncrypt(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	back, err := aesCBCDecrypt(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"), enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatal("AES-CBC round-trip mismatch")
	}
}

// TestPrfPlus checks the prf+ chaining against an independent reference
// computed straight from the prf primitive.
func TestPrfPlus(t *testing.T) {
	key := []byte("0123456789abcdef")
	seed := []byte("seed-material")
	const n = 100

	ref := func() []byte {
		var out, prev []byte
		for i := byte(1); len(out) < n; i++ {
			h := hmac.New(sha256.New, key)
			h.Write(prev)
			h.Write(seed)
			h.Write([]byte{i})
			prev = h.Sum(nil)
			out = append(out, prev...)
		}
		return out[:n]
	}()

	got := prfPlus(key, seed, n)
	if !bytes.Equal(got, ref) {
		t.Fatalf("prf+ mismatch:\n got %x\nwant %x", got, ref)
	}
	if len(got) != n {
		t.Fatalf("prf+ len = %d, want %d", len(got), n)
	}
}

// TestDH checks the MODP-2048 constant is well-formed and the exchange agrees.
func TestDH(t *testing.T) {
	if modp2048P.BitLen() != 2048 {
		t.Fatalf("MODP-2048 prime bit length = %d, want 2048", modp2048P.BitLen())
	}
	// g^2 mod p == 4, a cheap sanity check that the prime is intact.
	if got := new(big.Int).Exp(modp2048G, big.NewInt(2), modp2048P); got.Cmp(big.NewInt(4)) != 0 {
		t.Fatalf("g^2 mod p = %s, want 4", got)
	}

	a, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Public) != modp2048Len {
		t.Fatalf("public value length = %d, want %d", len(a.Public), modp2048Len)
	}
	sa, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("DH shared secrets disagree")
	}
	if len(sa) != modp2048Len {
		t.Fatalf("shared secret length = %d, want %d", len(sa), modp2048Len)
	}
	// Degenerate peer values must be rejected.
	for _, bad := range [][]byte{{}, {1}, leftPad([]byte{1}, modp2048Len)} {
		if _, err := a.Shared(bad); err == nil {
			t.Fatalf("Shared(%x) accepted a degenerate peer value", bad)
		}
	}
}

// TestDeriveRekeyIKE checks that the IKE-SA rekey derivation (RFC 7296 §2.18)
// agrees across roles, differs from the initial derivation, and can move the
// new SA to any negotiable suite (a rekey may change the envelope suite).
func TestDeriveRekeyIKE(t *testing.T) {
	ni := bytes.Repeat([]byte{0x77}, 32)
	nr := bytes.Repeat([]byte{0x88}, 32)
	dh := bytes.Repeat([]byte{0x99}, modp2048Len)

	// An initial (CBC) SA gives us an SK_d to key the rekey SKEYSEED.
	base := &IKESA{}
	if err := base.Derive(SuiteAESCBC256SHA256, Initiator, 1, 2, ni, nr, dh); err != nil {
		t.Fatal(err)
	}

	newNi := bytes.Repeat([]byte{0xAA}, 32)
	newNr := bytes.Repeat([]byte{0xBB}, 32)
	newDH := bytes.Repeat([]byte{0xCC}, modp2048Len)
	const spii, spir = 0xDEAD, 0xBEEF

	for _, suite := range allSuites {
		t.Run(suite.String(), func(t *testing.T) {
			ri, err := DeriveRekeyIKE(suite, base.SKd, Initiator, spii, spir, newNi, newNr, newDH)
			if err != nil {
				t.Fatal(err)
			}
			rr, err := DeriveRekeyIKE(suite, base.SKd, Responder, spii, spir, newNi, newNr, newDH)
			if err != nil {
				t.Fatal(err)
			}
			if ri.Suite != suite || rr.Suite != suite {
				t.Fatalf("rekeyed SA suite = %v/%v, want %v", ri.Suite, rr.Suite, suite)
			}
			if !bytes.Equal(ri.SKei, rr.SKei) || !bytes.Equal(ri.SKar, rr.SKar) || !bytes.Equal(ri.SKd, rr.SKd) {
				t.Fatal("rekey derivation disagrees across roles")
			}
			if bytes.Equal(ri.SKd, base.SKd) {
				t.Fatal("rekeyed SK_d must differ from the original")
			}
			// And the rekeyed SAs encrypt/decrypt across roles.
			sk, err := ri.EncryptToSK([]byte("rekey payload"))
			if err != nil {
				t.Fatal(err)
			}
			msg := skFrame(sk)
			if err := ri.FinalizeSK(msg, len(sk)); err != nil {
				t.Fatal(err)
			}
			got, icvOK, err := rr.OpenSK(msg, msg[len(msg)-len(sk):])
			if err != nil || !icvOK || string(got) != "rekey payload" {
				t.Fatalf("rekey SK round-trip failed: icvOK=%v err=%v got=%q", icvOK, err, got)
			}
		})
	}
}

// TestDeriveChildKeysPFS checks the PFS Child-key derivation folds the DH shared
// secret into KEYMAT (RFC 7296 §2.17): it is deterministic, differs from the
// non-PFS derivation over the same nonces, and changes when the shared secret
// changes.
func TestDeriveChildKeysPFS(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dhShared := bytes.Repeat([]byte{0x33}, modp2048Len)

	sa := &IKESA{}
	if err := sa.Derive(SuiteAESCBC256SHA256, Initiator, 1, 2, ni, nr, bytes.Repeat([]byte{0x44}, modp2048Len)); err != nil {
		t.Fatal(err)
	}

	pfs := sa.DeriveChildKeysPFS(dhShared, ni, nr, 32, 32)
	// Deterministic.
	if again := sa.DeriveChildKeysPFS(dhShared, ni, nr, 32, 32); !bytes.Equal(pfs.EncrIR, again.EncrIR) {
		t.Fatal("PFS child key derivation is not deterministic")
	}
	// Differs from the non-PFS derivation over the same nonces.
	if nonpfs := sa.DeriveChildKeys(ni, nr, 32, 32); bytes.Equal(pfs.EncrIR, nonpfs.EncrIR) {
		t.Fatal("PFS derivation must differ from non-PFS (DH secret not folded)")
	}
	// Changes when the shared secret changes.
	if other := sa.DeriveChildKeysPFS(bytes.Repeat([]byte{0x55}, modp2048Len), ni, nr, 32, 32); bytes.Equal(pfs.EncrIR, other.EncrIR) {
		t.Fatal("PFS derivation insensitive to the DH shared secret")
	}
	// All four directional keys are populated at the requested length.
	for _, k := range [][]byte{pfs.EncrIR, pfs.IntegIR, pfs.EncrRI, pfs.IntegRI} {
		if len(k) != 32 {
			t.Fatalf("key length = %d, want 32", len(k))
		}
	}
}

// TestDHSharedRejectsWrongLength: a peer DH public must be exactly the group's
// public length; a short/long value (a different group, or a truncated/malformed
// KE) is rejected rather than SetBytes-parsed into an in-range integer the peer
// never sent (group 14) or fed to X25519 with a non-32-byte key (group 31), either
// of which would silently mismatch KEYMAT.
func TestDHSharedRejectsWrongLength(t *testing.T) {
	dh, err := NewDH(DHGroup14)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dh.Shared(dh.Public); err != nil {
		t.Fatalf("valid-length Shared rejected: %v", err)
	}
	// Wrong-length but otherwise in-range values, so only the length check (not the
	// degenerate-value range check) can reject them: drop the trailing byte, and
	// prepend a zero byte (same magnitude, padded to 257 bytes).
	short := dh.Public[:modp2048Len-1]
	long := append([]byte{0}, dh.Public...)
	if _, err := dh.Shared(short); err == nil {
		t.Fatalf("Shared accepted a %d-byte (short) public", len(short))
	}
	if _, err := dh.Shared(long); err == nil {
		t.Fatalf("Shared accepted a %d-byte (long) public", len(long))
	}

	// Group 31: a 32-byte public is accepted; 31 and 33 bytes are rejected.
	x, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Public) != x25519Len {
		t.Fatalf("x25519 public length = %d, want %d", len(x.Public), x25519Len)
	}
	if _, err := x.Shared(x.Public); err != nil {
		t.Fatalf("valid-length x25519 Shared rejected: %v", err)
	}
	if _, err := x.Shared(x.Public[:x25519Len-1]); err == nil {
		t.Fatalf("x25519 Shared accepted a %d-byte (short) public", x25519Len-1)
	}
	if _, err := x.Shared(append([]byte{0}, x.Public...)); err == nil {
		t.Fatalf("x25519 Shared accepted a %d-byte (long) public", x25519Len+1)
	}
}

// TestX25519DHRoundTrip checks the group-31 exchange agrees across both ends and
// yields a 32-byte shared secret (RFC 7748).
func TestX25519DHRoundTrip(t *testing.T) {
	a, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDH(DHGroup31)
	if err != nil {
		t.Fatal(err)
	}
	if a.Group != DHGroup31 || len(a.Public) != x25519Len {
		t.Fatalf("group=%d publicLen=%d, want group 31 / %d-byte public", a.Group, len(a.Public), x25519Len)
	}
	sa, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("x25519 shared secrets disagree")
	}
	if len(sa) != x25519Len {
		t.Fatalf("x25519 shared secret length = %d, want %d", len(sa), x25519Len)
	}
}

// TestNewDHUnsupportedGroup: NewDH rejects a group the client cannot run.
func TestNewDHUnsupportedGroup(t *testing.T) {
	for _, g := range []uint16{0, 1, 18, 30, 32} {
		if _, err := NewDH(g); err == nil {
			t.Fatalf("NewDH(%d) accepted an unsupported group", g)
		}
	}
}

// allSuites enumerates every negotiable SK{} envelope suite.
var allSuites = []Suite{SuiteAESCBC256SHA256, SuiteAESGCM256, SuiteChaCha20Poly1305}

// skFrame wraps an EncryptToSK body into a minimal fake message frame — a
// 28-byte header plus a 4-byte generic SK header, filled with deterministic
// bytes (they become the AEAD AAD) — the shape FinalizeSK and OpenSK expect.
// ikesa deliberately does not depend on the ikemsg codec, so tests hand-build
// the frame.
func skFrame(body []byte) []byte {
	frame := make([]byte, ikeHdrLen+genericHdrLen, ikeHdrLen+genericHdrLen+len(body))
	for i := range frame {
		frame[i] = byte(i)
	}
	return append(frame, body...)
}

// TestSKRoundTrip exercises the full SK{} envelope for every suite: derive
// keys, encrypt a plaintext, finalize, open across roles — and reject a
// tampered header (AAD), body (IV/ciphertext) or trailing ICV/tag with
// icvOK=false so the session layer's grace-decode retry semantics hold.
func TestSKRoundTrip(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dh := bytes.Repeat([]byte{0x33}, modp2048Len)

	for _, suite := range allSuites {
		t.Run(suite.String(), func(t *testing.T) {
			init := &IKESA{}
			if err := init.Derive(suite, Initiator, 0xAAAA, 0xBBBB, ni, nr, dh); err != nil {
				t.Fatal(err)
			}
			resp := &IKESA{}
			if err := resp.Derive(suite, Responder, 0xAAAA, 0xBBBB, ni, nr, dh); err != nil {
				t.Fatal(err)
			}
			// Both ends must derive identical key material.
			if !bytes.Equal(init.SKei, resp.SKei) || !bytes.Equal(init.SKar, resp.SKar) {
				t.Fatal("derived keys disagree across roles")
			}

			for _, ptLen := range []int{0, 1, 15, 16, 17, 31, 200} {
				plain := bytes.Repeat([]byte{0x5A}, ptLen)
				sk, err := init.EncryptToSK(plain)
				if err != nil {
					t.Fatalf("encrypt len %d: %v", ptLen, err)
				}
				if suite.aead() {
					// AEAD framing: IV(8) | plaintext | padLen(0) | tag(16), no alignment.
					if len(sk) != aeadIVLen+ptLen+1+aeadTagLen {
						t.Fatalf("AEAD SK body len %d for pt len %d, want %d", len(sk), ptLen, aeadIVLen+ptLen+1+aeadTagLen)
					}
				} else if (len(sk)-integICVLen-aesBlock)%aesBlock != 0 {
					// CBC: IV + ≥1 block + ICV, block-aligned in the middle.
					t.Fatalf("SK body not block aligned for len %d", ptLen)
				}

				msg := skFrame(sk)
				if err := init.FinalizeSK(msg, len(sk)); err != nil {
					t.Fatalf("finalize len %d: %v", ptLen, err)
				}
				got, icvOK, err := resp.OpenSK(msg, msg[len(msg)-len(sk):])
				if err != nil || !icvOK {
					t.Fatalf("open len %d: icvOK=%v err=%v", ptLen, icvOK, err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("round-trip mismatch len %d:\n got %x\nwant %x", ptLen, got, plain)
				}

				// Tamper the header (the AEAD AAD / CBC ICV coverage), the first
				// body byte (the IV) and the trailing tag/ICV byte → every one must
				// fail with icvOK=false.
				for _, idx := range []int{0, ikeHdrLen + genericHdrLen, len(msg) - 1} {
					bad := append([]byte{}, msg...)
					bad[idx] ^= 0xFF
					if _, badOK, err := resp.OpenSK(bad, bad[len(bad)-len(sk):]); err == nil || badOK {
						t.Fatalf("tampered byte %d accepted for len %d (icvOK=%v err=%v)", idx, ptLen, badOK, err)
					}
				}
			}
		})
	}
}

// TestDeriveKeyLengthsPerSuite pins the RFC 5282 §7 key schedule: the AEAD
// suites derive 36-byte SK_e* (32-byte key + 4-byte salt from the END of the
// material) and NO SK_a*, while the CBC suite keeps 32/32; SK_d and SK_p* are
// always the 32-byte PRF size. The directional salts must come from the tail
// of the corresponding SK_e*.
func TestDeriveKeyLengthsPerSuite(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dh := bytes.Repeat([]byte{0x33}, modp2048Len)

	cases := []struct {
		suite      Suite
		encr, ineg int
	}{
		{SuiteAESCBC256SHA256, 32, 32},
		{SuiteAESGCM256, 36, 0},
		{SuiteChaCha20Poly1305, 36, 0},
	}
	for _, tc := range cases {
		t.Run(tc.suite.String(), func(t *testing.T) {
			s := &IKESA{}
			if err := s.Derive(tc.suite, Initiator, 1, 2, ni, nr, dh); err != nil {
				t.Fatal(err)
			}
			if s.Suite != tc.suite {
				t.Fatalf("Suite = %v, want %v", s.Suite, tc.suite)
			}
			if len(s.SKei) != tc.encr || len(s.SKer) != tc.encr {
				t.Fatalf("SK_e lengths %d/%d, want %d", len(s.SKei), len(s.SKer), tc.encr)
			}
			if len(s.SKai) != tc.ineg || len(s.SKar) != tc.ineg {
				t.Fatalf("SK_a lengths %d/%d, want %d", len(s.SKai), len(s.SKar), tc.ineg)
			}
			if len(s.SKd) != prfKeyLen || len(s.SKpi) != prfKeyLen || len(s.SKpr) != prfKeyLen {
				t.Fatalf("SK_d/SK_p lengths %d/%d/%d, want %d", len(s.SKd), len(s.SKpi), len(s.SKpr), prfKeyLen)
			}
			if !tc.suite.aead() {
				return
			}
			if s.outAEAD == nil || s.inAEAD == nil {
				t.Fatal("AEAD primitives not constructed")
			}
			// Initiator role: outbound = SK_ei, inbound = SK_er; salts from the tail.
			if !bytes.Equal(s.outSalt, s.SKei[32:]) || !bytes.Equal(s.inSalt, s.SKer[32:]) {
				t.Fatal("directional salts are not the trailing 4 bytes of SK_e*")
			}
		})
	}
}

// TestAEADIVCounter pins the SK{} nonce discipline: consecutive EncryptToSK
// calls burn strictly increasing IVs (the counter is the sole nonce-uniqueness
// guarantee, together with the never-re-encode retransmit invariant).
func TestAEADIVCounter(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dh := bytes.Repeat([]byte{0x33}, modp2048Len)

	for _, suite := range []Suite{SuiteAESGCM256, SuiteChaCha20Poly1305} {
		t.Run(suite.String(), func(t *testing.T) {
			s := &IKESA{}
			if err := s.Derive(suite, Initiator, 1, 2, ni, nr, dh); err != nil {
				t.Fatal(err)
			}
			sk1, err := s.EncryptToSK([]byte("one"))
			if err != nil {
				t.Fatal(err)
			}
			sk2, err := s.EncryptToSK([]byte("two"))
			if err != nil {
				t.Fatal(err)
			}
			iv1 := binary.BigEndian.Uint64(sk1[:aeadIVLen])
			iv2 := binary.BigEndian.Uint64(sk2[:aeadIVLen])
			if iv2 != iv1+1 {
				t.Fatalf("IVs not monotonic: %d then %d", iv1, iv2)
			}
		})
	}
}

// TestOpenSKAcceptsPeerPadding: RFC 5282 §3 lets the peer pad the AEAD SK
// plaintext (any pad content, self-described by the trailing Pad Length
// octet). We always send padLen=0 but must accept a padded message — and
// reject a pad length that overruns the authenticated plaintext (icvOK=true:
// authentication succeeded, the peer is just malformed).
func TestOpenSKAcceptsPeerPadding(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	dh := bytes.Repeat([]byte{0x33}, modp2048Len)

	for _, suite := range []Suite{SuiteAESGCM256, SuiteChaCha20Poly1305} {
		t.Run(suite.String(), func(t *testing.T) {
			init := &IKESA{}
			if err := init.Derive(suite, Initiator, 1, 2, ni, nr, dh); err != nil {
				t.Fatal(err)
			}
			resp := &IKESA{}
			if err := resp.Derive(suite, Responder, 1, 2, ni, nr, dh); err != nil {
				t.Fatal(err)
			}

			// Hand-build a padded body: IV | plaintext | pad(7) | padLen(7) | tag.
			plain := []byte("padded payload")
			const padLen = 7
			body := make([]byte, aeadIVLen+len(plain)+padLen+1+aeadTagLen)
			binary.BigEndian.PutUint64(body[:aeadIVLen], 42)
			copy(body[aeadIVLen:], plain)
			body[aeadIVLen+len(plain)+padLen] = padLen
			msg := skFrame(body)
			if err := init.FinalizeSK(msg, len(body)); err != nil {
				t.Fatal(err)
			}
			got, icvOK, err := resp.OpenSK(msg, msg[len(msg)-len(body):])
			if err != nil || !icvOK {
				t.Fatalf("padded SK rejected: icvOK=%v err=%v", icvOK, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("padded round-trip mismatch: got %x want %x", got, plain)
			}

			// A pad length exceeding the plaintext is malformed but authenticated:
			// error with icvOK=true (retrying under another SA is pointless).
			bad := make([]byte, aeadIVLen+1+aeadTagLen)
			binary.BigEndian.PutUint64(bad[:aeadIVLen], 43)
			bad[aeadIVLen] = 200
			badMsg := skFrame(bad)
			if err := init.FinalizeSK(badMsg, len(bad)); err != nil {
				t.Fatal(err)
			}
			if _, icvOK, err := resp.OpenSK(badMsg, badMsg[len(badMsg)-len(bad):]); err == nil || !icvOK {
				t.Fatalf("overrunning pad length: icvOK=%v err=%v, want icvOK=true with error", icvOK, err)
			}
		})
	}
}

// TestPRFPlusBlockCount is finding #3: prf+ supports up to the RFC 7296 §2.13
// maximum of 255 blocks; requesting a 256th block would wrap the single-byte
// counter, so the guard panics rather than emit silently-wrong key material.
func TestPRFPlusBlockCount(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	seed := []byte("prf+ block-count seed")

	if got := prfPlus(key, seed, 255*sha256.Size); len(got) != 255*sha256.Size {
		t.Fatalf("prfPlus(255 blocks) = %d bytes, want %d", len(got), 255*sha256.Size)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("prfPlus did not panic past 255 blocks")
		}
	}()
	_ = prfPlus(key, seed, 256*sha256.Size)
}
