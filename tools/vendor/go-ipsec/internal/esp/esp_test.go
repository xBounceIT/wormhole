package esp

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// allSuites drives the per-suite subtests over every ESP transform this
// package implements.
var allSuites = []Suite{SuiteAESCBC256SHA256, SuiteAESGCM256, SuiteChaCha20Poly1305}

// suiteKeys returns deterministic directional key material sized for the suite:
// 32+32 for CBC+HMAC, 36 (key+salt) with no integrity key for the AEAD suites.
func suiteKeys(suite Suite) (encrIR, integIR, encrRI, integRI []byte) {
	if suite == SuiteAESCBC256SHA256 {
		return bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32),
			bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32)
	}
	return bytes.Repeat([]byte{0x01}, aeadEncrKeyLen), nil,
		bytes.Repeat([]byte{0x03}, aeadEncrKeyLen), nil
}

func newTestSA(t *testing.T, suite Suite, window uint32) (*SA, *SA) {
	t.Helper()
	encrIR, integIR, encrRI, integRI := suiteKeys(suite)
	// init sends with the I→R keys (out SPI 0x1111), receives with the R→I keys
	// (in SPI 0x2222); the responder is the mirror.
	init, err := NewSA(suite, 0x1111, 0x2222, encrIR, integIR, encrRI, integRI, window)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewSA(suite, 0x2222, 0x1111, encrRI, integRI, encrIR, integIR, window)
	if err != nil {
		t.Fatal(err)
	}
	return init, resp
}

func forEachSuite(t *testing.T, fn func(t *testing.T, suite Suite)) {
	t.Helper()
	for _, suite := range allSuites {
		t.Run(suite.String(), func(t *testing.T) { fn(t, suite) })
	}
}

func TestESPRoundTrip(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		for _, n := range []int{0, 1, 2, 14, 15, 16, 20, 1400} {
			inner := bytes.Repeat([]byte{0xAB}, n)
			pkt, err := init.Encrypt(inner)
			if err != nil {
				t.Fatalf("encrypt len %d: %v", n, err)
			}
			got, err := resp.Decrypt(pkt)
			if err != nil {
				t.Fatalf("decrypt len %d: %v", n, err)
			}
			if !bytes.Equal(got, inner) {
				t.Fatalf("round-trip mismatch len %d", n)
			}
		}
	})
}

func TestESPTamper(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		pkt := init.mustEncrypt(t, []byte("hello world inner ip"))
		// flip the last ICV/tag byte
		bad := append([]byte(nil), pkt...)
		bad[len(bad)-1] ^= 0xFF
		if _, err := resp.Decrypt(bad); err == nil {
			t.Fatal("tampered ICV/tag accepted")
		}
		// flip a ciphertext byte → ICV/tag must catch it
		bad2 := append([]byte(nil), pkt...)
		bad2[len(bad2)-espICVLen-1] ^= 0xFF
		if _, err := resp.Decrypt(bad2); err == nil {
			t.Fatal("tampered ciphertext accepted")
		}
	})
}

// TestESPTamperHeaderDoesNotPoisonReplay flips the sequence number's high byte
// (authenticated: part of the CBC ICV scope and of the AEAD associated data).
// Decrypt must fail AND must not have moved the replay window to the forged
// (huge) sequence — the untampered packet still decrypts afterwards. This pins
// the invariant that only authenticated packets move the replay window.
func TestESPTamperHeaderDoesNotPoisonReplay(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		pkt := init.mustEncrypt(t, []byte("replay window probe")) // seq 1
		bad := append([]byte(nil), pkt...)
		bad[4] ^= 0xFF // seq 1 → 0xFF000001, far above the window
		if _, err := resp.Decrypt(bad); err == nil {
			t.Fatal("packet with a tampered sequence number accepted")
		}
		if _, err := resp.Decrypt(pkt); err != nil {
			t.Fatalf("replay window poisoned by an unauthenticated packet: %v", err)
		}
	})
}

func TestESPWrongSPI(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		pkt := resp.mustEncrypt(t, []byte("from responder")) // SPI=0x1111 (init's inSPI)
		if _, err := init.Decrypt(pkt); err != nil {
			t.Fatalf("init should accept responder packet: %v", err)
		}
		p := init.mustEncrypt(t, []byte("x"))
		p[0] ^= 0xFF // corrupt SPI
		if _, err := resp.Decrypt(p); err == nil {
			t.Fatal("wrong SPI accepted")
		}
	})
}

func (sa *SA) mustEncrypt(t *testing.T, b []byte) []byte {
	t.Helper()
	p, err := sa.Encrypt(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// encryptMangled mirrors Encrypt for the SA's suite but lets the test mutate
// the assembled plaintext (trailer included) before encryption, so the decode
// path can be exercised with authentically-protected malformed content.
// Test-only.
func (sa *SA) encryptMangled(t *testing.T, inner []byte, mutate func(plain []byte)) []byte {
	t.Helper()
	seq := sa.seq.Add(1)
	if sa.suite == SuiteAESCBC256SHA256 {
		padLen := (espBlock - (len(inner)+2)%espBlock) % espBlock
		plainLen := len(inner) + padLen + 2
		out := make([]byte, espHeaderLen+cbcIVLen+plainLen+espICVLen)
		binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
		binary.BigEndian.PutUint32(out[4:8], seq)
		iv := out[espHeaderLen : espHeaderLen+cbcIVLen]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			t.Fatal(err)
		}
		ctStart := espHeaderLen + cbcIVLen
		plain := out[ctStart : ctStart+plainLen]
		fillTrailer(plain, inner, padLen)
		mutate(plain)
		cipher.NewCBCEncrypter(sa.outBlock, iv).CryptBlocks(plain, plain)
		mac := hmac.New(sha256.New, sa.outInteg)
		mac.Write(out[:ctStart+plainLen])
		copy(out[ctStart+plainLen:], mac.Sum(nil)[:espICVLen])
		return out
	}
	padLen := (4 - (len(inner)+2)%4) % 4
	plainLen := len(inner) + padLen + 2
	out := make([]byte, espHeaderLen+aeadIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint64(out[espHeaderLen:espHeaderLen+aeadIVLen], uint64(seq))
	var nonce [aeadSaltLen + aeadIVLen]byte
	copy(nonce[:aeadSaltLen], sa.outSalt)
	copy(nonce[aeadSaltLen:], out[espHeaderLen:espHeaderLen+aeadIVLen])
	ctStart := espHeaderLen + aeadIVLen
	plain := out[ctStart : ctStart+plainLen]
	fillTrailer(plain, inner, padLen)
	mutate(plain)
	sa.outAEAD.Seal(plain[:0], nonce[:], plain, out[:espHeaderLen])
	return out
}

func TestESPSeqExhaustion(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, _ := newTestSA(t, suite, 64)
		init.seq.Store(^uint32(0)) // counter pinned at the top of the space
		if _, err := init.Encrypt([]byte("x")); !errors.Is(err, ErrSeqExhausted) {
			t.Fatalf("expected ErrSeqExhausted on wrap, got %v", err)
		}
		// The counter stays pinned, so every subsequent Encrypt also refuses.
		if _, err := init.Encrypt([]byte("y")); !errors.Is(err, ErrSeqExhausted) {
			t.Fatalf("expected ErrSeqExhausted to persist, got %v", err)
		}
	})
}

// TestESPSeqNoReuseAtExhaustion seeds the counter near the top of the space and
// checks the final packets carry the last valid sequence numbers, then every
// further Encrypt refuses — never emitting 0 or a reused value (finding #11).
// For the AEAD suites this doubles as the nonce-uniqueness guarantee (IV = seq).
func TestESPSeqNoReuseAtExhaustion(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, _ := newTestSA(t, suite, 64)
		const max = ^uint32(0)
		init.seq.Store(max - 2) // two valid seqs remain: max-1 and max

		var got []uint32
		for range 4 {
			pkt, err := init.Encrypt([]byte("x"))
			if err != nil {
				if !errors.Is(err, ErrSeqExhausted) {
					t.Fatalf("unexpected error: %v", err)
				}
				continue
			}
			got = append(got, binary.BigEndian.Uint32(pkt[4:8]))
		}
		if len(got) != 2 || got[0] != max-1 || got[1] != max {
			t.Fatalf("emitted seqs = %v, want [%d %d]", got, max-1, max)
		}
		for _, s := range got {
			if s == 0 {
				t.Fatal("Encrypt emitted sequence number 0")
			}
		}
	})
}

// TestESPConcurrentEncryptUnique runs many concurrent Encrypts across the
// exhaustion boundary and checks every emitted sequence number is unique and
// non-zero, with exactly the available slots succeeding. The two-step Add+Store
// could hand two goroutines the same seq at the wrap; the CAS loop cannot
// (finding #11). For the AEAD suites a duplicated seq would be a duplicated
// nonce, so this is also the nonce-reuse regression. Run under -race.
func TestESPConcurrentEncryptUnique(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, _ := newTestSA(t, suite, 64)
		const (
			max        = ^uint32(0)
			slots      = 200
			goroutines = 512
		)
		init.seq.Store(max - slots) // exactly `slots` sequence numbers remain

		var wg sync.WaitGroup
		seqs := make(chan uint32, goroutines)
		var exhausted, otherErr atomic.Int64
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pkt, err := init.Encrypt([]byte("y"))
				switch {
				case err == nil:
					seqs <- binary.BigEndian.Uint32(pkt[4:8])
				case errors.Is(err, ErrSeqExhausted):
					exhausted.Add(1)
				default:
					otherErr.Add(1)
				}
			}()
		}
		wg.Wait()
		close(seqs)

		if otherErr.Load() != 0 {
			t.Fatalf("%d Encrypts failed with an unexpected error", otherErr.Load())
		}
		seen := make(map[uint32]bool)
		for s := range seqs {
			if s == 0 {
				t.Fatal("Encrypt emitted sequence number 0")
			}
			if seen[s] {
				t.Fatalf("sequence number %d emitted twice (reuse)", s)
			}
			seen[s] = true
		}
		if len(seen) != slots {
			t.Fatalf("emitted %d unique seqs, want exactly %d", len(seen), slots)
		}
		if got := exhausted.Load(); got != int64(goroutines-slots) {
			t.Fatalf("got %d ErrSeqExhausted, want %d", got, goroutines-slots)
		}
	})
}

func TestESPNextHeader(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		stampNH := func(nh byte) func([]byte) {
			return func(plain []byte) { plain[len(plain)-1] = nh }
		}
		// IPv6 inner (Next Header 41) is accepted.
		if _, err := resp.Decrypt(init.encryptMangled(t, []byte("ipv6 inner pkt!!"), stampNH(nextHeaderIPv6))); err != nil {
			t.Fatalf("IPv6 next header rejected: %v", err)
		}
		// An unexpected Next Header (50 = ESP) is rejected even when authenticated.
		if _, err := resp.Decrypt(init.encryptMangled(t, []byte("bad inner pkt!!!"), stampNH(50))); err == nil {
			t.Fatal("packet with next header 50 accepted")
		}
	})
}

// nextHeaderOf decrypts pkt with sa's inbound key and returns the ESP trailer's
// Next Header byte, so a test can assert Encrypt stamped the inner IP family.
func (sa *SA) nextHeaderOf(t *testing.T, pkt []byte) byte {
	t.Helper()
	if sa.suite == SuiteAESCBC256SHA256 {
		ctStart := espHeaderLen + cbcIVLen
		iv := pkt[espHeaderLen:ctStart]
		ct := pkt[ctStart : len(pkt)-espICVLen]
		plain := make([]byte, len(ct))
		cipher.NewCBCDecrypter(sa.inBlock, iv).CryptBlocks(plain, ct)
		return plain[len(plain)-1]
	}
	var nonce [aeadSaltLen + aeadIVLen]byte
	copy(nonce[:aeadSaltLen], sa.inSalt)
	copy(nonce[aeadSaltLen:], pkt[espHeaderLen:espHeaderLen+aeadIVLen])
	plain, err := sa.inAEAD.Open(nil, nonce[:], pkt[espHeaderLen+aeadIVLen:], pkt[:espHeaderLen])
	if err != nil {
		t.Fatal(err)
	}
	return plain[len(plain)-1]
}

// TestESPEncryptNextHeaderByInnerVersion is finding #1: Encrypt must stamp the ESP
// Next Header from the inner packet's IP version (41 for IPv6, 4 for IPv4) so a
// dual-stack peer routes inner IPv6 correctly instead of dropping it.
func TestESPEncryptNextHeaderByInnerVersion(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		v6 := append([]byte{0x60}, bytes.Repeat([]byte{0xab}, 39)...) // 0x6x → IPv6
		if nh := resp.nextHeaderOf(t, init.mustEncrypt(t, v6)); nh != nextHeaderIPv6 {
			t.Fatalf("inner IPv6: Next Header = %d, want %d", nh, nextHeaderIPv6)
		}
		v4 := append([]byte{0x45}, bytes.Repeat([]byte{0xcd}, 19)...) // 0x4x → IPv4
		if nh := resp.nextHeaderOf(t, init.mustEncrypt(t, v4)); nh != nextHeaderIPv4 {
			t.Fatalf("inner IPv4: Next Header = %d, want %d", nh, nextHeaderIPv4)
		}
	})
}

// TestESPDecryptRejectsMalformedPadding is finding #10: pad octets that are not
// the monotonic 1..padLen sequence are rejected even when authenticated.
func TestESPDecryptRejectsMalformedPadding(t *testing.T) {
	forEachSuite(t, func(t *testing.T, suite Suite) {
		init, resp := newTestSA(t, suite, 64)
		// 13 inner bytes force at least one pad octet under both the 16-byte CBC
		// block and the 4-byte AEAD alignment.
		inner := []byte("thirteenbytes")
		badPad := func(plain []byte) {
			padLen := int(plain[len(plain)-2])
			if padLen == 0 {
				t.Fatal("inner length produced no padding; pick another length")
			}
			for i := range padLen {
				plain[len(plain)-2-padLen+i] = 0xFF // RFC 4303 wants 1,2,...,padLen
			}
		}
		if _, err := resp.Decrypt(init.encryptMangled(t, inner, badPad)); err == nil {
			t.Fatal("packet with non-monotonic padding accepted")
		}
		if _, err := resp.Decrypt(init.mustEncrypt(t, inner)); err != nil {
			t.Fatalf("valid packet of the same length rejected: %v", err)
		}
	})
}

// TestESPAEADFraming pins the AEAD wire layout: SPI(4) | Seq(4) | IV(8) |
// ciphertext | Tag(16), with the plaintext padded to a 4-byte boundary and the
// per-packet IV equal to the sequence number widened to 64 bits.
func TestESPAEADFraming(t *testing.T) {
	for _, suite := range []Suite{SuiteAESGCM256, SuiteChaCha20Poly1305} {
		t.Run(suite.String(), func(t *testing.T) {
			init, _ := newTestSA(t, suite, 64)
			for _, n := range []int{0, 1, 2, 3, 4, 21, 1400} {
				pkt := init.mustEncrypt(t, bytes.Repeat([]byte{0xCD}, n))
				plainLen := (n + 2 + 3) / 4 * 4 // inner+trailer rounded up to %4
				if want := espHeaderLen + aeadIVLen + plainLen + espICVLen; len(pkt) != want {
					t.Fatalf("inner %d: packet length %d, want %d", n, len(pkt), want)
				}
				seq := binary.BigEndian.Uint32(pkt[4:8])
				if iv := binary.BigEndian.Uint64(pkt[8:16]); iv != uint64(seq) {
					t.Fatalf("inner %d: IV %d != seq %d", n, iv, seq)
				}
			}
		})
	}
}

// TestESPAEADTamperIV flips a bit of the wire IV: the nonce no longer matches
// the one the tag was computed under, so Decrypt must fail.
func TestESPAEADTamperIV(t *testing.T) {
	for _, suite := range []Suite{SuiteAESGCM256, SuiteChaCha20Poly1305} {
		t.Run(suite.String(), func(t *testing.T) {
			init, resp := newTestSA(t, suite, 64)
			pkt := init.mustEncrypt(t, []byte("iv tamper probe"))
			pkt[espHeaderLen] ^= 0x01
			if _, err := resp.Decrypt(pkt); err == nil {
				t.Fatal("packet with a tampered IV accepted")
			}
		})
	}
}

// TestNewSAKeyLenValidation rejects key material whose lengths do not match the
// suite, so a KEYMAT split desync surfaces at construction instead of as a
// silently garbled data plane.
func TestNewSAKeyLenValidation(t *testing.T) {
	cases := []struct {
		name        string
		suite       Suite
		encr, integ int
		ok          bool
	}{
		{"cbc valid", SuiteAESCBC256SHA256, 32, 32, true},
		{"cbc aead-sized keys", SuiteAESCBC256SHA256, 36, 0, false},
		{"cbc short integ", SuiteAESCBC256SHA256, 32, 16, false},
		{"gcm valid", SuiteAESGCM256, 36, 0, true},
		{"gcm missing salt", SuiteAESGCM256, 32, 0, false},
		{"gcm with integ key", SuiteAESGCM256, 36, 32, false},
		{"chacha valid", SuiteChaCha20Poly1305, 36, 0, true},
		{"chacha short", SuiteChaCha20Poly1305, 35, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encr := bytes.Repeat([]byte{0xA1}, tc.encr)
			integ := bytes.Repeat([]byte{0xB2}, tc.integ)
			_, err := NewSA(tc.suite, 1, 2, encr, integ, encr, integ, 64)
			if tc.ok && err != nil {
				t.Fatalf("valid key material rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("mismatched key material accepted")
			}
		})
	}
	if _, err := NewSA(Suite(99), 1, 2, nil, nil, nil, nil, 64); err == nil {
		t.Fatal("unknown suite accepted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKATChaCha20Poly1305RFC7634 replays the RFC 7634 Appendix A ESP example
// through the full inbound path: the known packet (SPI 0x01020304, seq 5, IV
// 0x1011121314151617) must authenticate under the KEYMAT-derived key+salt,
// pass the replay check, and parse back to the exact source IP datagram. This
// pins the nonce construction (salt | IV), the AAD (SPI | Seq) and the RFC 4303
// trailer handling against an external reference, independent of our encryptor.
func TestKATChaCha20Poly1305RFC7634(t *testing.T) {
	keymat := mustHex(t, `
		808182838485868788898a8b8c8d8e8f
		909192939495969798999a9b9c9d9e9f
		a0a1a2a3`)
	source := mustHex(t, `
		45000054a6f200004001e778c6336405
		c000020508005b7a3a080000553bec10
		0007362708090a0b0c0d0e0f10111213
		1415161718191a1b1c1d1e1f20212223
		2425262728292a2b2c2d2e2f30313233
		34353637`)
	packet := mustHex(t, `
		01020304000000051011121314151617
		24039428b97f417e3c13753a4f05087b
		67c352e6a7fab1b982d466ef407ae5c6
		14ee8099d52844eb61aa95dfab4c02f7
		2aa71e7c4c4f64c9befe2facc638e8f3
		cbec163fac469b502773f6fb94e664da
		9165b82829f641e0
		76aaa8266b7fb0f7b11b369907e1ad43`)

	sa, err := NewSA(SuiteChaCha20Poly1305, 0xdeadbeef, 0x01020304, keymat, nil, keymat, nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sa.Decrypt(packet)
	if err != nil {
		t.Fatalf("RFC 7634 Appendix A packet rejected: %v", err)
	}
	if !bytes.Equal(got, source) {
		t.Fatalf("decrypted datagram mismatch:\n got %x\nwant %x", got, source)
	}
	// The same packet again must now be a replay.
	if _, err := sa.Decrypt(packet); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed KAT packet: got %v, want ErrReplay", err)
	}
}

// TestKATAESGCM256McGrew replays a 256-bit AES-GCM-ESP vector from
// draft-mcgrew-gcm-test-01 (SPI 0x4a2cbfe3, seq 2). The vector's trailer ends
// with Next Header 1, which our tunnel-mode decryptor rejects by policy — so
// the full-path assertion is that Decrypt authenticates the packet (nonce and
// AAD conventions match the reference) and fails ONLY at the Next Header
// filter, while a tampered tag fails authentication instead. A white-box Open
// additionally compares the full plaintext against the reference.
func TestKATAESGCM256McGrew(t *testing.T) {
	keymat := mustHex(t, `
		abbccddef00112233445566778899aab
		abbccddef00112233445566778899aab
		11223344`)
	plaintext := mustHex(t, `
		4500003069a6400080062690c0a80102
		9389155e0a9e008b2dc57ee000000000
		7002400020bf0000020405b401010402
		01020201`)
	packet := mustHex(t, `
		4a2cbfe3000000020102030405060708
		ff425c9b724599df7a3bcd510194e00d
		6a78107f1b0b1cbf06efae9d65a5d763
		748a637985771d347f0545659f14e99d
		ef842d8eb335f4eecfdbf831824b4c49
		15956c96`)

	sa, err := NewSA(SuiteAESGCM256, 0xdeadbeef, 0x4a2cbfe3, keymat, nil, keymat, nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	// Full inbound path: authentication and trailer parse succeed, only the
	// tunnel-mode Next Header policy rejects (the vector carries NH=1).
	_, err = sa.Decrypt(append([]byte(nil), packet...))
	if err == nil || !strings.Contains(err.Error(), "unexpected next header 1") {
		t.Fatalf("expected the Next Header filter to reject NH=1 after authentication, got %v", err)
	}
	// A flipped tag byte must fail AUTHENTICATION, proving the check above
	// really did verify the tag before reaching the trailer.
	bad := append([]byte(nil), packet...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := sa.Decrypt(bad); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected AEAD authentication failure on a flipped tag, got %v", err)
	}
	// White-box: the raw AEAD under our salt/nonce/AAD conventions reproduces
	// the reference plaintext byte-exact.
	var nonce [aeadSaltLen + aeadIVLen]byte
	copy(nonce[:aeadSaltLen], sa.inSalt)
	copy(nonce[aeadSaltLen:], packet[espHeaderLen:espHeaderLen+aeadIVLen])
	plain, err := sa.inAEAD.Open(nil, nonce[:], packet[espHeaderLen+aeadIVLen:], packet[:espHeaderLen])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, plaintext) {
		t.Fatalf("plaintext mismatch:\n got %x\nwant %x", plain, plaintext)
	}
}

func TestReplayWindow(t *testing.T) {
	w := NewReplayWindow(64)
	if w.Accept(0) {
		t.Fatal("sequence 0 must be rejected")
	}
	if !w.Accept(1) {
		t.Fatal("first packet rejected")
	}
	if w.Accept(1) {
		t.Fatal("replay of 1 accepted")
	}
	// jump ahead
	if !w.Accept(100) {
		t.Fatal("100 rejected")
	}
	// in-window, not seen
	if !w.Accept(99) {
		t.Fatal("99 (in window) rejected")
	}
	if w.Accept(99) {
		t.Fatal("replay of 99 accepted")
	}
	// older than window (100 - 64 = 36; anything <= 36 too old)
	if w.Accept(36) {
		t.Fatal("36 (out of window) accepted")
	}
	if !w.Accept(37) {
		t.Fatal("37 (edge of window) rejected")
	}
	// far jump clears window
	if !w.Accept(1_000_000) {
		t.Fatal("big jump rejected")
	}
	if w.Accept(100) {
		t.Fatal("100 after big jump should be out of window")
	}
}

func TestReplayWindowLargerSize(t *testing.T) {
	w := NewReplayWindow(256)
	for _, s := range []uint32{500, 400, 300, 250} {
		if !w.Accept(s) {
			t.Fatalf("%d rejected", s)
		}
	}
	for _, s := range []uint32{500, 400, 300, 250} {
		if w.Accept(s) {
			t.Fatalf("replay of %d accepted", s)
		}
	}
	// 500-256 = 244 → 244 and below are out of window
	if w.Accept(244) {
		t.Fatal("244 (out of window) accepted")
	}
	if !w.Accept(245) {
		t.Fatal("245 (in window) rejected")
	}
}

// TestReplayWindowHugeSizeNoOverflow guards the uint32 word-count overflow: a
// size near math.MaxUint32 previously wrapped (size+63) to a tiny value, yielding
// a zero-length bitmap that panicked on the first packet. It must now clamp to
// MaxReplayWindow and still accept traffic.
func TestReplayWindowHugeSizeNoOverflow(t *testing.T) {
	for _, size := range []uint32{math.MaxUint32, math.MaxUint32 - 1, 0xFFFFFFC0, MaxReplayWindow + 1} {
		w := NewReplayWindow(size)
		if w.size == 0 || len(w.bits) == 0 {
			t.Fatalf("size %d: zero-length window (overflow)", size)
		}
		if w.size > MaxReplayWindow {
			t.Fatalf("size %d: not clamped, got window size %d", size, w.size)
		}
		if !w.Accept(1) {
			t.Fatalf("size %d: first packet rejected", size)
		}
	}
}
