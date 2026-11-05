package ikemsg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// mh decodes a hex string (spaces allowed for readability) into bytes, failing the
// test on a malformed literal.
func mh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex literal %q: %v", s, err)
	}
	return b
}

// TestPayloadBodyGolden pins each payload body to bytes hand-derived from RFC 7296
// §3 (not from any reference implementation). These are the make-or-break wire
// vectors: a single wrong offset here breaks interop with every conformant peer.
func TestPayloadBodyGolden(t *testing.T) {
	cases := []struct {
		name string
		p    Payload
		want string
	}{
		{
			// §3.9: body is the raw nonce (16..256 octets).
			name: "nonce",
			p:    &NoncePayload{Data: mh(t, "000102030405060708090A0B0C0D0E0F")},
			want: "000102030405060708090A0B0C0D0E0F",
		},
		{
			// §3.4: Group(2) | RESERVED(2) | data. Group 31 = x25519.
			name: "ke",
			p:    &KEPayload{Group: DH_X25519, Data: mh(t, "01020304")},
			want: "001F0000 01020304",
		},
		{
			// §3.10: Protocol(1) | SPISize(1) | Type(2) | data. No SPI.
			name: "notify_nat",
			p:    &NotifyPayload{Protocol: ProtocolNone, Type: NotifyNATDetectionSourceIP, Data: mh(t, "AABB")},
			want: "0000 4004 AABB",
		},
		{
			// §3.10: REKEY_SA carries the old SPI in the SPI field (SPISize 4).
			name: "notify_rekey_spi",
			p:    &NotifyPayload{Protocol: ProtocolESP, Type: NotifyRekeySA, SPI: mh(t, "DEADBEEF")},
			want: "0304 4009 DEADBEEF",
		},
		{
			// §3.11: IKE-SA delete is a bare 4-byte body (Protocol 1, no SPIs).
			name: "delete_ike",
			p:    &DeletePayload{Protocol: ProtocolIKE},
			want: "01 00 0000",
		},
		{
			// §3.11: ESP delete carries 4-byte SPIs.
			name: "delete_esp",
			p:    &DeletePayload{Protocol: ProtocolESP, SPIs: [][]byte{mh(t, "00002222")}},
			want: "03 04 0001 00002222",
		},
		{
			// §3.5: ID Type(1) | RESERVED(3) | data. "a@b".
			name: "idi",
			p:    &IDiPayload{IDType: IDTypeRFC822, Data: []byte("a@b")},
			want: "03 000000 614062",
		},
		{
			// §3.8: Auth Method(1) | RESERVED(3) | data.
			name: "auth",
			p:    &AuthPayload{Method: 2, Data: mh(t, "01020304")},
			want: "02 000000 01020304",
		},
		{
			// §3.6: 1-byte header — Encoding(1) | data (no RESERVED padding).
			name: "cert",
			p:    &CertPayload{Encoding: CertX509Signature, Data: mh(t, "DEADBEEF")},
			want: "04 DEADBEEF",
		},
		{
			// §3.7: 1-byte header, like Certificate.
			name: "certreq",
			p:    &CertRequestPayload{Encoding: CertX509Signature, Data: mh(t, "CAFE")},
			want: "04 CAFE",
		},
		{
			// §3.12: raw vendor identifier.
			name: "vendorid",
			p:    &VendorIDPayload{Data: mh(t, "01020304")},
			want: "01020304",
		},
		{
			// §3.13: count + RESERVED, then one IPv4 full-range selector (length 16).
			name: "tsi_fulltunnel",
			p: &TSiPayload{Selectors: []TrafficSelector{{
				TSType: TSIPv4AddrRange, Protocol: 0, StartPort: 0, EndPort: 65535,
				StartAddr: mh(t, "00000000"), EndAddr: mh(t, "FFFFFFFF"),
			}}},
			want: "01000000 07000010 0000FFFF 00000000 FFFFFFFF",
		},
		{
			// §3.15: CFG_REQUEST with three empty (length-0) attributes.
			name: "cp_request",
			p: &ConfigPayload{CfgType: ConfigRequest, Attributes: []ConfigAttr{
				{Type: ConfigAttrInternalIP4Address}, {Type: ConfigAttrInternalIP4Netmask}, {Type: ConfigAttrInternalIP4DNS},
			}},
			want: "01000000 00010000 00020000 00030000",
		},
		{
			// §3.13: one IPv6 full-range selector (::/0), length 40 = 8 + 2×16.
			name: "tsi_v6_fulltunnel",
			p: &TSiPayload{Selectors: []TrafficSelector{{
				TSType: TSIPv6AddrRange, Protocol: 0, StartPort: 0, EndPort: 65535,
				StartAddr: mh(t, "00000000000000000000000000000000"),
				EndAddr:   mh(t, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			}}},
			want: "01000000 08000028 0000FFFF" +
				"00000000000000000000000000000000" +
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			// §3.15: CFG_REPLY carrying an INTERNAL_IP6_ADDRESS (16-byte addr +
			// 1-byte prefix length = 17), attribute type 8, length 0x0011.
			name: "cp_reply_ip6",
			p: &ConfigPayload{CfgType: ConfigReply, Attributes: []ConfigAttr{
				{Type: ConfigAttrInternalIP6Address, Value: mh(t, "FD000000000000000000000000000001 40")},
			}},
			want: "02000000 00080011 FD000000000000000000000000000001 40",
		},
		{
			// §3.3: the IKE v1 suite proposal (AES-CBC-256, PRF/INTEG SHA2-256, D-H
			// 31 then 14) in canonical transform order.
			name: "sa_ike_suite",
			p: &SAPayload{Proposals: []Proposal{{
				Number: 1, Protocol: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformEncr, ID: ENCR_AES_CBC, KeyLength: 256, HasKeyLength: true},
					{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
					{Type: TransformInteg, ID: AUTH_HMAC_SHA2_256_128},
					{Type: TransformDH, ID: DH_X25519},
					{Type: TransformDH, ID: DH_MODP2048},
				},
			}}},
			want: "00000034 01010005" +
				"0300000C 0100000C 800E0100" +
				"03000008 02000005" +
				"03000008 0300000C" +
				"03000008 0400001F" +
				"00000008 0400000E",
		},
		{
			// §3.3: the ESP Child SA proposal (AES-CBC-256, INTEG SHA2-256, No-ESN)
			// carrying a 4-byte SPI.
			name: "sa_esp_suite",
			p: &SAPayload{Proposals: []Proposal{{
				Number: 1, Protocol: ProtocolESP, SPI: mh(t, "DEADBEEF"),
				Transforms: []Transform{
					{Type: TransformEncr, ID: ENCR_AES_CBC, KeyLength: 256, HasKeyLength: true},
					{Type: TransformInteg, ID: AUTH_HMAC_SHA2_256_128},
					{Type: TransformESN, ID: ESN_NONE},
				},
			}}},
			want: "00000028 01030403 DEADBEEF" +
				"0300000C 0100000C 800E0100" +
				"03000008 0300000C" +
				"00000008 05000000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.p.marshalBody()
			if err != nil {
				t.Fatalf("marshalBody: %v", err)
			}
			if want := mh(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("body mismatch:\n got %X\nwant %X", got, want)
			}

			// Round-trip the body back through a fresh payload of the same type.
			fresh := newPayload(tc.p.PayloadType())
			if fresh == nil {
				t.Fatalf("newPayload(%d) = nil", tc.p.PayloadType())
			}
			if err := fresh.unmarshalBody(got); err != nil {
				t.Fatalf("unmarshalBody: %v", err)
			}
			again, err := fresh.marshalBody()
			if err != nil {
				t.Fatalf("re-marshalBody: %v", err)
			}
			if !bytes.Equal(again, got) {
				t.Fatalf("body round-trip not stable:\n first %X\nsecond %X", got, again)
			}
		})
	}
}

// TestMessageGolden pins two full messages to hand-derived bytes (RFC 7296 §3.1):
// a plain IKE_SA_INIT-style header carrying a Nonce, and an SK{} envelope whose
// header Next Payload is SK and whose inner-first type is preserved.
func TestMessageGolden(t *testing.T) {
	t.Run("nonce_message", func(t *testing.T) {
		nonce := mh(t, "000102030405060708090A0B0C0D0E0F") // 16 octets (RFC 7296 §3.9 minimum)
		m := &Message{
			InitiatorSPI: 0x1122334455667788,
			Exchange:     ExchangeIKESAInit,
			Flags:        FlagInitiator,
			Payloads:     Payloads{&NoncePayload{Data: nonce}},
		}
		want := mh(t, "1122334455667788 0000000000000000 28202208 00000000 00000030 00000014 000102030405060708090A0B0C0D0E0F")
		got, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message mismatch:\n got %X\nwant %X", got, want)
		}

		back, err := Parse(got)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if back.InitiatorSPI != m.InitiatorSPI || back.Exchange != ExchangeIKESAInit ||
			!back.Flags.IsInitiator() || back.Flags.IsResponse() {
			t.Fatalf("parsed header fields wrong: %+v", back)
		}
		if len(back.Payloads) != 1 {
			t.Fatalf("got %d payloads, want 1", len(back.Payloads))
		}
		n, ok := back.Payloads[0].(*NoncePayload)
		if !ok || !bytes.Equal(n.Data, nonce) {
			t.Fatalf("parsed nonce wrong: %#v", back.Payloads[0])
		}
	})

	t.Run("sk_envelope", func(t *testing.T) {
		m := &Message{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Exchange:     ExchangeIKEAuth,
			Flags:        FlagInitiator,
			MessageID:    1,
			Payloads:     Payloads{&EncryptedPayload{InnerFirst: PayloadEAP, Data: mh(t, "010203040506")}},
		}
		want := mh(t, "0000000000000001 0000000000000002 2E202308 00000001 00000026 3000000A 010203040506")
		got, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("SK message mismatch:\n got %X\nwant %X", got, want)
		}
		// The header Next Payload must be SK (46), not the inner type.
		if got[16] != byte(PayloadSK) {
			t.Fatalf("header Next Payload = %d, want %d (SK)", got[16], PayloadSK)
		}

		back, err := Parse(got)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		enc, ok := back.Payloads[0].(*EncryptedPayload)
		if !ok {
			t.Fatalf("first payload type %T, want *EncryptedPayload", back.Payloads[0])
		}
		if enc.InnerFirst != PayloadEAP {
			t.Fatalf("InnerFirst = %d, want %d (EAP)", enc.InnerFirst, PayloadEAP)
		}
		if !bytes.Equal(enc.Data, mh(t, "010203040506")) {
			t.Fatalf("SK data = %X", enc.Data)
		}
	})
}

// TestRoundTripAllPayloads threads a chain of every modeled payload type through
// Marshal → Parse → Marshal and asserts byte-identity, exercising the Next Payload
// linkage and each payload's body codec together.
func TestRoundTripAllPayloads(t *testing.T) {
	m := &Message{
		InitiatorSPI: 0xAABBCCDD00112233,
		ResponderSPI: 0x4455667788990011,
		Exchange:     ExchangeIKEAuth,
		Flags:        FlagInitiator | FlagResponse,
		MessageID:    7,
		Payloads: Payloads{
			&SAPayload{Proposals: []Proposal{{
				Number: 1, Protocol: ProtocolESP, SPI: mh(t, "DEADBEEF"),
				Transforms: []Transform{
					{Type: TransformEncr, ID: ENCR_AES_CBC, KeyLength: 256, HasKeyLength: true},
					{Type: TransformInteg, ID: AUTH_HMAC_SHA2_256_128},
					{Type: TransformESN, ID: ESN_NONE},
				},
			}}},
			&KEPayload{Group: DH_MODP2048, Data: bytes.Repeat([]byte{0x5A}, 256)},
			&NoncePayload{Data: bytes.Repeat([]byte{0xA5}, 32)},
			&NotifyPayload{Protocol: ProtocolNone, Type: NotifyNATDetectionDestinationIP, Data: mh(t, "0011223344556677889900112233445566778899")},
			&IDiPayload{IDType: IDTypeRFC822, Data: []byte("user@example.com")},
			&IDrPayload{IDType: IDTypeFQDN, Data: []byte("vpn.example.com")},
			&AuthPayload{Method: 14, Data: mh(t, "0A0B0C0D")},
			&CertPayload{Encoding: CertX509Signature, Data: bytes.Repeat([]byte{0xCC}, 40)},
			&CertRequestPayload{Encoding: CertX509Signature, Data: mh(t, "ABCDEF")},
			&TSiPayload{Selectors: []TrafficSelector{{
				TSType: TSIPv4AddrRange, EndPort: 65535,
				StartAddr: mh(t, "00000000"), EndAddr: mh(t, "FFFFFFFF"),
			}}},
			&TSrPayload{Selectors: []TrafficSelector{{
				TSType: TSIPv4AddrRange, EndPort: 65535,
				StartAddr: mh(t, "00000000"), EndAddr: mh(t, "FFFFFFFF"),
			}}},
			&ConfigPayload{CfgType: ConfigReply, Attributes: []ConfigAttr{
				{Type: ConfigAttrInternalIP4Address, Value: mh(t, "0A0A002A")},
				{Type: ConfigAttrInternalIP4Netmask, Value: mh(t, "FFFFFF00")},
			}},
			&VendorIDPayload{Data: mh(t, "0102030405")},
			&DeletePayload{Protocol: ProtocolESP, SPIs: [][]byte{mh(t, "00002222"), mh(t, "00003333")}},
		},
	}

	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(back.Payloads) != len(m.Payloads) {
		t.Fatalf("got %d payloads, want %d", len(back.Payloads), len(m.Payloads))
	}
	raw2, err := back.Marshal()
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip not byte-exact:\n%X\n%X", raw, raw2)
	}

	// Spot-check a few decoded fields survived intact.
	if d, ok := back.Payloads[13].(*DeletePayload); !ok || d.SPISize() != 4 || len(d.SPIs) != 2 {
		t.Fatalf("delete payload decoded wrong: %#v", back.Payloads[13])
	}
	if cp, ok := back.Payloads[11].(*ConfigPayload); !ok || len(cp.Attributes) != 2 ||
		!bytes.Equal(cp.Attributes[0].Value, mh(t, "0A0A002A")) {
		t.Fatalf("config payload decoded wrong: %#v", back.Payloads[11])
	}
}

// TestEmptyChain verifies the inner-chain rules: an empty chain marshals to no
// bytes with no error (a DPD probe wraps zero inner payloads), and ParsePayloads of
// an empty body yields an empty chain.
func TestEmptyChain(t *testing.T) {
	first, body, err := Payloads(nil).Marshal()
	if err != nil || first != PayloadNone || body != nil {
		t.Fatalf("empty Marshal = (%d, %X, %v), want (PayloadNone, nil, nil)", first, body, err)
	}
	ps, err := ParsePayloads(PayloadNone, nil)
	if err != nil || len(ps) != 0 {
		t.Fatalf("empty ParsePayloads = (%v, %v), want (empty, nil)", ps, err)
	}
}

// TestInnerChainRoundTrip exercises the SK plaintext path: Payloads.Marshal then
// ParsePayloads(first, body) must round-trip byte-exact, mirroring how the session
// encodes and decodes the encrypted inner payloads.
func TestInnerChainRoundTrip(t *testing.T) {
	inner := Payloads{
		&IDiPayload{IDType: IDTypeRFC822, Data: []byte("a@b.example")},
		&AuthPayload{Method: 2, Data: bytes.Repeat([]byte{0x99}, 32)},
		&EAPPayload{Data: mh(t, "0201000501")},
	}
	first, body, err := inner.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if first != PayloadIDi {
		t.Fatalf("first = %d, want IDi", first)
	}
	back, err := ParsePayloads(first, body)
	if err != nil {
		t.Fatalf("ParsePayloads: %v", err)
	}
	_, body2, err := back.Marshal()
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(body, body2) {
		t.Fatalf("inner chain round-trip not byte-exact:\n%X\n%X", body, body2)
	}
}

// TestParseRejectsMalformedSA is the finding-#1 regression in codec form: an SA
// proposal claiming ProposalLength=9 but SPISize=200 would index out of range. Parse
// must return an error, not panic (it is the reason the old safeDecode recover
// existed).
func TestParseRejectsMalformedSA(t *testing.T) {
	raw := malformedSAInit()
	if _, err := Parse(raw); err == nil {
		t.Fatal("Parse accepted a malformed SA proposal (SPISize overruns proposal length)")
	}
}

// malformedSAInit builds an otherwise well-formed IKE_SA_INIT whose single SA
// proposal sets ProposalLength=9 and SPISize=200, so a naive decoder slices
// body[208:9].
func malformedSAInit() []byte {
	const total = 240
	raw := make([]byte, total)
	binary.BigEndian.PutUint64(raw[0:8], 0x1122334455667788)
	binary.BigEndian.PutUint64(raw[8:16], 0x99AABBCCDDEEFF00)
	raw[16] = byte(PayloadSA)
	raw[17] = version
	raw[18] = byte(ExchangeIKESAInit)
	raw[19] = byte(FlagResponse)
	binary.BigEndian.PutUint32(raw[24:28], total)

	// SA generic payload header at offset 28.
	binary.BigEndian.PutUint16(raw[30:32], total-28)

	// Proposal substructure at offset 32.
	body := raw[32:]
	binary.BigEndian.PutUint16(body[2:4], 9) // proposal length
	body[4] = 1                              // number
	body[5] = byte(ProtocolIKE)
	body[6] = 200 // SPI size — overruns the 9-byte proposal
	body[7] = 0   // num transforms
	return raw
}

// TestParseRejectsHardenedCases pins the payload-validity guards added against
// crafted post-decrypt input: a zero-width Delete with a non-zero SPI count (a
// memory-amplification vector) and a sub-16-byte Nonce (RFC 7296 §3.9).
func TestParseRejectsHardenedCases(t *testing.T) {
	t.Run("zero_width_delete", func(t *testing.T) {
		// Protocol IKE, SPI Size 0, Num of SPIs 0xFFFF — a 4-byte body claiming 65535 SPIs.
		var d DeletePayload
		if err := d.unmarshalBody(mh(t, "01 00 FFFF")); err == nil {
			t.Fatal("accepted a zero-width Delete with a non-zero SPI count")
		}
	})
	t.Run("short_nonce", func(t *testing.T) {
		var n NoncePayload
		if err := n.unmarshalBody(mh(t, "00112233")); err == nil {
			t.Fatal("accepted a 4-byte nonce below the 16-byte minimum")
		}
		if err := n.unmarshalBody(bytes.Repeat([]byte{1}, 16)); err != nil {
			t.Fatalf("rejected a 16-byte nonce: %v", err)
		}
	})
}

// TestMarshalRejectsOversizedProposal pins the marshal-side guard against a
// proposal whose transform count would truncate into the 1-octet field.
func TestMarshalRejectsOversizedProposal(t *testing.T) {
	transforms := make([]Transform, 256)
	for i := range transforms {
		transforms[i] = Transform{Type: TransformDH, ID: uint16(i)}
	}
	sa := &SAPayload{Proposals: []Proposal{{Number: 1, Protocol: ProtocolIKE, Transforms: transforms}}}
	if _, err := sa.marshalBody(); err == nil {
		t.Fatal("marshaled a proposal with 256 transforms (count truncates to a byte)")
	}
}

// TestParseNeverPanics feeds truncations and crafted length fields of valid seed
// messages to Parse, asserting it always returns (nil, error) or a clean decode and
// never panics on hostile, pre-authentication input.
func TestParseNeverPanics(t *testing.T) {
	seeds := [][]byte{
		mustMarshal(t, &Message{
			InitiatorSPI: 1, Exchange: ExchangeIKESAInit, Flags: FlagInitiator,
			Payloads: Payloads{
				&SAPayload{Proposals: []Proposal{{
					Number: 1, Protocol: ProtocolIKE,
					Transforms: []Transform{
						{Type: TransformEncr, ID: ENCR_AES_CBC, KeyLength: 256, HasKeyLength: true},
						{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
						{Type: TransformInteg, ID: AUTH_HMAC_SHA2_256_128},
						{Type: TransformDH, ID: DH_X25519},
					},
				}}},
				&KEPayload{Group: DH_X25519, Data: bytes.Repeat([]byte{1}, 32)},
				&NoncePayload{Data: bytes.Repeat([]byte{2}, 32)},
			},
		}),
		mustMarshal(t, &Message{
			InitiatorSPI: 1, ResponderSPI: 2, Exchange: ExchangeIKEAuth, Flags: FlagResponse,
			Payloads: Payloads{&EncryptedPayload{InnerFirst: PayloadIDi, Data: bytes.Repeat([]byte{7}, 48)}},
		}),
		malformedSAInit(),
	}

	guard := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked on %d bytes (%X): %v", len(b), b, r)
			}
		}()
		_, _ = Parse(b)
	}

	for _, seed := range seeds {
		// Every truncation length.
		for n := 0; n <= len(seed); n++ {
			guard(seed[:n])
		}
		// Crafted header length fields (over- and under-claiming).
		for _, l := range []uint32{0, 1, 27, 28, uint32(len(seed)) - 1, uint32(len(seed)) + 1, 0xFFFFFFFF} {
			if len(seed) >= 28 {
				m := append([]byte(nil), seed...)
				binary.BigEndian.PutUint32(m[24:28], l)
				guard(m)
			}
		}
		// Single-byte length-field perturbations inside the first payload header.
		if len(seed) >= 32 {
			for _, off := range []int{30, 31} {
				m := append([]byte(nil), seed...)
				m[off] ^= 0xFF
				guard(m)
			}
		}
	}
}

func mustMarshal(t *testing.T, m *Message) []byte {
	t.Helper()
	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal seed: %v", err)
	}
	return raw
}

// TestProposalByType checks the flat transform list filters by type, replacing the
// five named slices of the previous codec.
func TestProposalByType(t *testing.T) {
	p := Proposal{Transforms: []Transform{
		{Type: TransformEncr, ID: ENCR_AES_CBC, KeyLength: 256, HasKeyLength: true},
		{Type: TransformDH, ID: DH_X25519},
		{Type: TransformDH, ID: DH_MODP2048},
	}}
	if got := p.ByType(TransformDH); len(got) != 2 || got[0].ID != DH_X25519 || got[1].ID != DH_MODP2048 {
		t.Fatalf("ByType(DH) = %#v", got)
	}
	if got := p.ByType(TransformESN); len(got) != 0 {
		t.Fatalf("ByType(ESN) = %#v, want empty", got)
	}
}

// TestNotifyTypeIsError pins the error/status class boundary (RFC 7296 §3.10.1).
func TestNotifyTypeIsError(t *testing.T) {
	for _, tc := range []struct {
		t    NotifyType
		want bool
	}{
		{NotifyNoProposalChosen, true},
		{NotifyInvalidKEPayload, true},
		{NotifyAuthenticationFailed, true},
		{NotifyInitialContact, false},
		{NotifyCookie, false},
		{NotifyRekeySA, false},
		{0, false},
	} {
		if got := tc.t.IsError(); got != tc.want {
			t.Errorf("NotifyType(%d).IsError() = %v, want %v", tc.t, got, tc.want)
		}
	}
}

// FuzzParse runs Parse over its seed corpus on every `go test` (and is available
// for `go test -fuzz`). The only invariant is that it must never panic.
func FuzzParse(f *testing.F) {
	f.Add(mustMarshalF(f, &Message{
		InitiatorSPI: 1, Exchange: ExchangeIKESAInit, Flags: FlagInitiator,
		Payloads: Payloads{&NoncePayload{Data: bytes.Repeat([]byte{9}, 16)}},
	}))
	f.Add([]byte{})
	f.Add(make([]byte, 28))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Parse(raw) // must not panic
	})
}

func mustMarshalF(f *testing.F, m *Message) []byte {
	f.Helper()
	raw, err := m.Marshal()
	if err != nil {
		f.Fatalf("Marshal seed: %v", err)
	}
	return raw
}

// TestParseTransformsIgnoresNonKeyLengthTV: parseTransforms must surface a TV
// attribute as Transform.KeyLength only when its type field is Key Length (14).
// A TV attribute of any other type previously wrote its value into KeyLength,
// corrupting suite matching.
func TestParseTransformsIgnoresNonKeyLengthTV(t *testing.T) {
	mkTransform := func(attrType uint16) []byte {
		b := make([]byte, 12)
		b[0] = 3 // last transform
		binary.BigEndian.PutUint16(b[2:4], 12)
		b[4] = byte(TransformEncr)
		binary.BigEndian.PutUint16(b[6:8], ENCR_AES_CBC)
		binary.BigEndian.PutUint16(b[8:10], 0x8000|attrType) // TV form
		binary.BigEndian.PutUint16(b[10:12], 256)
		return b
	}

	// A genuine Key Length attribute (type 14) is surfaced.
	got, err := parseTransforms(mkTransform(AttrKeyLength))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].KeyLength != 256 || !got[0].HasKeyLength {
		t.Fatalf("Key Length attribute not parsed: %+v", got)
	}

	// A non-Key-Length TV attribute (type 7) must leave KeyLength zero.
	got, err = parseTransforms(mkTransform(7))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].KeyLength != 0 || got[0].HasKeyLength {
		t.Fatalf("non-Key-Length TV attribute mis-parsed into KeyLength: %+v", got)
	}
}

// TestParseTransformsKeyLengthNotFirstAttribute is finding #11: parseTransforms
// must walk ALL transform attributes (RFC 7296 §3.3.5 permits several in any
// order) and surface the TV Key Length even when another attribute precedes it.
func TestParseTransformsKeyLengthNotFirstAttribute(t *testing.T) {
	t.Run("TV attribute before KeyLength", func(t *testing.T) {
		b := make([]byte, 16)
		b[0] = 3 // last transform
		binary.BigEndian.PutUint16(b[2:4], 16)
		b[4] = byte(TransformEncr)
		binary.BigEndian.PutUint16(b[6:8], ENCR_AES_CBC)
		binary.BigEndian.PutUint16(b[8:10], 0x8000|7) // non-KeyLength TV first
		binary.BigEndian.PutUint16(b[10:12], 0xBEEF)
		binary.BigEndian.PutUint16(b[12:14], 0x8000|AttrKeyLength) // TV KeyLength second
		binary.BigEndian.PutUint16(b[14:16], 256)
		got, err := parseTransforms(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].KeyLength != 256 || !got[0].HasKeyLength {
			t.Fatalf("KeyLength not surfaced as the 2nd attribute: %+v", got)
		}
	})
	t.Run("TLV attribute before KeyLength", func(t *testing.T) {
		// 8-byte header + 6-byte TLV (type 5, value length 2) + 4-byte TV KeyLength.
		b := make([]byte, 18)
		b[0] = 3
		binary.BigEndian.PutUint16(b[2:4], 18)
		b[4] = byte(TransformEncr)
		binary.BigEndian.PutUint16(b[6:8], ENCR_AES_CBC)
		binary.BigEndian.PutUint16(b[8:10], 5)  // TLV (AF=0), type 5
		binary.BigEndian.PutUint16(b[10:12], 2) // value length
		binary.BigEndian.PutUint16(b[14:16], 0x8000|AttrKeyLength)
		binary.BigEndian.PutUint16(b[16:18], 256)
		got, err := parseTransforms(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].KeyLength != 256 || !got[0].HasKeyLength {
			t.Fatalf("KeyLength not surfaced after a TLV attribute: %+v", got)
		}
	})
}

// TestNoncePayloadBounds is finding #16: a nonce outside the RFC 7296 §3.9
// 16..256-byte range is rejected at the parse boundary.
func TestNoncePayloadBounds(t *testing.T) {
	var n NoncePayload
	if err := n.unmarshalBody(bytes.Repeat([]byte{1}, 16)); err != nil {
		t.Fatalf("16-byte nonce rejected: %v", err)
	}
	if err := n.unmarshalBody(bytes.Repeat([]byte{1}, 256)); err != nil {
		t.Fatalf("256-byte nonce rejected: %v", err)
	}
	if err := n.unmarshalBody(bytes.Repeat([]byte{1}, 15)); err == nil {
		t.Fatal("15-byte nonce accepted (below minimum)")
	}
	if err := n.unmarshalBody(bytes.Repeat([]byte{1}, 257)); err == nil {
		t.Fatal("257-byte nonce accepted (above maximum)")
	}
}

// TestParseTSBodyRejectsDegenerate is finding #14: parseTSBody must reject a
// zero-selector count and a body with trailing bytes after the declared selectors.
func TestParseTSBodyRejectsDegenerate(t *testing.T) {
	valid, err := marshalTSBody([]TrafficSelector{{
		TSType: TSIPv4AddrRange, EndPort: 65535,
		StartAddr: []byte{0, 0, 0, 0}, EndAddr: []byte{255, 255, 255, 255},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseTSBody(valid); err != nil {
		t.Fatalf("valid TS body rejected: %v", err)
	}
	if _, err := parseTSBody([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("zero-selector count accepted")
	}
	if _, err := parseTSBody(append(append([]byte(nil), valid...), 0xAA)); err == nil {
		t.Fatal("trailing bytes after selectors accepted")
	}
}

// TestMarshalRejectsOversizedPayloadBody pins the chain-marshal guard: a body
// that cannot fit the 16-bit generic-header length field must error instead of
// silently wrapping the length and corrupting the outgoing message. This also
// transitively bounds every nested length field (proposal, selector, config
// attribute), each of which spans a subset of the payload body.
func TestMarshalRejectsOversizedPayloadBody(t *testing.T) {
	huge := &VendorIDPayload{Data: make([]byte, 0x10000)}
	if _, _, err := (Payloads{huge}).Marshal(); err == nil {
		t.Fatal("marshaled a payload body larger than the 16-bit length field")
	}
	// At the exact boundary (body + 4-byte header == 0xFFFF) it still fits.
	max := &VendorIDPayload{Data: make([]byte, 0xFFFF-genericHeaderLen)}
	if _, _, err := (Payloads{max}).Marshal(); err != nil {
		t.Fatalf("boundary-size payload rejected: %v", err)
	}
}

// TestMarshalRejectsKeyLengthWithoutFlag: a transform carrying a KeyLength but
// not HasKeyLength is an inconsistent struct; marshalling it must fail rather
// than silently drop the Key Length attribute from the wire.
func TestMarshalRejectsKeyLengthWithoutFlag(t *testing.T) {
	sa := &SAPayload{Proposals: []Proposal{{
		Number: 1, Protocol: ProtocolESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{{Type: TransformEncr, ID: ENCR_AES_GCM_16, KeyLength: 256}},
	}}}
	if _, err := sa.marshalBody(); err == nil {
		t.Fatal("KeyLength without HasKeyLength was marshalled")
	}
	sa.Proposals[0].Transforms[0].HasKeyLength = true
	if _, err := sa.marshalBody(); err != nil {
		t.Fatal(err)
	}
}
