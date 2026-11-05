package session

import (
	"bytes"
	"testing"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// The scripted responders in this package negotiate the CBC suite unless a test
// says otherwise; these are its per-direction KEYMAT lengths.
const (
	espEncrKeyLen  = 32
	espIntegKeyLen = 32
)

// mustSuite returns the suite-table row for an esp.Suite id.
func mustSuite(t *testing.T, id esp.Suite) espSuite {
	t.Helper()
	s, ok := suiteByID(id, espSuites)
	if !ok {
		t.Fatalf("suite %v missing from the table", id)
	}
	return s
}

// mustIKESuite returns the IKE suite-table row for an ikesa.Suite id.
func mustIKESuite(t *testing.T, id ikesa.Suite) ikeSuite {
	t.Helper()
	s, ok := suiteByID(id, ikeSuites)
	if !ok {
		t.Fatalf("IKE suite %v missing from the table", id)
	}
	return s
}

// buildESPProposalCBC builds the single-proposal AES-CBC-256 + HMAC-SHA2-256-128
// offer used by scripted responders and legacy fixtures.
func buildESPProposalCBC(number uint8, spi []byte, groups ...uint16) ikemsg.Proposal {
	s, _ := suiteByID(esp.SuiteAESCBC256SHA256, espSuites)
	return buildProposalForSuite(number, s, spi, groups...)
}

// TestSAProposalRoundTrip encodes the full multi-suite IKE offer (one proposal
// per suite, numbered 1..3, all with both DH groups) through the message codec
// and checks it decodes byte-exact with the per-suite wire shape: GCM with
// KeyLength=256 and no INTEG, ChaCha WITHOUT a Key Length attribute and no
// INTEG, CBC with KeyLength=256 plus an HMAC INTEG — and a PRF and no ESN on
// every proposal.
func TestSAProposalRoundTrip(t *testing.T) {
	m := &ikemsg.Message{
		InitiatorSPI: 0x1122334455667788,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagInitiator,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: buildProposals(nil, ikeSuites, ikemsg.DH_X25519, ikemsg.DH_MODP2048)},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xA5}, nonceLen)},
		},
	}

	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	dec, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw2, err := dec.Marshal()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("SA round-trip not byte-exact:\n%x\n%x", raw, raw2)
	}

	var saP *ikemsg.SAPayload
	for _, p := range dec.Payloads {
		if v, ok := p.(*ikemsg.SAPayload); ok {
			saP = v
		}
	}
	if saP == nil || len(saP.Proposals) != len(ikeSuites) {
		t.Fatalf("expected %d decoded proposals", len(ikeSuites))
	}
	for i, prop := range saP.Proposals {
		suite := ikeSuites[i]
		if prop.Number != uint8(i+1) {
			t.Fatalf("proposal %d numbered %d, want %d", i, prop.Number, i+1)
		}
		if len(prop.SPI) != 0 {
			t.Fatalf("IKE_SA_INIT proposal %d carries an SPI: %x", i, prop.SPI)
		}
		encrs := prop.ByType(ikemsg.TransformEncr)
		if len(encrs) != 1 || encrs[0].ID != suite.encrID || encrs[0].KeyLength != suite.keyBits {
			t.Fatalf("proposal %d (%s): ENCR = %+v", i, suite.name(), encrs)
		}
		prfs := prop.ByType(ikemsg.TransformPRF)
		if len(prfs) != 1 || prfs[0].ID != ikemsg.PRF_HMAC_SHA2_256 {
			t.Fatalf("proposal %d (%s): PRF = %+v", i, suite.name(), prfs)
		}
		integs := prop.ByType(ikemsg.TransformInteg)
		if suite.aead() && len(integs) != 0 {
			t.Fatalf("proposal %d (%s): AEAD proposal carries INTEG %+v", i, suite.name(), integs)
		}
		if !suite.aead() && (len(integs) != 1 || integs[0].ID != suite.integID) {
			t.Fatalf("proposal %d (%s): INTEG = %+v", i, suite.name(), integs)
		}
		if !proposalHasDHGroup(prop, ikemsg.DH_X25519) || !proposalHasDHGroup(prop, ikemsg.DH_MODP2048) {
			t.Fatalf("proposal %d (%s): missing a DH group", i, suite.name())
		}
		if len(prop.ByType(ikemsg.TransformESN)) != 0 {
			t.Fatalf("proposal %d (%s): IKE proposal carries ESN", i, suite.name())
		}
		if !suiteMatches(suite, prop) {
			t.Fatalf("proposal %d (%s): does not match its own suite after round-trip", i, suite.name())
		}
	}
}

// TestIKESuiteTableMatchesDerivedKeys cross-checks the session-layer suite
// table against internal/ikesa's key schedule: the SK_e*/SK_a* lengths the
// table advertises must be exactly what Derive produces for that suite id.
func TestIKESuiteTableMatchesDerivedKeys(t *testing.T) {
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	shared := bytes.Repeat([]byte{0x33}, 256)
	for _, suite := range ikeSuites {
		sa := &ikesa.IKESA{}
		if err := sa.Derive(suite.id, ikesa.Initiator, 1, 2, ni, nr, shared); err != nil {
			t.Fatal(err)
		}
		if len(sa.SKei) != suite.encrKeyLen || len(sa.SKai) != suite.integKeyLen {
			t.Fatalf("%s: derived SK_e/SK_a lengths %d/%d, table says %d/%d",
				suite.name(), len(sa.SKei), len(sa.SKai), suite.encrKeyLen, suite.integKeyLen)
		}
	}
}

// TestIKESuiteMatchStrictness pins the strict wire semantics per IKE suite:
// ChaCha must NOT carry a Key Length attribute (RFC 7634), GCM must carry
// exactly 256, a missing PRF disqualifies a proposal, and an AEAD proposal may
// not be narrowed against real-only integrity alternatives — but an explicit
// AUTH_NONE alternative is fine.
func TestIKESuiteMatchStrictness(t *testing.T) {
	gcm := mustIKESuite(t, ikesa.SuiteAESGCM256)
	chacha := mustIKESuite(t, ikesa.SuiteChaCha20Poly1305)

	// ChaCha with an (illegal) KeyLength attribute → no match for any suite.
	p := buildProposalForSuite(1, chacha, nil)
	p.Transforms[0].KeyLength = 256
	p.Transforms[0].HasKeyLength = true
	for _, s := range ikeSuites {
		if suiteMatches(s, p) {
			t.Fatalf("%s matched a ChaCha transform carrying a Key Length attribute", s.name())
		}
	}

	// GCM with a 128-bit Key Length → no match (we only run GCM-256).
	p = buildProposalForSuite(1, gcm, nil)
	p.Transforms[0].KeyLength = 128
	for _, s := range ikeSuites {
		if suiteMatches(s, p) {
			t.Fatalf("%s matched a GCM-128 transform", s.name())
		}
	}

	// A proposal without a PRF cannot match (the PRF drives the key schedule).
	p = buildProposalForSuite(1, gcm, nil)
	p.Transforms = p.Transforms[:1] // drop the PRF
	if suiteMatches(gcm, p) {
		t.Fatal("GCM matched a proposal with no PRF transform")
	}

	// An AEAD proposal whose only integrity options are real algorithms cannot
	// be narrowed to the AEAD suite (RFC 7296 §3.3.3).
	p = buildProposalForSuite(1, gcm, nil)
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_HMAC_SHA2_256_128})
	if suiteMatches(gcm, p) {
		t.Fatal("GCM matched a proposal whose only INTEG option is a real algorithm")
	}

	// ...but an explicit AUTH_NONE among the alternatives is selectable.
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_NONE})
	if !suiteMatches(gcm, p) {
		t.Fatal("GCM did not match a proposal offering AUTH_NONE among the INTEG alternatives")
	}
}

// TestSelectedIKESuiteAmbiguityRejected: a responder "selection" echoing two
// ENCR (or two PRF) alternatives leaves the SKEYSEED split undefined and must
// map to no suite; a clean selection maps to exactly its suite, and a suite
// the config disabled is rejected even if the server picked it.
func TestSelectedIKESuiteAmbiguityRejected(t *testing.T) {
	gcm := mustIKESuite(t, ikesa.SuiteAESGCM256)
	chacha := mustIKESuite(t, ikesa.SuiteChaCha20Poly1305)

	twoENCR := buildProposalForSuite(1, gcm, nil)
	twoENCR.Transforms = append(twoENCR.Transforms,
		ikemsg.Transform{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_CHACHA20_POLY1305})
	if _, ok := selectedSuite(twoENCR, ikeSuites); ok {
		t.Fatal("an ambiguous two-ENCR selection was accepted")
	}

	twoPRF := buildProposalForSuite(1, gcm, nil)
	twoPRF.Transforms = append(twoPRF.Transforms,
		ikemsg.Transform{Type: ikemsg.TransformPRF, ID: 7 /* PRF_HMAC_SHA2_512 */})
	if _, ok := selectedSuite(twoPRF, ikeSuites); ok {
		t.Fatal("an ambiguous two-PRF selection was accepted")
	}

	clean := buildProposalForSuite(2, chacha, nil)
	s, ok := selectedSuite(clean, ikeSuites)
	if !ok || s.id != ikesa.SuiteChaCha20Poly1305 {
		t.Fatalf("clean ChaCha selection mapped to %v, ok=%v", s.id, ok)
	}
	// A selection of a suite that is not enabled must be rejected.
	if _, ok := selectedSuite(clean, []ikeSuite{mustIKESuite(t, ikesa.SuiteAESCBC256SHA256)}); ok {
		t.Fatal("a selection of a disabled suite was accepted")
	}
	// An AEAD selection with a single explicit AUTH_NONE INTEG is valid.
	withNone := buildProposalForSuite(1, gcm, nil)
	withNone.Transforms = append(withNone.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_NONE})
	if s, ok := selectedSuite(withNone, ikeSuites); !ok || s.id != ikesa.SuiteAESGCM256 {
		t.Fatal("an AEAD selection with an explicit AUTH_NONE was rejected")
	}
}

// TestSelectIKEProposalPreference: picking from a peer IKE-rekey offer follows
// OUR preference order (the enabled-slice order), requires an 8-byte SPI, and
// honors the requireGroup constraint (a more-preferred proposal that does not
// advertise the group is skipped in favour of one that does).
func TestSelectIKEProposalPreference(t *testing.T) {
	gcm := mustIKESuite(t, ikesa.SuiteAESGCM256)
	cbc := mustIKESuite(t, ikesa.SuiteAESCBC256SHA256)
	spi := bytes.Repeat([]byte{0xA1}, 8)

	offer := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{
		buildProposalForSuite(1, cbc, spi, ikemsg.DH_MODP2048),
		buildProposalForSuite(2, gcm, spi, ikemsg.DH_MODP2048),
	}}
	p, s, ok := selectProposal(offer, ikeSuites, 0)
	if !ok || s.id != ikesa.SuiteAESGCM256 || p.Number != 2 {
		t.Fatalf("full table: picked %v #%d, want GCM #2", s.id, p.Number)
	}
	p, s, ok = selectProposal(offer, []ikeSuite{cbc}, 0)
	if !ok || s.id != ikesa.SuiteAESCBC256SHA256 || p.Number != 1 {
		t.Fatalf("CBC-only: picked %v #%d, want CBC #1", s.id, p.Number)
	}
	if _, _, ok := selectProposal(offer, []ikeSuite{mustIKESuite(t, ikesa.SuiteChaCha20Poly1305)}, 0); ok {
		t.Fatal("ChaCha-only matched an offer with no ChaCha proposal")
	}

	// A proposal without the 8-byte rekey SPI is not selectable.
	noSPI := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, gcm, nil, ikemsg.DH_MODP2048)}}
	if _, _, ok := selectProposal(noSPI, ikeSuites, 0); ok {
		t.Fatal("a proposal without an 8-byte SPI was selected for an IKE rekey")
	}

	// requireGroup: the GCM proposal lacks the group → fall back to CBC.
	grouped := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{
		buildProposalForSuite(1, gcm, spi), // no DH group
		buildProposalForSuite(2, cbc, spi, ikemsg.DH_MODP2048),
	}}
	p, s, ok = selectProposal(grouped, ikeSuites, ikemsg.DH_MODP2048)
	if !ok || s.id != ikesa.SuiteAESCBC256SHA256 || p.Number != 2 {
		t.Fatalf("requireGroup: picked %v #%d, want CBC #2", s.id, p.Number)
	}
	if _, _, ok := selectProposal(grouped, ikeSuites, ikemsg.DH_X25519); ok {
		t.Fatal("matched despite no proposal advertising the required group")
	}
}

// TestESPProposalsRoundTrip encodes the full multi-suite ESP offer (one
// proposal per suite, numbered 1..3, all with a DH group and ESN) through the
// message codec and checks it decodes byte-exact with the per-suite wire shape:
// GCM with KeyLength=256 and no INTEG, ChaCha WITHOUT a Key Length attribute
// and no INTEG, CBC with KeyLength=256 plus an HMAC INTEG.
func TestESPProposalsRoundTrip(t *testing.T) {
	spi := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	m := &ikemsg.Message{
		InitiatorSPI: 1, ResponderSPI: 2,
		Exchange:  ikemsg.ExchangeIKEAuth,
		Flags:     ikemsg.FlagInitiator,
		MessageID: 1,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: buildProposals(spi, espSuites, ikemsg.DH_X25519)},
		},
	}

	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw2, err := dec.Marshal()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("ESP proposals round-trip not byte-exact:\n%x\n%x", raw, raw2)
	}

	var saP *ikemsg.SAPayload
	for _, p := range dec.Payloads {
		if v, ok := p.(*ikemsg.SAPayload); ok {
			saP = v
		}
	}
	if saP == nil || len(saP.Proposals) != len(espSuites) {
		t.Fatalf("expected %d decoded proposals", len(espSuites))
	}
	for i, prop := range saP.Proposals {
		suite := espSuites[i]
		if prop.Number != uint8(i+1) {
			t.Fatalf("proposal %d numbered %d, want %d", i, prop.Number, i+1)
		}
		if !bytes.Equal(prop.SPI, spi) {
			t.Fatalf("proposal %d SPI mismatch: %x", i, prop.SPI)
		}
		encrs := prop.ByType(ikemsg.TransformEncr)
		if len(encrs) != 1 || encrs[0].ID != suite.encrID || encrs[0].KeyLength != suite.keyBits {
			t.Fatalf("proposal %d (%s): ENCR = %+v", i, suite.name(), encrs)
		}
		integs := prop.ByType(ikemsg.TransformInteg)
		if suite.aead() && len(integs) != 0 {
			t.Fatalf("proposal %d (%s): AEAD proposal carries INTEG %+v", i, suite.name(), integs)
		}
		if !suite.aead() && (len(integs) != 1 || integs[0].ID != suite.integID) {
			t.Fatalf("proposal %d (%s): INTEG = %+v", i, suite.name(), integs)
		}
		if !proposalHasDHGroup(prop, ikemsg.DH_X25519) {
			t.Fatalf("proposal %d (%s): missing the DH group", i, suite.name())
		}
		if !hasTransform(prop.ByType(ikemsg.TransformESN), ikemsg.ESN_NONE, nil) {
			t.Fatalf("proposal %d (%s): missing ESN None", i, suite.name())
		}
		if !suiteMatches(suite, prop) {
			t.Fatalf("proposal %d (%s): does not match its own suite after round-trip", i, suite.name())
		}
	}
}

// TestSuiteMatchStrictness pins the strict wire semantics per suite: ChaCha
// must NOT carry a Key Length attribute (RFC 7634), GCM must carry exactly 256,
// and an AEAD proposal may not be narrowed against real-only integrity
// alternatives — but an explicit AUTH_NONE alternative is fine.
func TestSuiteMatchStrictness(t *testing.T) {
	gcm := mustSuite(t, esp.SuiteAESGCM256)
	chacha := mustSuite(t, esp.SuiteChaCha20Poly1305)
	spi := []byte{1, 2, 3, 4}

	// ChaCha with an (illegal) KeyLength attribute → no match for any suite.
	p := buildProposalForSuite(1, chacha, spi)
	p.Transforms[0].KeyLength = 256
	p.Transforms[0].HasKeyLength = true
	for _, s := range espSuites {
		if suiteMatches(s, p) {
			t.Fatalf("%s matched a ChaCha transform carrying a Key Length attribute", s.name())
		}
	}
	// Even an explicit KEY_LENGTH=0 must be rejected: ChaCha requires the
	// attribute to be absent, not present-with-zero.
	p = buildProposalForSuite(1, chacha, spi)
	p.Transforms[0].HasKeyLength = true
	for _, s := range espSuites {
		if suiteMatches(s, p) {
			t.Fatalf("%s matched a ChaCha transform carrying an explicit zero Key Length attribute", s.name())
		}
	}

	// GCM with a 128-bit Key Length → no match (we only run GCM-256).
	p = buildProposalForSuite(1, gcm, spi)
	p.Transforms[0].KeyLength = 128
	p.Transforms[0].HasKeyLength = true
	for _, s := range espSuites {
		if suiteMatches(s, p) {
			t.Fatalf("%s matched a GCM-128 transform", s.name())
		}
	}

	// An AEAD proposal whose only integrity options are real algorithms cannot
	// be narrowed to the AEAD suite (RFC 7296 §3.3.3).
	p = buildProposalForSuite(1, gcm, spi)
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_HMAC_SHA2_256_128})
	if suiteMatches(gcm, p) {
		t.Fatal("GCM matched a proposal whose only INTEG option is a real algorithm")
	}

	// ...but an explicit AUTH_NONE among the alternatives is selectable.
	p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_NONE})
	if !suiteMatches(gcm, p) {
		t.Fatal("GCM did not match a proposal offering AUTH_NONE among the INTEG alternatives")
	}
}

// TestSelectedESPSuiteAmbiguityRejected: a responder "selection" echoing two
// ENCR alternatives leaves the KEYMAT lengths undefined and must map to no
// suite; a clean single-ENCR selection maps to exactly its suite.
func TestSelectedESPSuiteAmbiguityRejected(t *testing.T) {
	gcm := mustSuite(t, esp.SuiteAESGCM256)
	chacha := mustSuite(t, esp.SuiteChaCha20Poly1305)
	spi := []byte{1, 2, 3, 4}

	ambiguous := buildProposalForSuite(1, gcm, spi)
	ambiguous.Transforms = append(ambiguous.Transforms,
		ikemsg.Transform{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_CHACHA20_POLY1305})
	if _, ok := selectedSuite(ambiguous, espSuites); ok {
		t.Fatal("an ambiguous two-ENCR selection was accepted")
	}

	clean := buildProposalForSuite(2, chacha, spi)
	s, ok := selectedSuite(clean, espSuites)
	if !ok || s.id != esp.SuiteChaCha20Poly1305 {
		t.Fatalf("clean ChaCha selection mapped to %v, ok=%v", s.id, ok)
	}
	// A selection of a suite that is not enabled must be rejected.
	if _, ok := selectedSuite(clean, []espSuite{mustSuite(t, esp.SuiteAESCBC256SHA256)}); ok {
		t.Fatal("a selection of a disabled suite was accepted")
	}
	// An AEAD selection with a single explicit AUTH_NONE INTEG is valid.
	withNone := buildProposalForSuite(1, gcm, spi)
	withNone.Transforms = append(withNone.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: ikemsg.AUTH_NONE})
	if s, ok := selectedSuite(withNone, espSuites); !ok || s.id != esp.SuiteAESGCM256 {
		t.Fatal("an AEAD selection with an explicit AUTH_NONE was rejected")
	}
}

// TestSelectESPProposalPreference: picking from a peer offer follows OUR
// preference order (the enabled-slice order), not the peer's proposal order.
func TestSelectESPProposalPreference(t *testing.T) {
	cbc := mustSuite(t, esp.SuiteAESCBC256SHA256)
	gcm := mustSuite(t, esp.SuiteAESGCM256)
	offer := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{
		buildProposalForSuite(1, cbc, []byte{1, 1, 1, 1}),
		buildProposalForSuite(2, gcm, []byte{2, 2, 2, 2}),
	}}

	p, s, ok := selectProposal(offer, espSuites, 0)
	if !ok || s.id != esp.SuiteAESGCM256 || p.Number != 2 {
		t.Fatalf("full table: picked %v #%d, want GCM #2", s.id, p.Number)
	}
	p, s, ok = selectProposal(offer, []espSuite{cbc}, 0)
	if !ok || s.id != esp.SuiteAESCBC256SHA256 || p.Number != 1 {
		t.Fatalf("CBC-only: picked %v #%d, want CBC #1", s.id, p.Number)
	}
	if _, _, ok := selectProposal(offer, []espSuite{mustSuite(t, esp.SuiteChaCha20Poly1305)}, 0); ok {
		t.Fatal("ChaCha-only matched an offer with no ChaCha proposal")
	}
}

// TestSelectESPProposalRequireGroup: with a DH-group constraint, a
// more-preferred proposal that does not advertise the group is skipped in
// favour of one that does; no group anywhere → no match.
func TestSelectESPProposalRequireGroup(t *testing.T) {
	gcm := mustSuite(t, esp.SuiteAESGCM256)
	offer := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{
		buildProposalForSuite(1, gcm, []byte{1, 1, 1, 1}), // no DH group
		buildESPProposalCBC(2, []byte{2, 2, 2, 2}, ikemsg.DH_MODP2048),
	}}

	p, s, ok := selectProposal(offer, espSuites, ikemsg.DH_MODP2048)
	if !ok || s.id != esp.SuiteAESCBC256SHA256 || p.Number != 2 {
		t.Fatalf("requireGroup: picked %v #%d, want CBC #2", s.id, p.Number)
	}
	if _, _, ok := selectProposal(offer, espSuites, ikemsg.DH_X25519); ok {
		t.Fatal("matched despite no proposal advertising the required group")
	}
}

// TestSuiteMatchToleratesAlternatives asserts the matcher accepts a
// peer-initiated offer that lists multiple alternative transforms per type (the
// strongSwan both-ESN default), that a GCM-128 proposal matches no suite (the
// key length is strict — 128 is not the 256 we run), and that selection from a
// mixed offer follows our preference.
func TestSuiteMatchToleratesAlternatives(t *testing.T) {
	cbc := mustSuite(t, esp.SuiteAESCBC256SHA256)
	gcm := mustSuite(t, esp.SuiteAESGCM256)

	multi := buildESPProposalMultiOption(1, []byte{1, 2, 3, 4})
	if !suiteMatches(cbc, multi) {
		t.Fatal("matcher rejected a valid multi-option offer (both-ESN regression)")
	}

	// AES-GCM-128: same transform ID as our GCM suite but a key length we do
	// not run — unmatched by every suite (not "unsupported transform" anymore,
	// but a strict key-length mismatch).
	gcm128 := ikemsg.Proposal{
		Number: 1, Protocol: ikemsg.ProtocolESP, SPI: []byte{9, 9, 9, 9},
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_AES_GCM_16, KeyLength: 128, HasKeyLength: true},
			{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE},
		},
	}
	for _, s := range espSuites {
		if suiteMatches(s, gcm128) {
			t.Fatalf("%s matched an AES-GCM-128 proposal", s.name())
		}
	}

	// [GCM-128, multi-CBC, GCM-256]: the full table picks GCM-256 (our top
	// preference), a CBC-only config picks the multi-CBC offer.
	gcm256 := buildProposalForSuite(3, gcm, []byte{5, 6, 7, 8})
	saP := &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{gcm128, multi, gcm256}}
	p, s, ok := selectProposal(saP, espSuites, 0)
	if !ok || s.id != esp.SuiteAESGCM256 || !bytes.Equal(p.SPI, gcm256.SPI) {
		t.Fatal("selectProposal did not pick the GCM-256 proposal")
	}
	p, s, ok = selectProposal(saP, []espSuite{cbc}, 0)
	if !ok || s.id != esp.SuiteAESCBC256SHA256 || !bytes.Equal(p.SPI, multi.SPI) {
		t.Fatal("CBC-only selectProposal did not pick the multi-option CBC proposal")
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":          "1.2.3.4:500",
		"1.2.3.4:4500":     "1.2.3.4:4500",
		"vpn.example.com":  "vpn.example.com:500",
		"[2001:db8::1]":    "[2001:db8::1]:500",
		"[2001:db8::1]:99": "[2001:db8::1]:99",
	}
	for in, want := range cases {
		if got := withDefaultPort(in); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}
