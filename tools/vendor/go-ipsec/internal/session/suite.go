package session

import (
	"fmt"
	"slices"
	"strings"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// keyLenAES256 is the AES-256 Key Length attribute value (in bits) carried on
// the encryption transform of the IKE suite and the AES-based ESP suites.
const keyLenAES256 uint16 = 256

// suiteID is the constraint shared by esp.Suite and ikesa.Suite: a uint8-based
// transform id that also renders a diagnostic name. It lets one generic
// negotiation core serve both the ESP (Child SA) and IKE (SK{} envelope) suite
// tables instead of two byte-for-byte parallel copies.
type suiteID interface {
	~uint8
	fmt.Stringer
}

// transformSuite describes one negotiable transform suite for either layer: the
// wire transforms it is offered and matched by, and the per-direction KEYMAT
// lengths internal/ikesa derives for it. The layer (ESP or IKE) is fixed by the
// ID type parameter (see protocol), which governs the only structural
// differences between the two — an IKE proposal carries a PRF transform and an
// 8-byte SPI, an ESP proposal an ESN transform and a 4-byte SPI. The
// espSuite/ikeSuite aliases below pin the id type per layer.
type transformSuite[ID suiteID] struct {
	id     ID
	encrID uint16 // ENCR transform ID
	// keyBits is the Key Length attribute value on the ENCR transform; 0 means
	// the attribute is ABSENT (ChaCha20-Poly1305, RFC 7634 §2 — its key size is
	// implicit and a peer must not attach the attribute). Matching is strict in
	// both directions: tolerance here would let the two ends derive different
	// KEYMAT lengths.
	keyBits    uint16
	encrKeyLen int // per-direction encryption KEYMAT (including the salt for AEAD)
	// integID is the INTEG transform ID; 0 means the suite is AEAD and no INTEG
	// transform is emitted (this client never offers an explicit AUTH_NONE).
	integID     uint16
	integKeyLen int // per-direction integrity KEYMAT (0 for AEAD)
}

// espSuite / ikeSuite pin transformSuite to each layer's Suite enum. They are
// aliases, so the id field, key lengths and helper methods are shared; only the
// id type (and with it the protocol) differs.
type (
	espSuite = transformSuite[esp.Suite]
	ikeSuite = transformSuite[ikesa.Suite]
)

// name returns the suite's diagnostic name (shared with the Suite.String impls).
func (s transformSuite[ID]) name() string { return s.id.String() }

// protocol returns the IKE protocol the suite's layer negotiates, derived from
// the ID type so a table row cannot disagree with its layer: ProtocolESP for an
// esp.Suite row, ProtocolIKE for an ikesa.Suite row. Any other ID type is a
// programming error (the suiteID constraint cannot name the two types exactly).
func (s transformSuite[ID]) protocol() ikemsg.ProtocolID {
	switch any(s.id).(type) {
	case esp.Suite:
		return ikemsg.ProtocolESP
	case ikesa.Suite:
		return ikemsg.ProtocolIKE
	default:
		panic(fmt.Sprintf("session: transformSuite with unsupported id type %T", s.id))
	}
}

// aead reports whether the suite is a combined-mode (AEAD) cipher.
func (s transformSuite[ID]) aead() bool { return s.integID == 0 }

// spiLen is the SPI size the suite's protocol carries in a proposal: 8 bytes for
// an IKE SA, 4 for an ESP Child SA (RFC 7296 §3.3.1).
func (s transformSuite[ID]) spiLen() int {
	if s.protocol() == ikemsg.ProtocolIKE {
		return 8
	}
	return 4
}

// espSuites is the full ESP suite table in this client's preference order:
// AES-256-GCM-16 (hardware-accelerated single pass), ChaCha20-Poly1305 (fast
// without AES-NI), then the RFC-MUST AES-CBC-256 + HMAC-SHA2-256-128.
var espSuites = []espSuite{
	{id: esp.SuiteAESGCM256, encrID: ikemsg.ENCR_AES_GCM_16, keyBits: keyLenAES256, encrKeyLen: 36},
	{id: esp.SuiteChaCha20Poly1305, encrID: ikemsg.ENCR_CHACHA20_POLY1305, encrKeyLen: 36},
	{id: esp.SuiteAESCBC256SHA256, encrID: ikemsg.ENCR_AES_CBC, keyBits: keyLenAES256, encrKeyLen: 32,
		integID: ikemsg.AUTH_HMAC_SHA2_256_128, integKeyLen: 32},
}

// ikeSuites is the negotiable IKE suite table in this client's preference order,
// mirroring the ESP table: AES-256-GCM-16 (RFC 5282, single pass,
// hardware-accelerated), ChaCha20-Poly1305 (RFC 7634), then the RFC-MUST
// AES-CBC-256 + HMAC-SHA2-256-128. The PRF is PRF_HMAC_SHA2_256 in every row (it
// also drives the AUTH signed octets), so only the encryption transform is
// negotiable.
var ikeSuites = []ikeSuite{
	{id: ikesa.SuiteAESGCM256, encrID: ikemsg.ENCR_AES_GCM_16, keyBits: keyLenAES256, encrKeyLen: 36},
	{id: ikesa.SuiteChaCha20Poly1305, encrID: ikemsg.ENCR_CHACHA20_POLY1305, encrKeyLen: 36},
	{id: ikesa.SuiteAESCBC256SHA256, encrID: ikemsg.ENCR_AES_CBC, keyBits: keyLenAES256, encrKeyLen: 32,
		integID: ikemsg.AUTH_HMAC_SHA2_256_128, integKeyLen: 32},
}

// suiteByID returns the table row for a suite id.
func suiteByID[ID suiteID](id ID, table []transformSuite[ID]) (transformSuite[ID], bool) {
	for _, s := range table {
		if s.id == id {
			return s, true
		}
	}
	return transformSuite[ID]{}, false
}

// enabledSuites maps a Config suite-id list into table rows, preserving the
// caller's preference order; nil/empty enables the full table in its built-in
// order. Unknown ids are skipped here; checkSuites rejects them up front (at
// IKESAInit) so a skipped id can never shrink an offer silently.
func enabledSuites[ID suiteID](configured []ID, table []transformSuite[ID]) []transformSuite[ID] {
	if len(configured) == 0 {
		return table
	}
	out := make([]transformSuite[ID], 0, len(configured))
	for _, id := range configured {
		if s, ok := suiteByID(id, table); ok {
			out = append(out, s)
		}
	}
	return out
}

// checkSuites reports an error for any configured id that has no row in the
// layer's table. The public config layer validates against its own mapper, so
// this is the backstop for a mapper/table drift (a new Suite mapped but never
// added to the table) or a session.Config built directly with a bogus id —
// either would otherwise drop the id silently, or offer an empty SA payload.
func checkSuites[ID suiteID](layer string, configured []ID, table []transformSuite[ID]) error {
	for _, id := range configured {
		if _, ok := suiteByID(id, table); !ok {
			return fmt.Errorf("session: %s suite %v has no negotiation table entry", layer, id)
		}
	}
	return nil
}

// checkConfiguredSuites validates Config.ESPSuites / IKESuites against the
// built-in tables (see checkSuites).
func (s *Session) checkConfiguredSuites() error {
	if err := checkSuites("ESP", s.cfg.ESPSuites, espSuites); err != nil {
		return err
	}
	return checkSuites("IKE", s.cfg.IKESuites, ikeSuites)
}

// enabledESPSuites / enabledIKESuites resolve the session's configured suite
// preference (Config.ESPSuites / IKESuites) against the built-in tables.
func (s *Session) enabledESPSuites() []espSuite { return enabledSuites(s.cfg.ESPSuites, espSuites) }
func (s *Session) enabledIKESuites() []ikeSuite { return enabledSuites(s.cfg.IKESuites, ikeSuites) }

// buildProposalForSuite returns the proposal for one suite, with transforms in
// the canonical RFC 7296 §3.3 emission order for the suite's protocol so the
// encoding is byte-deterministic: Encr, PRF, [Integ], [DH...] for IKE; Encr,
// [Integ], [DH...], ESN for ESP. An AEAD suite carries no INTEG transform (RFC
// 7296 §3.3.3) and a keyBits==0 suite no Key Length attribute. spi is empty for
// IKE_SA_INIT and the protocol's SPI (4-byte ESP / 8-byte IKE) otherwise.
func buildProposalForSuite[ID suiteID](number uint8, s transformSuite[ID], spi []byte, groups ...uint16) ikemsg.Proposal {
	p := ikemsg.Proposal{
		Number:   number,
		Protocol: s.protocol(),
		Transforms: []ikemsg.Transform{
			{Type: ikemsg.TransformEncr, ID: s.encrID, KeyLength: s.keyBits, HasKeyLength: s.keyBits != 0},
		},
	}
	if len(spi) > 0 {
		p.SPI = append([]byte(nil), spi...)
	}
	if s.protocol() == ikemsg.ProtocolIKE {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformPRF, ID: ikemsg.PRF_HMAC_SHA2_256})
	}
	if !s.aead() {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformInteg, ID: s.integID})
	}
	for _, g := range groups {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformDH, ID: g})
	}
	if s.protocol() == ikemsg.ProtocolESP {
		p.Transforms = append(p.Transforms, ikemsg.Transform{Type: ikemsg.TransformESN, ID: ikemsg.ESN_NONE})
	}
	return p
}

// buildProposals returns one proposal per enabled suite, numbered 1..n in the
// given preference order — one proposal per suite (rather than one proposal with
// alternative ENCR transforms) keeps the cipher choice under OUR preference (a
// responder picks the first proposal it can run), maps a selection back to its
// suite trivially, and never mixes AEAD and non-AEAD transforms in one proposal
// (RFC 7296 §3.3.3). Any DH groups are advertised identically on every proposal.
func buildProposals[ID suiteID](spi []byte, suites []transformSuite[ID], groups ...uint16) []ikemsg.Proposal {
	props := make([]ikemsg.Proposal, 0, len(suites))
	for i, s := range suites {
		props = append(props, buildProposalForSuite(uint8(i+1), s, spi, groups...))
	}
	return props
}

// hasTransform reports whether the offered transforms include one with the given
// IANA ID (and, when keyLen != nil, that key-length attribute — where a *keyLen
// of 0 requires the attribute to be ABSENT). A peer that INITIATES a
// CREATE_CHILD_SA offers MULTIPLE alternative transforms per type for us to
// choose from — strongSwan, for example, offers both No-ESN and ESN by default.
// Suite matching therefore checks that our required transform is PRESENT among
// the offered alternatives, not that it is the sole option (which only holds
// for an already-narrowed responder selection). RFC 7296 §3.3.
func hasTransform(ts []ikemsg.Transform, id uint16, keyLen *uint16) bool {
	for _, t := range ts {
		if t.ID != id {
			continue
		}
		if keyLen != nil {
			switch {
			case *keyLen == 0 && t.HasKeyLength:
				continue // key length must be ABSENT
			case *keyLen != 0 && (!t.HasKeyLength || t.KeyLength != *keyLen):
				continue
			}
		}
		return true
	}
	return false
}

// suiteMatches reports whether a proposal offers the given suite, tolerating
// extra alternative transforms a peer-initiated proposal may list alongside ours
// (presence semantics). The ENCR key length is matched strictly in both
// directions: keyBits==0 (ChaCha20-Poly1305) matches only a transform WITHOUT the
// Key Length attribute, keyBits==256 only a transform carrying exactly 256 —
// tolerance would silently desync the KEYMAT lengths. For an AEAD suite the
// proposal must carry either no INTEG transform or an explicit AUTH_NONE among
// the alternatives (RFC 7296 §3.3.3 forbids combining an AEAD cipher with a
// separate integrity transform). An IKE proposal must additionally carry the
// PRF; an ESP proposal the (No-)ESN transform. The DH group is checked
// separately by the callers — the constraint differs per exchange.
func suiteMatches[ID suiteID](s transformSuite[ID], p ikemsg.Proposal) bool {
	if p.Protocol != s.protocol() {
		return false
	}
	keyBits := s.keyBits
	if !hasTransform(p.ByType(ikemsg.TransformEncr), s.encrID, &keyBits) {
		return false
	}
	if s.protocol() == ikemsg.ProtocolIKE &&
		!hasTransform(p.ByType(ikemsg.TransformPRF), ikemsg.PRF_HMAC_SHA2_256, nil) {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		if len(integs) > 0 && !hasTransform(integs, ikemsg.AUTH_NONE, nil) {
			return false
		}
	} else if !hasTransform(integs, s.integID, nil) {
		return false
	}
	if s.protocol() == ikemsg.ProtocolESP &&
		!hasTransform(p.ByType(ikemsg.TransformESN), ikemsg.ESN_NONE, nil) {
		return false
	}
	return true
}

// isSelectionFor reports whether p is a valid narrowed responder SELECTION of the
// suite: beyond suiteMatches (presence among possibly-many offered alternatives)
// it requires exactly one ENCR transform, an unambiguous integrity type — none
// or a single AUTH_NONE for an AEAD suite, exactly one HMAC otherwise — at most
// one DH transform, and, for IKE, exactly one PRF, for ESP exactly one ESN
// transform. The selected suite fixes the KEYMAT/SKEYSEED split and the
// sequence-number width, so an ambiguous "selection" would leave the key
// schedule or the data plane undefined (RFC 7296 §2.7).
func isSelectionFor[ID suiteID](s transformSuite[ID], p ikemsg.Proposal) bool {
	if !suiteMatches(s, p) || len(p.ByType(ikemsg.TransformEncr)) != 1 {
		return false
	}
	if len(p.ByType(ikemsg.TransformDH)) > 1 {
		return false
	}
	if s.protocol() == ikemsg.ProtocolIKE && len(p.ByType(ikemsg.TransformPRF)) != 1 {
		return false
	}
	if s.protocol() == ikemsg.ProtocolESP && len(p.ByType(ikemsg.TransformESN)) != 1 {
		return false
	}
	integs := p.ByType(ikemsg.TransformInteg)
	if s.aead() {
		return len(integs) == 0 || (len(integs) == 1 && integs[0].ID == ikemsg.AUTH_NONE)
	}
	return len(integs) == 1
}

// selectedSuite maps a narrowed responder proposal to the single enabled suite it
// selects, or ok=false when the proposal is ambiguous or selects a suite we did
// not offer. At most one suite can pass isSelectionFor (the single ENCR transform
// pins the suite), so the enabled order does not matter here — it is the
// responder's choice being decoded, not a preference.
func selectedSuite[ID suiteID](p ikemsg.Proposal, enabled []transformSuite[ID]) (transformSuite[ID], bool) {
	for _, s := range enabled {
		if isSelectionFor(s, p) {
			return s, true
		}
	}
	return transformSuite[ID]{}, false
}

// selectProposal picks from a peer-initiated offer: the first enabled suite (in
// OUR preference order) that some offered proposal advertises with the protocol's
// SPI size, together with that proposal. requireGroup, when non-zero,
// additionally requires the proposal to advertise that DH group — a peer's KE
// group may be advertised by only some of its proposals, and the DH exchange must
// run against a proposal that actually offered the group (RFC 7296 §3.3).
func selectProposal[ID suiteID](sa *ikemsg.SAPayload, enabled []transformSuite[ID], requireGroup uint16) (ikemsg.Proposal, transformSuite[ID], bool) {
	for _, s := range enabled {
		for _, p := range sa.Proposals {
			if !suiteMatches(s, p) || len(p.SPI) != s.spiLen() {
				continue
			}
			if requireGroup != 0 && !proposalHasDHGroup(p, requireGroup) {
				continue
			}
			return p, s, true
		}
	}
	return ikemsg.Proposal{}, transformSuite[ID]{}, false
}

// preferredDHGroups lists the DH groups internal/ikesa can run, most-preferred
// first: Curve25519 (group 31), MODP-2048 (group 14), P-256 (group 19), and P-384
// (group 20). It drives both the multi-group offers we build and the group we
// pick from a peer's offer.
var preferredDHGroups = []uint16{ikemsg.DH_X25519, ikemsg.DH_MODP2048, 19, 20}

func (s *Session) configuredDHGroups() []uint16 {
	if len(s.cfg.DHGroups) > 0 {
		return s.cfg.DHGroups
	}
	return preferredDHGroups
}

// supportedDHGroup reports whether g is a DH group we can run.
func supportedDHGroup(g uint16) bool {
	return slices.Contains(preferredDHGroups, g)
}

// proposalHasDHGroup reports whether a proposal offers the given DH group. A
// peer-initiated proposal may list several alternative DH transforms; this checks
// for presence among them (like hasTransform), not that it is the sole option.
func proposalHasDHGroup(p ikemsg.Proposal, g uint16) bool {
	return hasTransform(p.ByType(ikemsg.TransformDH), g, nil)
}

// selectedDHGroup returns the single DH-group ID carried by a narrowed responder
// proposal (the responder selects exactly one transform per type, RFC 7296 §2.7),
// or 0 when the proposal carries no DH transform.
func selectedDHGroup(p ikemsg.Proposal) uint16 {
	dh := p.ByType(ikemsg.TransformDH)
	if len(dh) == 0 {
		return 0
	}
	return dh[0].ID
}

// describeProposals renders the offered proposals' transform IDs so a no-match
// error names exactly what the peer proposed (the information needed to debug an
// interop mismatch).
func describeProposals(sa *ikemsg.SAPayload) string {
	var b strings.Builder
	for i, p := range sa.Proposals {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "#%d proto=%d enc=%v integ=%v prf=%v dh=%v esn=%v spiLen=%d",
			p.Number, p.Protocol,
			transformIDs(p.ByType(ikemsg.TransformEncr)), transformIDs(p.ByType(ikemsg.TransformInteg)),
			transformIDs(p.ByType(ikemsg.TransformPRF)), transformIDs(p.ByType(ikemsg.TransformDH)),
			transformIDs(p.ByType(ikemsg.TransformESN)), len(p.SPI))
	}
	return b.String()
}

func transformIDs(ts []ikemsg.Transform) []uint16 {
	ids := make([]uint16, len(ts))
	for i, t := range ts {
		ids[i] = t.ID
	}
	return ids
}
