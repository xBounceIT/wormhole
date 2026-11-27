package vault

import (
	"encoding/binary"

	"github.com/google/uuid"
)

type RDPBitwardenSlots byte

const (
	RDPBitwardenPrimary RDPBitwardenSlots = 1 << iota
	RDPBitwardenGateway
	rdpBitwardenLinkBytes = 32
)

func (s RDPBitwardenSlots) valid() bool {
	return s != 0 && s & ^(RDPBitwardenPrimary|RDPBitwardenGateway) == 0
}

// The link is shared only by the vault, the RDP recipient and the one-use
// resolver. The resolver has no access to the vault's target-encrypted base.
type RDPBitwardenLookup struct {
	PrimaryItemID string `json:"primaryItemId,omitempty"`
	GatewayItemID string `json:"gatewayItemId,omitempty"`
	Link          []byte `json:"link"`
}

func (r RDPBitwardenLookup) Slots() RDPBitwardenSlots {
	var slots RDPBitwardenSlots
	if r.PrimaryItemID != "" {
		slots |= RDPBitwardenPrimary
	}
	if r.GatewayItemID != "" {
		slots |= RDPBitwardenGateway
	}
	return slots
}

func (r RDPBitwardenLookup) valid(routed bool) bool {
	if !r.Slots().valid() || len(r.Link) != rdpBitwardenLinkBytes || (routed && r.GatewayItemID != "") {
		return false
	}
	for _, id := range []string{r.PrimaryItemID, r.GatewayItemID} {
		if id != "" {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil || parsed.String() != id {
				return false
			}
		}
	}
	return true
}

func validateRDPBitwardenBase(base RDPBundlePayload, slots RDPBitwardenSlots) error {
	if !slots.valid() ||
		(slots&RDPBitwardenPrimary != 0 && base.PasswordProvided) ||
		(slots&RDPBitwardenGateway != 0 && (base.GatewayPasswordProvided || base.Settings.GatewayUsageMethod == 0 || base.Settings.GatewayUseSameCreds)) {
		return ErrPolicy
	}
	return nil
}

func EncodeRDPBitwardenBase(base RDPBundlePayload, slots RDPBitwardenSlots, link []byte) ([]byte, error) {
	if validateRDPBitwardenBase(base, slots) != nil {
		return nil, ErrFormat
	}
	frame, err := EncodeRDPBundle(base)
	defer Wipe(frame)
	if err != nil {
		return nil, err
	}
	return encodeRDPBitwardenBase(frame, slots, link)
}

func EncodeManualRDPBitwardenBase(base RDPBundlePayload, inner SealedBundle, link []byte) ([]byte, error) {
	if validateRDPBitwardenBase(base, RDPBitwardenGateway) != nil {
		return nil, ErrFormat
	}
	frame, err := EncodeRDPManualAuthorization(base, inner)
	defer Wipe(frame)
	if err != nil {
		return nil, err
	}
	return encodeRDPBitwardenBase(frame, RDPBitwardenGateway, link)
}

func encodeRDPBitwardenBase(frame []byte, slots RDPBitwardenSlots, link []byte) ([]byte, error) {
	if len(link) != rdpBitwardenLinkBytes || len(frame)+2+len(link) > MaxRDPBundleBytes {
		return nil, ErrFormat
	}
	raw := make([]byte, 2, 2+len(link)+len(frame))
	raw[0], raw[1] = 3, byte(slots)
	raw = append(raw, link...)
	return append(raw, frame...), nil
}

func decodeRDPBitwardenBase(raw []byte) (RDPBundlePayload, RDPBitwardenSlots, []byte, error) {
	if len(raw) < 2+rdpBitwardenLinkBytes+26 || len(raw) > MaxRDPBundleBytes || raw[0] != 3 {
		return RDPBundlePayload{}, 0, nil, ErrFormat
	}
	slots := RDPBitwardenSlots(raw[1])
	base, err := DecodeRDPBundle(raw[2+rdpBitwardenLinkBytes:])
	if err != nil || validateRDPBitwardenBase(base, slots) != nil {
		return RDPBundlePayload{}, 0, nil, ErrFormat
	}
	return base, slots, raw[2 : 2+rdpBitwardenLinkBytes], nil
}

type RDPBitwardenAccounts struct {
	Username, GatewayUsername string
	Password, GatewayPassword []byte
}

func (p RDPBitwardenAccounts) validate(slots RDPBitwardenSlots) error {
	if !validRDPBundleIdentity(p.Username) || !validRDPBundleIdentity(p.GatewayUsername) ||
		!validRDPBundlePassword(p.Password) || !validRDPBundlePassword(p.GatewayPassword) {
		return ErrFormat
	}
	if slots&RDPBitwardenPrimary != 0 {
		if len(p.Password) == 0 {
			return ErrAuthentication
		}
	} else if len(p.Password) != 0 || p.Username != "" {
		return ErrPolicy
	}
	if slots&RDPBitwardenGateway != 0 {
		if len(p.GatewayPassword) == 0 {
			return ErrAuthentication
		}
	} else if len(p.GatewayPassword) != 0 || p.GatewayUsername != "" {
		return ErrPolicy
	}
	return nil
}

func rdpBitwardenAccountsInfo(b BundleBinding, route *TunnelBundleBinding, endpoint string, slots RDPBitwardenSlots, link []byte) ([]byte, error) {
	if !slots.valid() || len(link) != rdpBitwardenLinkBytes || !ValidRDPHost(b.Host) {
		return nil, ErrFormat
	}
	bound, err := manualCredentialInfo(b, route, endpoint, "rdp", "wormhole/v1/rdp-bitwarden-accounts")
	if err != nil {
		return nil, err
	}
	return canonical("wormhole/v1/rdp-bitwarden-link", bound, []byte{byte(slots)}, link), nil
}

func SealRDPBitwardenAccounts(public []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, lookup RDPBitwardenLookup, accounts RDPBitwardenAccounts) (SealedBundle, error) {
	slots := lookup.Slots()
	info, err := rdpBitwardenAccountsInfo(b, route, endpoint, slots, lookup.Link)
	if err != nil {
		return SealedBundle{}, err
	}
	defer Wipe(info)
	if err = accounts.validate(slots); err != nil {
		return SealedBundle{}, err
	}
	fields := [][]byte{[]byte(accounts.Username), accounts.Password, []byte(accounts.GatewayUsername), accounts.GatewayPassword}
	size := 16
	for _, field := range fields {
		size += len(field)
	}
	raw := make([]byte, 0, size)
	for _, field := range fields {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}

// The returned passwords borrow baseRaw or the returned account frame. Both
// buffers belong to the native recipient and must be cleared after handoff.
func OpenRDPBitwardenAccounts(private []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, baseRaw []byte, sealed SealedBundle) (RDPBundlePayload, []byte, error) {
	base, slots, link, err := decodeRDPBitwardenBase(baseRaw)
	if err != nil {
		return RDPBundlePayload{}, nil, err
	}
	return openRDPBitwardenAccounts(private, b, route, endpoint, base, slots, link, sealed)
}

func OpenManualRDPBitwardenAccounts(private []byte, b BundleBinding, baseRaw []byte, sealed SealedBundle) (RDPBundlePayload, SealedBundle, []byte, error) {
	const header = 2 + rdpBitwardenLinkBytes
	if len(baseRaw) < header || len(baseRaw) > MaxRDPBundleBytes || baseRaw[0] != 3 || RDPBitwardenSlots(baseRaw[1]) != RDPBitwardenGateway {
		return RDPBundlePayload{}, SealedBundle{}, nil, ErrFormat
	}
	base, inner, err := DecodeRDPManualAuthorization(baseRaw[header:])
	if err != nil || validateRDPBitwardenBase(base, RDPBitwardenGateway) != nil {
		return RDPBundlePayload{}, SealedBundle{}, nil, ErrFormat
	}
	payload, raw, err := openRDPBitwardenAccounts(private, b, nil, "", base, RDPBitwardenGateway, baseRaw[2:header], sealed)
	if err != nil {
		return RDPBundlePayload{}, SealedBundle{}, nil, err
	}
	return payload, inner, raw, nil
}

func openRDPBitwardenAccounts(private []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, base RDPBundlePayload, slots RDPBitwardenSlots, link []byte, sealed SealedBundle) (RDPBundlePayload, []byte, error) {
	info, err := rdpBitwardenAccountsInfo(b, route, endpoint, slots, link)
	if err != nil {
		return RDPBundlePayload{}, nil, err
	}
	defer Wipe(info)
	if validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) < 33 || len(sealed.Ciphertext) > 16+16+2*2048+2*16384 {
		return RDPBundlePayload{}, nil, ErrFormat
	}
	raw, err := openBundlePayload(private, info, sealed)
	if err != nil {
		return RDPBundlePayload{}, nil, err
	}
	fields := [4][]byte{}
	rest := raw
	for i := range fields {
		if len(rest) < 4 {
			Wipe(raw)
			return RDPBundlePayload{}, nil, ErrFormat
		}
		n := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			Wipe(raw)
			return RDPBundlePayload{}, nil, ErrFormat
		}
		fields[i], rest = rest[:int(n)], rest[int(n):]
	}
	accounts := RDPBitwardenAccounts{Username: string(fields[0]), Password: fields[1], GatewayUsername: string(fields[2]), GatewayPassword: fields[3]}
	if len(rest) != 0 || accounts.validate(slots) != nil {
		Wipe(raw)
		return RDPBundlePayload{}, nil, ErrFormat
	}
	if slots&RDPBitwardenPrimary != 0 {
		base.Password, base.PasswordProvided = accounts.Password, true
		if base.Username == "" {
			base.Username = accounts.Username
		}
	}
	if slots&RDPBitwardenGateway != 0 {
		base.GatewayPassword, base.GatewayPasswordProvided = accounts.GatewayPassword, true
		if base.GatewayUsername == "" {
			base.GatewayUsername = accounts.GatewayUsername
		}
	}
	return base, raw, nil
}
