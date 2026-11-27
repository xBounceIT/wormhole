package vault

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const (
	BitwardenTicketLifetime = 90 * time.Second
	MaxBitwardenTicket      = 96 * 1024
	MaxBitwardenSession     = 64 * 1024
)

type ConnectionBitwardenTicket struct {
	Binding BundleBinding `json:"binding"`
	Ticket  SealedBundle  `json:"ticket"`
}

// Only serve may open this ticket. The target receives a different bundle
// containing its login and never receives the Bitwarden session.
type ConnectionBitwardenTicketPayload struct {
	TargetPublicKey []byte               `json:"targetPublicKey"`
	SavedSession    []byte               `json:"savedSession"`
	ItemID          string               `json:"itemId"`
	Username        string               `json:"username"`
	Fingerprint     string               `json:"fingerprint"`
	SFTPOnly        bool                 `json:"sftpOnly"`
	AutoSudo        bool                 `json:"autoSudo"`
	RDP             *RDPBitwardenLookup  `json:"rdp,omitempty"`
	Route           *TunnelBundleBinding `json:"route,omitempty"`
	Endpoint        string               `json:"endpoint"`
	ExpiresAt       int64                `json:"expiresAt"`
}

func connectionBitwardenTicketInfo(b BundleBinding) ([]byte, error) {
	for _, id := range []string{b.WorkspaceID, b.SessionID, b.RequestID, b.NodeID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, ErrFormat
		}
	}
	if b.Port == 0 || b.UseExternalClient || b.Epoch > 9007199254740991 ||
		strings.IndexFunc(b.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 {
		return nil, ErrFormat
	}
	var domain string
	switch b.Protocol {
	case "ssh", "sftp":
		domain = "wormhole/v1/ssh-bitwarden-ticket"
	case "vnc":
		if len(b.Host) > 1024 {
			return nil, ErrFormat
		}
		domain = "wormhole/v1/vnc-bitwarden-ticket"
	case "rdp":
		if !ValidRDPHost(b.Host) {
			return nil, ErrFormat
		}
		domain = "wormhole/v1/rdp-bitwarden-ticket"
	default:
		return nil, ErrFormat
	}
	base, err := b.info()
	if err != nil {
		return nil, err
	}
	return canonical(domain, base), nil
}

func (p ConnectionBitwardenTicketPayload) validate(b BundleBinding, now time.Time) error {
	if validateX25519Public(p.TargetPublicKey) != nil ||
		len(p.SavedSession) == 0 || len(p.SavedSession) > MaxBitwardenSession ||
		p.ExpiresAt <= now.UnixMilli() || p.ExpiresAt > now.Add(BitwardenTicketLifetime).UnixMilli() {
		return ErrFormat
	}
	if b.Protocol == "rdp" {
		if p.RDP == nil || !p.RDP.valid(p.Route != nil) || p.ItemID != "" {
			return ErrFormat
		}
	} else {
		id, err := uuid.Parse(p.ItemID)
		if err != nil || id == uuid.Nil || id.String() != p.ItemID || p.RDP != nil {
			return ErrFormat
		}
	}
	if b.Protocol == "vnc" || b.Protocol == "rdp" {
		if p.Fingerprint != "" || p.Username != "" || p.AutoSudo || p.SFTPOnly {
			return ErrFormat
		}
	} else if !ValidSSHFingerprint(p.Fingerprint) || !validText(p.Username, MaxContextBytes, true) ||
		(p.AutoSudo && (p.SFTPOnly || b.Protocol != "ssh")) {
		return ErrFormat
	}
	if p.Route == nil {
		if b.TunnelConfigID != "" || p.Endpoint != "" {
			return ErrFormat
		}
		return nil
	}
	if p.Route.BundleBinding != b {
		return ErrAuthentication
	}
	_, err := routedBundleInfo(*p.Route, p.Endpoint)
	return err
}

func SealConnectionBitwardenTicket(recipient []byte, b BundleBinding, p ConnectionBitwardenTicketPayload, now time.Time) (ConnectionBitwardenTicket, error) {
	info, err := connectionBitwardenTicketInfo(b)
	if err != nil {
		return ConnectionBitwardenTicket{}, err
	}
	if p.validate(b, now) != nil || validateX25519Public(recipient) != nil || bytes.Equal(recipient, p.TargetPublicKey) {
		return ConnectionBitwardenTicket{}, ErrFormat
	}
	plain, err := json.Marshal(p)
	defer Wipe(plain)
	if err != nil || len(plain) > MaxBitwardenTicket {
		return ConnectionBitwardenTicket{}, ErrFormat
	}
	sealed, err := sealBundlePayload(recipient, info, plain)
	if err != nil {
		return ConnectionBitwardenTicket{}, err
	}
	return ConnectionBitwardenTicket{Binding: b, Ticket: sealed}, nil
}

func OpenConnectionBitwardenTicket(private []byte, ticket ConnectionBitwardenTicket, now time.Time) (ConnectionBitwardenTicketPayload, error) {
	if validateSealedBundle(ticket.Ticket) != nil || len(ticket.Ticket.Ciphertext) > MaxBitwardenTicket+16 {
		return ConnectionBitwardenTicketPayload{}, ErrFormat
	}
	info, err := connectionBitwardenTicketInfo(ticket.Binding)
	if err != nil {
		return ConnectionBitwardenTicketPayload{}, err
	}
	plain, err := openBundlePayload(private, info, ticket.Ticket)
	defer Wipe(plain)
	if err != nil {
		return ConnectionBitwardenTicketPayload{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var payload ConnectionBitwardenTicketPayload
	if dec.Decode(&payload) != nil || dec.Decode(new(struct{})) != io.EOF || payload.validate(ticket.Binding, now) != nil {
		Wipe(payload.SavedSession)
		if payload.RDP != nil {
			Wipe(payload.RDP.Link)
		}
		return ConnectionBitwardenTicketPayload{}, ErrFormat
	}
	return payload, nil
}
