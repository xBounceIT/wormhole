package localvault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func (o *Owner) PrepareRDPBitwarden(ctx context.Context, q TunnelBundleRequest, route *vault.TunnelBundleBinding, endpoint string, recipient []byte, reviewed string) (BitwardenPreparation, error) {
	return o.prepareRDPBitwarden(ctx, q, route, endpoint, recipient, reviewed, nil)
}

type rdpManualOpening struct {
	binding vault.BundleBinding
	bundle  vault.SealedBundle
}

func (o *Owner) PrepareManualRDPBitwarden(ctx context.Context, q TunnelBundleRequest, expected vault.BundleBinding, inner vault.SealedBundle, recipient []byte, reviewed string) (BitwardenPreparation, error) {
	if q.CredentialOverride != "" || vault.ValidateRDPManualEnvelope(inner) != nil {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	return o.prepareRDPBitwarden(ctx, q, nil, "", recipient, reviewed, &rdpManualOpening{expected, inner})
}

func (o *Owner) prepareRDPBitwarden(ctx context.Context, q TunnelBundleRequest, route *vault.TunnelBundleBinding, endpoint string, recipient []byte, reviewed string, manual *rdpManualOpening) (BitwardenPreparation, error) {
	if ctx == nil || q.Validate() != nil || (route != nil && !vault.ValidRouteEndpoint(endpoint)) || (route == nil && endpoint != "") ||
		(len(recipient) == 0) != (reviewed == "") {
		return BitwardenPreparation{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, binding, settings, err := o.planRDPBundle(ctx, q.Plan(), route, manual != nil)
	if err != nil {
		return BitwardenPreparation{}, err
	}
	if manual != nil && binding != manual.binding {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	var lookup vault.RDPBitwardenLookup
	if manual == nil {
		lookup.PrimaryItemID, err = rdpBitwardenItem(r.Account.SourceKind, r.Credential)
		if err != nil {
			return BitwardenPreparation{}, err
		}
	}
	if r.Plan.GatewayMethod != 0 && !r.Plan.GatewaySameCredentials {
		lookup.GatewayItemID, err = rdpBitwardenItem(r.GatewayAccount.SourceKind, r.GatewayCredential)
		if err != nil {
			return BitwardenPreparation{}, err
		}
	}
	slots := lookup.Slots()
	if slots == 0 {
		if len(recipient) != 0 {
			return BitwardenPreparation{}, vault.ErrPolicy
		}
		return BitwardenPreparation{}, nil
	}
	revision := connectionResolutionRevision(r, q.Plan())
	if manual != nil {
		// Bind the probe to this document envelope as well as current gateway
		// metadata. The encapsulation and revision have fixed lengths.
		h := sha256.New()
		h.Write([]byte("wormhole/v1/rdp-manual-bitwarden-review"))
		h.Write([]byte(revision))
		h.Write(manual.bundle.Enc)
		h.Write(manual.bundle.Ciphertext)
		revision = hex.EncodeToString(h.Sum(nil))
	}
	if len(recipient) == 0 {
		return BitwardenPreparation{Required: true, Revision: revision}, nil
	}
	if reviewed != revision {
		return BitwardenPreparation{}, vault.ErrPolicy
	}
	var payload vault.RDPBundlePayload
	if manual != nil {
		payload, err = o.manualRDPBundlePayload(ctx, q.NodeID, r, settings, slots)
	} else {
		payload, err = o.rdpBundlePayload(ctx, q.NodeID, r, settings, slots)
	}
	defer func() { vault.Wipe(payload.Password); vault.Wipe(payload.GatewayPassword) }()
	if err != nil {
		return BitwardenPreparation{}, err
	}
	if slots&vault.RDPBitwardenGateway != 0 {
		// The account projection normally qualifies a saved gateway username.
		// Retain a domain-only prefix for the resolver's username fallback.
		domain := strings.TrimSpace(r.GatewayCredential.Domain)
		if domain != "" && payload.GatewayUsername == domain+"\\" {
			payload.GatewayUsername, payload.GatewayDomain = "", domain
		}
	}
	var link [32]byte
	if _, err = rand.Read(link[:]); err != nil {
		return BitwardenPreparation{}, err
	}
	defer vault.Wipe(link[:])
	lookup.Link = link[:]
	var frame []byte
	if manual != nil {
		frame, err = vault.EncodeManualRDPBitwardenBase(payload, manual.bundle, lookup.Link)
	} else {
		frame, err = vault.EncodeRDPBitwardenBase(payload, slots, lookup.Link)
	}
	if err != nil {
		return BitwardenPreparation{}, err
	}
	defer vault.Wipe(frame)
	var base vault.SealedBundle
	if route == nil {
		base, err = vault.SealBundle(q.PublicKey, binding, frame)
	} else {
		base, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, frame)
	}
	if err != nil {
		return BitwardenPreparation{}, err
	}
	prepared, err := o.prepareBitwardenTicket(ctx, binding, vault.ConnectionBitwardenTicketPayload{
		TargetPublicKey: q.PublicKey, RDP: &lookup, Route: route, Endpoint: endpoint,
	}, recipient, revision, reviewed)
	if err != nil {
		return BitwardenPreparation{}, err
	}
	prepared.RDPBase = &base
	return prepared, nil
}

func rdpBitwardenItem(source string, credential *vaultstore.Credential) (string, error) {
	if credential == nil || credential.Provider != "bitwarden" {
		return "", nil
	}
	if source != "saved" || credential.Kind != "password" || credential.BitwardenItemID == "" ||
		(credential.BitwardenFieldPath != "" && credential.BitwardenFieldPath != "login.password") {
		return "", vault.ErrPolicy
	}
	return credential.BitwardenItemID, nil
}
