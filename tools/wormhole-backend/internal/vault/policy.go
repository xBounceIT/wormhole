package vault

import (
	"crypto/ed25519"
	"encoding/json"
)

type Profile string

const (
	Default  Profile = "default"
	Standard Profile = "standard"
	Hardened Profile = "hardened"
	Paranoid Profile = "paranoid"
)

// AllowsDirectRoute applies to a connection whose authenticated plan has no VPN
// and to a request to bypass an already configured VPN.
func (p Profile) AllowsDirectRoute() bool {
	return p == Default || p == Standard
}

func profileRank(profile Profile) int {
	switch profile {
	case Default:
		return 0
	case Standard:
		return 1
	case Hardened:
		return 2
	case Paranoid:
		return 3
	default:
		return -1
	}
}

// An absent optional OS/user floor is represented by Default by the caller.
// Missing or unrecognized authenticated policy is never silently downgraded.
func EffectiveProfile(osFloor, workspace, user Profile) Profile {
	result := Default
	for _, p := range []Profile{osFloor, workspace, user} {
		if profileRank(p) < 0 {
			return Paranoid
		}
		if profileRank(p) > profileRank(result) {
			result = p
		}
	}
	return result
}

type Policy struct {
	FormatVersion  uint16    `json:"formatVersion"`
	WorkspaceID    string    `json:"workspaceId"`
	Sequence       uint64    `json:"sequence"`
	Profile        Profile   `json:"profile"`
	KDF            KDFPreset `json:"kdf"`
	LowKDFApproved bool      `json:"lowKdfApproved"`
	ASKRequired    bool      `json:"askRequired"`
	OrgEscrow      bool      `json:"orgEscrow"`
	MinAPI         uint32    `json:"minApi"`
	MaxAPI         uint32    `json:"maxApi"`
	// A positive count describes a direct PostgreSQL deployment. Zero selects
	// polling for poolers or unknown topology. Older policies omit the field.
	DirectConnectionDevices *uint32 `json:"directConnectionDevices,omitempty"`
}

type SignedPolicy struct {
	Policy           Policy `json:"policy"`
	SignerKeyID      string `json:"signerKeyId"`
	SignerKeyVersion uint32 `json:"signerKeyVersion"`
	Signature        []byte `json:"signature"`
}

func (p Policy) Validate() error {
	if p.FormatVersion > FormatVersion {
		return ErrNewerFormat
	}
	if p.FormatVersion != FormatVersion || !validText(p.WorkspaceID, MaxContextBytes, false) || p.Sequence == 0 || profileRank(p.Profile) < 0 || p.MinAPI == 0 || p.MaxAPI < p.MinAPI {
		return ErrFormat
	}
	params, err := Parameters(p.KDF)
	if err != nil {
		return err
	}
	if p.KDF == KDFLow && (p.Profile != Default || !p.LowKDFApproved) {
		return ErrPolicy
	}
	if p.Profile == Hardened && params.MemoryKiB < 512*1024 {
		return ErrPolicy
	}
	if p.Profile == Paranoid && (p.KDF != KDFV3 || !p.ASKRequired) {
		return ErrPolicy
	}
	if !p.OrgEscrow && p.Profile != Paranoid {
		return ErrPolicy
	}
	return nil
}

func (p SignedPolicy) signingBytes() ([]byte, error) {
	if err := p.Policy.Validate(); err != nil {
		return nil, err
	}
	if !validText(p.SignerKeyID, MaxContextBytes, false) || p.SignerKeyVersion == 0 {
		return nil, ErrFormat
	}
	// Explicit structs with stable field order, no maps or floating point values.
	p.Signature = nil
	body, err := json.Marshal(p)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/signed-profile", body), nil
}

func SignPolicy(policy Policy, signerID string, signerVersion uint32, privateKey ed25519.PrivateKey) (SignedPolicy, error) {
	result := SignedPolicy{Policy: policy, SignerKeyID: signerID, SignerKeyVersion: signerVersion}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedPolicy{}, ErrFormat
	}
	body, err := result.signingBytes()
	if err != nil {
		return SignedPolicy{}, err
	}
	result.Signature = ed25519.Sign(privateKey, body)
	return result, nil
}

// The trusted key and signer identity come from the pinned organisation trust
// root. Never accept a key supplied alongside the signed profile itself.
func VerifyPolicy(signed SignedPolicy, workspaceID, signerID string, signerVersion uint32, trustedKey ed25519.PublicKey, minimumSequence uint64) error {
	if signed.Policy.WorkspaceID != workspaceID || signed.SignerKeyID != signerID || signed.SignerKeyVersion != signerVersion || len(trustedKey) != ed25519.PublicKeySize {
		return ErrAuthentication
	}
	body, err := signed.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(trustedKey, body, signed.Signature) {
		return ErrAuthentication
	}
	if signed.Policy.Sequence < minimumSequence {
		return ErrRollback
	}
	return nil
}
