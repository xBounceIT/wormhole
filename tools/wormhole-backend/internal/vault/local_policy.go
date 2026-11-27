package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"math"
)

const MaxLocalPolicyBytes = 16 * 1024

// LocalPolicy authenticates both the workspace policy and the owner's additional
// floor. It belongs inside SQLite; its sequence floor belongs in the slot file.
// File/root binding prevents transplanting policy between copies or key epochs.
type LocalPolicy struct {
	Policy         Policy  `json:"policy"`
	FileID         string  `json:"fileId"`
	RootKeyID      string  `json:"rootKeyId"`
	RootKeyVersion uint32  `json:"rootKeyVersion"`
	UserProfile    Profile `json:"userProfile"`
	Authentication []byte  `json:"authentication"`
}

func (p LocalPolicy) validate() error {
	if err := p.Policy.Validate(); err != nil {
		return err
	}
	if !canonicalID(p.Policy.WorkspaceID) || !canonicalID(p.FileID) || !canonicalID(p.RootKeyID) || p.RootKeyVersion == 0 || p.Policy.Sequence > math.MaxInt64 || profileRank(p.UserProfile) < 0 {
		return ErrFormat
	}
	// A stricter personal choice must not retain the workspace's weaker KDF or
	// ASK requirements. The native controller must also enforce the optional OS floor.
	effective := p.Policy
	effective.Profile = EffectiveProfile(Default, p.Policy.Profile, p.UserProfile)
	return effective.Validate()
}

func localPolicyMAC(key []byte, p LocalPolicy) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrFormat
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	subkey, err := DeriveKey(key, []byte(p.Policy.WorkspaceID), PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer Wipe(subkey)
	p.Authentication = nil
	body, err := json.Marshal(p)
	if err != nil {
		return nil, ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write(canonical("wormhole/v1/local-profile", body))
	return mac.Sum(nil), nil
}

func EncodeLocalPolicy(key []byte, p LocalPolicy) ([]byte, error) {
	mac, err := localPolicyMAC(key, p)
	if err != nil {
		return nil, err
	}
	p.Authentication = mac
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxLocalPolicyBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

// Only canonical stored documents are accepted. This rejects unknown, missing,
// duplicate/case-folded fields and rounded numbers before authentication.
func DecodeLocalPolicy(raw []byte) (LocalPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxLocalPolicyBytes {
		return LocalPolicy{}, ErrFormat
	}
	var p LocalPolicy
	if json.Unmarshal(raw, &p) != nil {
		return LocalPolicy{}, ErrFormat
	}
	if err := p.validate(); err != nil {
		return LocalPolicy{}, err
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(raw, canonical) || len(p.Authentication) != sha256.Size {
		return LocalPolicy{}, ErrFormat
	}
	return p, nil
}

func VerifyLocalPolicy(key []byte, p LocalPolicy, workspaceID, fileID, rootID string, rootVersion uint32, minimumSequence uint64) error {
	if err := p.validate(); err != nil {
		return err
	}
	if p.Policy.WorkspaceID != workspaceID || p.FileID != fileID || p.RootKeyID != rootID || p.RootKeyVersion != rootVersion {
		return ErrAuthentication
	}
	mac, err := localPolicyMAC(key, p)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, p.Authentication) {
		return ErrAuthentication
	}
	if p.Policy.Sequence < minimumSequence {
		return ErrRollback
	}
	return nil
}
