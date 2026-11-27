package vault

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

// ResolutionRecord contains every credential-routing field. Optional fields
// retain null versus false/empty distinctions used by inheritance. Chain order
// is leaf to root; records are signed individually, never by an unordered map.
type ResolutionRecord struct {
	WorkspaceID            string  `json:"workspaceId"`
	NodeID                 string  `json:"nodeId"`
	ParentID               string  `json:"parentId"`
	BoundaryID             string  `json:"boundaryId"`
	Revision               uint64  `json:"revision"`
	Host                   *string `json:"host"`
	Port                   *uint16 `json:"port"`
	Protocol               *string `json:"protocol"`
	CredentialMode         *uint8  `json:"credentialMode"`
	CredentialID           *string `json:"credentialId"`
	CredentialSlotID       *string `json:"credentialSlotId"`
	UseInlinePassword      *bool   `json:"useInlinePassword"`
	Username               *string `json:"username"`
	RDPDomain              *string `json:"rdpDomain"`
	RDPGatewayHost         *string `json:"rdpGatewayHost"`
	RDPGatewayCredentialID *string `json:"rdpGatewayCredentialId"`
	RDPGatewayUsageMethod  *uint8  `json:"rdpGatewayUsageMethod"`
	RDPGatewayBypassLocal  *bool   `json:"rdpGatewayBypassLocal"`
	RDPGatewayUseSameCreds *bool   `json:"rdpGatewayUseSameCreds"`
	RDPUseExternalClient   *bool   `json:"rdpUseExternalClient"`
	HTTPPath               *string `json:"httpPath"`
	HTTPIgnoreCertErrors   *bool   `json:"httpIgnoreCertErrors"`
	TunnelEnabled          *bool   `json:"tunnelEnabled"`
	TunnelConfigID         *string `json:"tunnelConfigId"`
	SSHHostKeyFingerprint  *string `json:"sshHostKeyFingerprint"`
}

type RecordSeal struct {
	FormatVersion    uint16  `json:"formatVersion"`
	SignerKeyID      string  `json:"signerKeyId"`
	SignerKeyVersion uint32  `json:"signerKeyVersion"`
	CapabilityID     *string `json:"capabilityId"`
	Revision         uint64  `json:"revision"`
	Signature        []byte  `json:"signature"`
}

func (r ResolutionRecord) canonical() ([]byte, error) {
	if r.WorkspaceID == "" || r.NodeID == "" || r.BoundaryID == "" || r.Revision == 0 || (r.CredentialMode != nil && *r.CredentialMode > 3) {
		return nil, ErrFormat
	}
	for _, s := range []string{r.WorkspaceID, r.NodeID, r.ParentID, r.BoundaryID} {
		if !validText(s, MaxContextBytes, true) {
			return nil, ErrFormat
		}
	}
	for _, s := range []*string{r.Host, r.Protocol, r.CredentialID, r.CredentialSlotID, r.Username, r.RDPDomain, r.RDPGatewayHost, r.RDPGatewayCredentialID, r.HTTPPath, r.TunnelConfigID, r.SSHHostKeyFingerprint} {
		if s != nil && !validText(*s, 8192, true) {
			return nil, ErrFormat
		}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/resolution-record", body), nil
}

func recordSigningBytes(record ResolutionRecord, seal RecordSeal) ([]byte, error) {
	if seal.FormatVersion > FormatVersion {
		return nil, ErrNewerFormat
	}
	if seal.FormatVersion != FormatVersion || seal.Revision != record.Revision || !validText(seal.SignerKeyID, MaxContextBytes, false) || seal.SignerKeyVersion == 0 || (seal.CapabilityID != nil && !validText(*seal.CapabilityID, MaxContextBytes, false)) {
		return nil, ErrFormat
	}
	body, err := record.canonical()
	if err != nil {
		return nil, err
	}
	seal.Signature = nil
	header, err := json.Marshal(seal)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/record-seal", header, body), nil
}

func SignRecord(record ResolutionRecord, signerID string, signerVersion uint32, capabilityID *string, key ed25519.PrivateKey) (RecordSeal, error) {
	seal := RecordSeal{FormatVersion, signerID, signerVersion, capabilityID, record.Revision, nil}
	if len(key) != ed25519.PrivateKeySize {
		return RecordSeal{}, ErrFormat
	}
	body, err := recordSigningBytes(record, seal)
	if err != nil {
		return RecordSeal{}, err
	}
	seal.Signature = ed25519.Sign(key, body)
	return seal, nil
}

func VerifyRecord(record ResolutionRecord, seal RecordSeal, key ed25519.PublicKey, minimumRevision uint64) error {
	if len(key) != ed25519.PublicKeySize {
		return ErrFormat
	}
	body, err := recordSigningBytes(record, seal)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, seal.Signature) {
		return ErrAuthentication
	}
	if record.Revision < minimumRevision {
		return ErrRollback
	}
	return nil
}

func SealLocalRecord(record ResolutionRecord, vaultKey []byte) ([]byte, error) {
	body, err := record.canonical()
	if err != nil {
		return nil, err
	}
	key, err := DeriveKey(vaultKey, nil, PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil), nil
}

func VerifyLocalRecord(record ResolutionRecord, signature, vaultKey []byte, minimumRevision uint64) error {
	actual, err := SealLocalRecord(record, vaultKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(actual, signature) {
		return ErrAuthentication
	}
	if record.Revision < minimumRevision {
		return ErrRollback
	}
	return nil
}
