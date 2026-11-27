package vault

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
)

// BundleBinding is supplied independently by the child bound to the relay.
// SessionID and epoch prevent an old unlock/session's ciphertext from being
// accepted by a new protocol session. Recipients also consume each request once.
type BundleBinding struct {
	WorkspaceID       string `json:"workspaceId"`
	SessionID         string `json:"sessionId"`
	RequestID         string `json:"requestId"`
	NodeID            string `json:"nodeId"`
	Protocol          string `json:"protocol"`
	Host              string `json:"host"`
	Port              uint16 `json:"port"`
	TunnelConfigID    string `json:"tunnelConfigId"`
	UseExternalClient bool   `json:"useExternalClient"`
	Epoch             uint64 `json:"epoch"`
}

type SealedBundle struct {
	FormatVersion uint16 `json:"formatVersion"`
	SuiteID       uint16 `json:"suiteId"`
	Enc           []byte `json:"enc"`
	Ciphertext    []byte `json:"ciphertext"`
}

func (b BundleBinding) info() ([]byte, error) {
	fields := []string{b.WorkspaceID, b.SessionID, b.RequestID, b.NodeID, b.Protocol, b.Host}
	var values [][]byte
	for _, field := range fields {
		if !validText(field, MaxContextBytes, false) {
			return nil, ErrFormat
		}
		values = append(values, []byte(field))
	}
	if b.Epoch == 0 || !validText(b.TunnelConfigID, MaxContextBytes, true) {
		return nil, ErrFormat
	}
	external := byte(0)
	if b.UseExternalClient {
		external = 1
	}
	values = append(values, binary.BigEndian.AppendUint16(nil, b.Port), []byte(b.TunnelConfigID), []byte{external}, binary.BigEndian.AppendUint64(nil, b.Epoch))
	return canonical("wormhole/v1/protocol-bundle", values...), nil
}

func SealBundle(publicKey []byte, binding BundleBinding, plaintext []byte) (SealedBundle, error) {
	if len(plaintext) > MaxSecretBytes {
		return SealedBundle{}, ErrFormat
	}
	info, err := binding.info()
	if err != nil {
		return SealedBundle{}, err
	}
	return sealBundlePayload(publicKey, info, plaintext)
}

func OpenBundle(privateKey []byte, binding BundleBinding, bundle SealedBundle) ([]byte, error) {
	if err := validateSealedBundle(bundle); err != nil {
		return nil, err
	}
	info, err := binding.info()
	if err != nil {
		return nil, err
	}
	return openBundlePayload(privateKey, info, bundle)
}

func validateSealedBundle(bundle SealedBundle) error {
	if bundle.FormatVersion > FormatVersion {
		return ErrNewerFormat
	}
	if bundle.FormatVersion != FormatVersion || bundle.SuiteID != SuiteX25519HKDFSHA256AES256GCM || len(bundle.Enc) != 32 || len(bundle.Ciphertext) < 16 || len(bundle.Ciphertext) > MaxSecretBytes+16 {
		return ErrFormat
	}
	return nil
}

func openBundlePayload(privateKey, info []byte, bundle SealedBundle) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, ErrFormat
	}
	key, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, ErrFormat
	}
	recipient, err := hpke.NewRecipient(bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, ErrAuthentication
	}
	plaintext, err := recipient.Open(nil, bundle.Ciphertext)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func sealBundlePayload(publicKey, info, plaintext []byte) (SealedBundle, error) {
	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return SealedBundle{}, ErrFormat
	}
	key, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return SealedBundle{}, ErrFormat
	}
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return SealedBundle{}, ErrAuthentication
	}
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		return SealedBundle{}, ErrAuthentication
	}
	return SealedBundle{FormatVersion, SuiteX25519HKDFSHA256AES256GCM, enc, ciphertext}, nil
}
