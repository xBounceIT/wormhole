package eap

import (
	"errors"

	"layeh.com/radius/rfc3079"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// MSKLen is the EAP Master Session Key length (RFC 3748 §7.10).
const MSKLen = 64

// DeriveMSK builds the 64-byte EAP-MSCHAPv2 Master Session Key from the
// password-hash-hash and the NT-Response captured during the exchange.
//
// rfc3079 only exposes the 16-byte MPPE master keys, so the 64-byte expansion
// is ours:
//
//	MasterKey        = GetMasterKey(PasswordHashHash, NT-Response)        [RFC 3079 §3.4]
//	MasterReceiveKey = GetAsymmetricStartKey(MasterKey, 16, isSend=false) [magic2]
//	MasterSendKey    = GetAsymmetricStartKey(MasterKey, 16, isSend=true)  [magic3]
//	MSK              = MasterReceiveKey | MasterSendKey | 32 zero bytes
//
// Both the EAP peer and the authenticator derive the identical 64 bytes: the
// MasterReceiveKey (magic2) always precedes the MasterSendKey (magic3),
// independent of role. This matches wpa_supplicant's eap_mschapv2_getKey (peer)
// and hostapd's server getKey, which order their send/receive calls
// oppositely but land on the same magic2|magic3 concatenation. The result is
// validated against RFC 3079 §3.5.3 (MasterSendKey) and end-to-end against a
// live IKEv2-EAP-MSCHAPv2 gateway.
func DeriveMSK(passwordHashHash, ntResponse []byte) ([]byte, error) {
	if len(passwordHashHash) == 0 || len(ntResponse) == 0 {
		return nil, errors.New("eap: MSK derivation needs password-hash-hash and NT-Response")
	}
	// Derive inside secretmem.Do: the MSK buffer (and the MPPE master-key
	// intermediates) is then runtime-tracked and erased once dropped after
	// the AUTH exchange (see internal/secretmem).
	var msk []byte
	var derr error
	secretmem.Do(func() {
		master := rfc3079.GetMasterKey(passwordHashHash, ntResponse)

		recvKey, err := rfc3079.GetAsymmetricStartKey(master, rfc3079.KeyLength128Bit, false)
		if err != nil {
			derr = err
			return
		}
		sendKey, err := rfc3079.GetAsymmetricStartKey(master, rfc3079.KeyLength128Bit, true)
		if err != nil {
			derr = err
			return
		}

		msk = make([]byte, MSKLen)
		copy(msk[0:16], recvKey)
		copy(msk[16:32], sendKey)
		// msk[32:64] stays zero.
	})
	if derr != nil {
		return nil, derr
	}
	return msk, nil
}
