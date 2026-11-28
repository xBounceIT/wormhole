package vault

import "github.com/google/uuid"

// SealAccountResetDisplay hands the separate code and ASK to the one-use
// recipient in the protected custodian window.
func SealAccountResetDisplay(publicKey []byte, workspace, request uuid.UUID, login string, factors []byte) (SealedBundle, error) {
	if workspace == uuid.Nil || request == uuid.Nil || len(factors) != InviteCodeBytes+32 {
		return SealedBundle{}, ErrFormat
	}
	if _, err := SharedSalt(workspace.String(), login); err != nil {
		return SealedBundle{}, err
	}
	info := canonical("wormhole/v1/account-reset-display", []byte(workspace.String()), []byte(request.String()), []byte(login))
	return sealBundlePayload(publicKey, info, factors)
}
