package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

// SealInviteDisplay binds the separate code to the exact public document
// presented by this protected window, including its endpoints and trust bundle.
func SealInviteDisplay(publicKey []byte, request uuid.UUID, invite InviteContext, document string, code []byte) (SealedBundle, error) {
	if request == uuid.Nil || document == "" || len(code) != InviteCodeBytes {
		return SealedBundle{}, ErrFormat
	}
	if _, _, err := invite.binding(); err != nil {
		return SealedBundle{}, err
	}
	digest := sha256.Sum256([]byte(document))
	info := canonical("wormhole/v1/member-invitation-display", []byte(request.String()), []byte(invite.LoginName),
		[]byte(invite.WorkspaceID.String()), []byte(invite.InviteID.String()), hex.AppendEncode(nil, digest[:]))
	return sealBundlePayload(publicKey, info, code)
}

// Linux main owns the OS clipboard and supplies a fresh, main-only recipient.
func SealMemberInvitationClipboard(publicKey []byte, workspace, issuance, invite, copyID uuid.UUID, seconds int, value []byte) (SealedBundle, error) {
	if workspace == uuid.Nil || issuance == uuid.Nil || invite == uuid.Nil || copyID == uuid.Nil ||
		(seconds != 20 && seconds != 30) || len(value) != 2*InviteCodeBytes ||
		bytes.IndexFunc(value, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0 {
		return SealedBundle{}, ErrFormat
	}
	data := make([]byte, 2+len(value))
	defer Wipe(data)
	data[0], data[1] = 1, byte(seconds)
	copy(data[2:], value)
	return sealBundlePayload(publicKey, canonical("wormhole/v1/member-invitation-clipboard",
		[]byte(workspace.String()), []byte(issuance.String()), []byte(invite.String()), []byte(copyID.String())), data)
}
