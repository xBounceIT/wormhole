package sharedpg

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSuspensionReceiptPinsAuthorityAndOrder(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(private)
	pin := vault.UserKeyTrust{WorkspaceID: uuid.New(), UserID: uuid.New(), Signer: vault.KeyRef{ID: uuid.New(), Version: 1}, Organisation: public}
	target := uuid.New()
	actor := uuid.New()
	receipt := suspensionReceipt{pin.WorkspaceID, 7, actor, target, 12, pin.Signer}
	message, err := receipt.message()
	if err != nil {
		t.Fatal(err)
	}
	row := [][]byte{[]byte(actor.String()), []byte(target.String()), []byte("12"), hex.AppendEncode(nil, ed25519.Sign(private, message))}
	type page = [][][]byte
	if accounts, err := verifySuspensionReceipts(page{row}, pin, 7, uuid.Nil); err != nil ||
		!slices.Equal(accounts, []SuspendedAccount{{target, 12}}) {
		t.Fatal(accounts, err)
	}
	for _, change := range []string{"workspace", "epoch", "actor", "target", "revision", "key", "key-version", "signature", "missing", "short-row", "cursor", "repeated", "self", "self-suspension", "zero", "encoding"} {
		t.Run(change, func(t *testing.T) {
			rows := page{slices.Clone(row)}
			current, epoch, after := pin, int64(7), uuid.Nil
			switch change {
			case "workspace":
				current.WorkspaceID = uuid.New()
			case "epoch":
				epoch++
			case "actor":
				rows[0][0] = []byte(uuid.NewString())
			case "target":
				rows[0][1] = []byte(uuid.NewString())
			case "revision":
				rows[0][2] = []byte("13")
			case "key":
				current.Organisation = nil
			case "key-version":
				current.Signer.Version++
			case "signature":
				rows[0][3] = hex.AppendEncode(nil, make([]byte, ed25519.SignatureSize))
			case "missing":
				rows[0][3] = nil
			case "short-row":
				rows[0] = rows[0][:3]
			case "cursor":
				after = target
			case "repeated":
				rows = append(rows, row)
			case "self":
				current.UserID = target
			case "self-suspension":
				rows[0][0] = rows[0][1]
			case "zero":
				rows[0][2] = []byte("0")
			case "encoding":
				rows[0][3] = []byte("zz")
			}
			if accounts, err := verifySuspensionReceipts(rows, current, epoch, after); err == nil || accounts != nil {
				t.Fatal("accepted modified suspension receipt", accounts, err)
			}
		})
	}
	if _, err := (suspensionReceipt{}).message(); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
}
