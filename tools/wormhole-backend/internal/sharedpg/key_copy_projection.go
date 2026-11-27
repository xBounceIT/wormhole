package sharedpg

import (
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// UnverifiedKeyCopy remains untrusted until AdvanceKeyCopy succeeds and returned
// observations are durably committed. Expected key/holder come from the verified
// release graph. Org issuers carry no response-supplied public key.
type UnverifiedKeyCopy struct {
	Binding vault.KeyCopyBinding
	Copy    vault.SignedKeyCopy
	Author  *UnverifiedNodeAuthor
	group   *groupBoundaryCopy // Set only for a boundary root in an audited graph.
}

func parseKeyCopyProjection(rows [][][]byte, request AdmissionRequest, key, holder vault.KeyRef, epoch, sequence uint64) (*UnverifiedKeyCopy, error) {
	if request.WorkspaceID == uuid.Nil || key.ID == uuid.Nil || holder.ID == uuid.Nil || key == holder || key.Version == 0 || key.Version > math.MaxInt32 || holder.Version == 0 || holder.Version > math.MaxInt32 || epoch == 0 || epoch > math.MaxInt64 || sequence > math.MaxInt64 || len(rows) != 1 || (len(rows[0]) != 23 && len(rows[0]) != 24) {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != strconv.FormatUint(epoch, 10) || string(r[2]) != strconv.FormatUint(sequence, 10) || string(r[3]) != key.ID.String() || string(r[4]) != strconv.Itoa(int(key.Version)) || string(r[5]) != holder.ID.String() || string(r[6]) != strconv.Itoa(int(holder.Version)) || string(r[7]) != "2" {
		return nil, ErrAdmissionResponse
	}
	issuer, ok := treeID(r[10])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	version, ok := treeNumber(r[11], 1, math.MaxInt32)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	if len(r[8]) != 64 || len(r[9]) != 96 || len(r[12]) != 128 {
		return nil, ErrAdmissionResponse
	}
	enc, e1 := hex.DecodeString(string(r[8]))
	ciphertext, e2 := hex.DecodeString(string(r[9]))
	signature, e3 := hex.DecodeString(string(r[12]))
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, ErrAdmissionResponse
	}
	result := &UnverifiedKeyCopy{Binding: vault.KeyCopyBinding{WorkspaceID: request.WorkspaceID, Key: key, Holder: holder, Issuer: vault.KeyRef{ID: issuer, Version: uint32(version)}}, Copy: vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: enc, Ciphertext: ciphertext}, Signature: signature}}
	switch string(r[13]) {
	case "org-sign":
		for _, v := range r[14:] {
			if v != nil {
				return nil, ErrAdmissionResponse
			}
		}
	case "user-sign":
		authorRow := [][]byte{r[0], r[3], r[14], r[1], r[2], r[10], r[11], r[15], r[16], r[17], r[18], r[19], r[20], r[21], r[22]}
		if len(r) == 24 {
			authorRow = append(authorRow, r[23])
		}
		author, e := parseNodeAuthor([][][]byte{authorRow}, request, key.ID, epoch, sequence)
		if e != nil {
			return nil, e
		}
		result.Author = author
	default:
		return nil, ErrAdmissionResponse
	}
	return result, nil
}
