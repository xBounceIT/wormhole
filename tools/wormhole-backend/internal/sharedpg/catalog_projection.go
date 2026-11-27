package sharedpg

import (
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type catalogProjectionEnvelope struct {
	Boundary uuid.UUID
	Seal     vault.RecordSeal
	Author   *UnverifiedNodeAuthor
}

// parseCatalogProjectionEnvelope binds the common signed-record snapshot header
// and current author material. Callers must validate the kind-specific body.
func parseCatalogProjectionEnvelope(rows [][][]byte, request AdmissionRequest, id uuid.UUID, epoch, sequence uint64) (*catalogProjectionEnvelope, error) {
	if id == uuid.Nil || request.WorkspaceID == uuid.Nil || epoch == 0 || epoch > math.MaxInt64 || sequence > math.MaxInt64 || len(rows) != 1 || (len(rows[0]) != 23 && len(rows[0]) != 24) {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != id.String() || string(r[2]) != strconv.FormatUint(epoch, 10) || string(r[3]) != strconv.FormatUint(sequence, 10) {
		return nil, ErrAdmissionResponse
	}
	boundary, ok := treeID(r[5])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	revision, ok := treeNumber(r[6], 1, math.MaxInt64)
	if !ok || string(r[7]) != "2" {
		return nil, ErrAdmissionResponse
	}
	signer, ok := treeID(r[8])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	version, ok := treeNumber(r[9], 1, math.MaxInt32)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	var capability *string
	if r[10] != nil {
		v, ok := treeID(r[10])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		s := v.String()
		capability = &s
	}
	if len(r[11]) != 128 {
		return nil, ErrAdmissionResponse
	}
	signature, err := hex.DecodeString(string(r[11]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	// Author responses share the same opaque entity-ID/snapshot header layout.
	authorRow := [][]byte{r[0], r[1], r[12], r[2], r[3], r[13], r[14], r[15], r[16], r[17], r[18], r[19], r[20], r[21], r[22]}
	if len(r) == 24 {
		authorRow = append(authorRow, r[23])
	}
	author, err := parseNodeAuthor([][][]byte{authorRow}, request, id, epoch, sequence)
	if err != nil || author.Key.ID != signer || author.Key.Version != uint32(version) {
		return nil, ErrAdmissionResponse
	}
	return &catalogProjectionEnvelope{Boundary: boundary, Seal: vault.RecordSeal{FormatVersion: vault.FormatVersion, SignerKeyID: signer.String(), SignerKeyVersion: uint32(version), CapabilityID: capability, Revision: revision, Signature: signature}, Author: author}, nil
}
