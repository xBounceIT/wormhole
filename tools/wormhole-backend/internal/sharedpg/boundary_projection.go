package sharedpg

import (
	"bytes"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// parseBoundaryProjection consumes a private projection inside an authorized
// release snapshot. Decode is structural only: AdvanceBoundary and durable
// publication must succeed before any root/copy/secret is used.
func parseBoundaryProjection(rows [][][]byte, request AdmissionRequest, id uuid.UUID, epoch, sequence uint64) (*vault.BoundaryManifest, error) {
	if request.WorkspaceID == uuid.Nil || id == uuid.Nil || epoch == 0 || epoch > math.MaxInt64 || sequence > math.MaxInt64 || len(rows) != 1 || len(rows[0]) != 9 {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != id.String() || string(r[2]) != strconv.FormatUint(epoch, 10) || string(r[3]) != strconv.FormatUint(sequence, 10) {
		return nil, ErrAdmissionResponse
	}
	revision, ok := treeNumber(r[4], 1, math.MaxInt64)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	if len(r[5]) == 0 || len(r[5]) > 2*vault.MaxBoundaryManifestBytes {
		return nil, ErrAdmissionResponse
	}
	body, err := hex.DecodeString(string(r[5]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	signer, ok := treeID(r[6])
	if !ok {
		return nil, ErrAdmissionResponse
	}
	version, ok := treeNumber(r[7], 1, math.MaxInt32)
	if !ok {
		return nil, ErrAdmissionResponse
	}
	if len(r[8]) != 128 {
		return nil, ErrAdmissionResponse
	}
	signature, err := hex.DecodeString(string(r[8]))
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	m, err := vault.DecodeBoundaryManifest(body)
	if err == vault.ErrNewerFormat {
		return nil, err
	}
	if err != nil || m.WorkspaceID != request.WorkspaceID || m.BoundaryID != id || m.Revision != revision || m.Signer.ID != signer || m.Signer.Version != uint32(version) || !bytes.Equal(m.Signature, signature) {
		return nil, ErrAdmissionResponse
	}
	return &m, nil
}
