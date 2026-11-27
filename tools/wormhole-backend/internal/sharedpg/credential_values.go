package sharedpg

import (
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxCredentialCipherBytes = 8 * 1024 * 1024

// UnverifiedSharedValue contains ciphertext only. Its binding derives from the
// selected record/field manifest plus the returned DEK coordinate. Authenticate
// the profile, copy graph/issuers and envelope context before decrypting.
type UnverifiedSharedValue struct {
	Binding  vault.SharedValueBinding
	Envelope vault.Envelope
}

func parseCredentialValues(rows [][][]byte, request AdmissionRequest, profile sharedcatalog.CredentialRecord, epoch, sequence uint64) ([]UnverifiedSharedValue, error) {
	content := vaultstore.Credential{CredentialMetadata: profile.Metadata, RowVersion: 1, Deleted: profile.Deleted, Fields: profile.Fields}
	if request.WorkspaceID == uuid.Nil || epoch == 0 || epoch > math.MaxInt64 || sequence > math.MaxInt64 || profile.Deleted || content.ValidateContent() != nil {
		return nil, ErrAdmissionResponse
	}
	return parseManifestValues(rows, request, "credential", uuid.MustParse(profile.Metadata.ID), profile.Fields, epoch, sequence)
}

// Owner identity and versions come from a validated signed manifest, not from
// the value row or envelope. Authentication and durable trust precede opening.
func parseManifestValues(rows [][][]byte, request AdmissionRequest, ownerKind string, ownerID uuid.UUID, fields []vaultstore.CredentialField, epoch, sequence uint64) ([]UnverifiedSharedValue, error) {
	expected := []vaultstore.CredentialField{}
	for _, f := range fields {
		if f.Present {
			expected = append(expected, f)
		}
	}
	if len(rows) != len(expected) {
		return nil, ErrAdmissionResponse
	}
	result := make([]UnverifiedSharedValue, 0, len(expected))
	size := 0
	for i, row := range rows {
		if len(row) != 9 || string(row[0]) != request.WorkspaceID.String() || string(row[1]) != ownerID.String() || string(row[2]) != strconv.FormatUint(epoch, 10) || string(row[3]) != strconv.FormatUint(sequence, 10) || string(row[4]) != expected[i].Field {
			return nil, ErrAdmissionResponse
		}
		version, ok := treeNumber(row[5], 1, math.MaxInt64)
		if !ok || version != expected[i].Version {
			return nil, ErrAdmissionResponse
		}
		dek, ok := treeID(row[6])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		keyVersion, ok := treeNumber(row[7], 1, math.MaxInt32)
		if !ok {
			return nil, ErrAdmissionResponse
		}
		if len(row[8]) == 0 || len(row[8]) > 2*vault.MaxSharedEnvelopeBytes || len(row[8])%2 != 0 || len(row[8])/2 > MaxCredentialCipherBytes-size {
			return nil, ErrAdmissionResponse
		}
		size += len(row[8]) / 2
		raw, err := hex.DecodeString(string(row[8]))
		if err != nil {
			return nil, ErrAdmissionResponse
		}
		envelope, err := vault.DecodeSharedEnvelope(raw)
		if err == vault.ErrNewerFormat {
			return nil, err
		}
		if err != nil || envelope.KeyID != dek.String() || envelope.KeyVersion != uint32(keyVersion) {
			return nil, ErrAdmissionResponse
		}
		result = append(result, UnverifiedSharedValue{Binding: vault.SharedValueBinding{WorkspaceID: request.WorkspaceID, OwnerKind: ownerKind, OwnerID: ownerID, Field: expected[i].Field, Version: version, DEK: vault.KeyRef{ID: dek, Version: uint32(keyVersion)}}, Envelope: envelope})
	}
	return result, nil
}
