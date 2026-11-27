package sharedpg

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// parseCredentialProjection consumes the bounded projection embedded in a future
// authorized release response. Parsing does not authenticate any returned value.
func parseCredentialProjection(rows [][][]byte, request AdmissionRequest, id uuid.UUID, epoch, sequence uint64) (*UnverifiedCredential, *UnverifiedNodeAuthor, error) {
	envelope, err := parseCatalogProjectionEnvelope(rows, request, id, epoch, sequence)
	if err != nil {
		return nil, nil, err
	}
	record, err := parseCredentialRecord(rows[0][4], envelope.Seal.Revision)
	if err != nil || record.Metadata.ID != id.String() {
		return nil, nil, ErrAdmissionResponse
	}
	return &UnverifiedCredential{Record: record, Boundary: envelope.Boundary, Seal: envelope.Seal}, envelope.Author, nil
}

// strictCatalogObject rejects aliases, duplicates, absent fields and explicit
// nulls (except explicitly nullable fields) before the ordinary struct decoder
// can hide schema ambiguity.
func strictCatalogObject(raw []byte, template any, nullable ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrAdmissionResponse
	}
	expectedRaw, _ := json.Marshal(template)
	var expected map[string]json.RawMessage
	json.Unmarshal(expectedRaw, &expected)
	allowedNull := make(map[string]bool, len(nullable))
	for _, name := range nullable {
		allowedNull[name] = true
	}
	fields := make(map[string]json.RawMessage, len(expected))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrAdmissionResponse
		}
		if _, ok := expected[key]; !ok {
			return nil, ErrAdmissionResponse
		}
		if _, ok := fields[key]; ok {
			return nil, ErrAdmissionResponse
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !allowedNull[key]) {
			return nil, ErrAdmissionResponse
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || len(fields) != len(expected) {
		return nil, ErrAdmissionResponse
	}
	return fields, nil
}

func validateCatalogFields(raw json.RawMessage, limit int) error {
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > limit {
		return ErrAdmissionResponse
	}
	for _, entry := range entries {
		if _, err := strictCatalogObject(entry, vaultstore.CredentialField{}); err != nil {
			return err
		}
	}
	return nil
}

func parseCredentialRecord(raw []byte, revision uint64) (sharedcatalog.CredentialRecord, error) {
	var result sharedcatalog.CredentialRecord
	if len(raw) == 0 || len(raw) > 128*1024 || !utf8.Valid(raw) {
		return result, ErrAdmissionResponse
	}
	fields, err := strictCatalogObject(raw, result)
	if err != nil {
		return result, err
	}
	if _, err = strictCatalogObject(fields["metadata"], result.Metadata); err != nil {
		return result, err
	}
	if err := validateCatalogFields(fields["fields"], 4); err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result) != nil {
		return sharedcatalog.CredentialRecord{}, ErrAdmissionResponse
	}
	content := vaultstore.Credential{CredentialMetadata: result.Metadata, RowVersion: revision, Deleted: result.Deleted, Fields: result.Fields}
	if content.ValidateContent() != nil {
		return sharedcatalog.CredentialRecord{}, ErrAdmissionResponse
	}
	return result, nil
}
