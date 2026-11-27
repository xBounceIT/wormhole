package sharedpg

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// parseSelectionProjection binds the response to the requested logical identity,
// including user and record kind. Parsing alone does not authenticate the record.
func parseSelectionProjection(rows [][][]byte, request AdmissionRequest, scope sharedcatalog.SelectionScope, epoch, sequence uint64) (*UnverifiedSelection, *UnverifiedNodeAuthor, error) {
	envelope, err := parseCatalogProjectionEnvelope(rows, request, scope.Subject, epoch, sequence)
	if err != nil {
		return nil, nil, err
	}
	record, err := parseSelectionRecord(rows[0][4], scope.Kind)
	if err != nil {
		return nil, nil, err
	}
	actual, _, err := sharedcatalog.SelectionIdentity(record)
	if err != nil || actual != scope {
		return nil, nil, ErrAdmissionResponse
	}
	return &UnverifiedSelection{Record: record, Boundary: envelope.Boundary, Seal: envelope.Seal}, envelope.Author, nil
}

func parseSelectionRecord(raw []byte, kind string) (sharedcatalog.SelectionRecord, error) {
	if len(raw) == 0 || len(raw) > 16384 || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	var record sharedcatalog.SelectionRecord
	switch kind {
	case "slot":
		var v sharedcatalog.SlotRecord
		if _, err := strictCatalogObject(raw, v); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		record = v
	case "slot-value":
		var v sharedcatalog.SlotValueRecord
		if _, err := strictCatalogObject(raw, v); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		record = v
	case "override":
		var v sharedcatalog.OverrideRecord
		if _, err := strictCatalogObject(raw, v); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		record = v
	case "tunnel":
		var v sharedcatalog.TunnelRecord
		fields, err := strictCatalogObject(raw, v)
		if err != nil {
			return nil, err
		}
		if _, err := strictCatalogObject(fields["metadata"], vaultstore.TunnelMetadata{}); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		record = v
	case "node-fields":
		var v sharedcatalog.NodeFieldsRecord
		fields, err := strictCatalogObject(raw, v)
		if err != nil {
			return nil, err
		}
		if err := validateCatalogFields(fields["fields"], 1); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		record = v
	default:
		return nil, ErrAdmissionResponse
	}
	if _, _, err := sharedcatalog.SelectionIdentity(record); err != nil {
		return nil, ErrAdmissionResponse
	}
	return record, nil
}
