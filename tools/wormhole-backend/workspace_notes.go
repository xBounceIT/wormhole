package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"
)

// Read notes separately so workspace/startup responses cannot grow with their total size.
func loadWorkspaceNodeNotes(databasePath string, request workspaceNodeRequest) (map[string]string, error) {
	id, err := normalizeWorkspaceNodeID(request.NodeID)
	if err != nil {
		return nil, err
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return nil, err
	}
	if database == nil {
		return nil, errors.New("workspace connection was not found")
	}
	defer database.Close()
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return nil, err
	}
	var notes sql.NullString
	if err := database.QueryRow("SELECT "+workspaceColumnExpression(columns, "Notes")+" FROM Nodes WHERE lower(Id) = ? AND Kind = ?", id, workspaceNodeConnection).Scan(&notes); err != nil {
		return nil, errors.New("could not read workspace connection notes")
	}
	if err := validateWorkspaceNotes(&notes.String); err != nil {
		return nil, err
	}
	return map[string]string{"notes": notes.String}, nil
}

// encoding/json replaces lone surrogate escapes with U+FFFD. Validate the raw
// escapes too, so importing or writing notes cannot silently change their text.
func parseWorkspaceNotesJSON(raw json.RawMessage) (*string, error) {
	var notes *string
	if err := json.Unmarshal(raw, &notes); err != nil || !utf8.Valid(raw) {
		return nil, errors.New("workspace connection notes are invalid")
	}
	if err := validateWorkspaceNotes(notes); err != nil {
		return nil, err
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		// Syntax and bounds are already checked by json.Unmarshal above.
		unit, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if unit >= 0xDC00 && unit <= 0xDFFF {
			return nil, errors.New("workspace connection notes are invalid")
		}
		if unit < 0xD800 || unit > 0xDBFF {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return nil, errors.New("workspace connection notes are invalid")
		}
		low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if low < 0xDC00 || low > 0xDFFF {
			return nil, errors.New("workspace connection notes are invalid")
		}
		i += 6
	}
	return notes, nil
}

func (request *workspaceNodeWriteRequest) UnmarshalJSON(raw []byte) error {
	type plainRequest workspaceNodeWriteRequest
	decoded := struct {
		*plainRequest
		Notes json.RawMessage `json:"notes"`
	}{plainRequest: new(plainRequest)}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	if len(decoded.Notes) > 0 {
		notes, err := parseWorkspaceNotesJSON(decoded.Notes)
		if err != nil {
			return err
		}
		decoded.plainRequest.Notes = notes
	}
	*request = workspaceNodeWriteRequest(*decoded.plainRequest)
	return nil
}
