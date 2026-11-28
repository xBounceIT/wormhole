package sharedpg

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
)

const accountSuspensionInventorySignature = "wormhole_api_v1.account_suspension_inventory(bytea,uuid,text,bigint,bigint,bytea,bytea)"
const accountSuspensionAvailableSQL = "SELECT (pg_catalog.to_regprocedure('" + accountSuspensionInventorySignature + "') IS NOT NULL)::text"
const accountSuspensionInventorySQL = `SELECT status,payload::text FROM wormhole_api_v1.account_suspension_inventory(
	pg_catalog.decode($1,'hex'),$2::uuid,$3,$4::bigint,$5::bigint,pg_catalog.decode($6,'hex'),pg_catalog.decode($7,'hex'))`
const accountSuspensionGroupsSignature = "wormhole_api_v1.account_suspension_groups(bytea,uuid,bigint,bigint,bytea,bytea)"
const accountSuspensionGroupsSQL = `SELECT status,payload::text FROM wormhole_api_v1.account_suspension_groups(
	pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,pg_catalog.decode($5,'hex'),pg_catalog.decode($6,'hex'))`
const accountSuspensionWebSignature = "wormhole_api_v1.account_suspension_web_sessions(bytea,uuid,bigint,bigint,bytea,bytea)"
const accountSuspensionWebSQL = `SELECT status,payload::text FROM wormhole_api_v1.account_suspension_web_sessions(
	pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,pg_catalog.decode($5,'hex'),pg_catalog.decode($6,'hex'))`
const accountSuspensionPageBytes = 192 * 1024

type AccountSuspensionRequest struct {
	AccountID string `json:"accountId"`
	Kind      string `json:"kind"`
	Revision  string `json:"revision,omitempty"`
	After     string `json:"after,omitempty"`
}

func (r AccountSuspensionRequest) Valid() bool {
	if _, ok := treeID([]byte(r.AccountID)); !ok || (r.Kind != "roots" && r.Kind != "passwords" && r.Kind != "groups" && r.Kind != "web-sessions") {
		return false
	}
	if r.Revision == "" && r.After == "" {
		return true
	}
	_, revisionOK := treeNumber([]byte(r.Revision), 1, math.MaxInt64)
	_, afterOK := treeNumber([]byte(r.After), 1, math.MaxInt64)
	return revisionOK && afterOK
}

type AccountSuspensionEntry struct {
	Position   string `json:"position"`
	BoundaryID string `json:"boundaryId,omitempty"`
	Kind       string `json:"kind,omitempty"`
	ID         string `json:"id,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Direct     *bool  `json:"direct,omitempty"`
	GroupCount string `json:"groupCount,omitempty"`
	Status     string `json:"status,omitempty"`
	Name       string `json:"name,omitempty"`
	Personal   bool   `json:"personal,omitempty"`
	JobID      string `json:"jobId,omitempty"`
}

type AccountSuspensionPage struct {
	AccountID string                   `json:"accountId"`
	Kind      string                   `json:"kind"`
	Revision  string                   `json:"revision"`
	Entries   []AccountSuspensionEntry `json:"entries"`
	After     string                   `json:"after,omitempty"`
}

type AccountSuspensionReply struct {
	Status string                 `json:"status"`
	Page   *AccountSuspensionPage `json:"page,omitempty"`
}

func (s *Session) AccountSuspensionSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, accountSuspensionAvailableSQL)
}

func (s *Session) AccountSuspensionInventory(ctx context.Context, trust TrustState, request AccountSuspensionRequest) (result AccountSuspensionReply, err error) {
	if !request.Valid() {
		return result, ErrConfiguration
	}
	query := accountSuspensionInventorySQL
	args := [][]byte{[]byte(request.AccountID), []byte(request.Kind)}
	var capability string
	switch request.Kind {
	case "groups":
		query, capability = accountSuspensionGroupsSQL, accountSuspensionGroupsSignature
	case "web-sessions":
		query, capability = accountSuspensionWebSQL, accountSuspensionWebSignature
	}
	if capability != "" {
		supported, err := s.serverCapability(ctx, "SELECT (pg_catalog.to_regprocedure('"+capability+"') IS NOT NULL)::text")
		if err != nil {
			return result, err
		}
		if !supported {
			return AccountSuspensionReply{Status: "unsupported"}, nil
		}
		args = args[:1]
	}
	args = append(args, adminArgument(request.Revision), adminArgument(request.After))
	err = s.queryAdministration(ctx, trust, query, args, accountSuspensionPageBytes, 2, func(row [][]byte) error {
		result, err = parseAccountSuspensionReply(row, request)
		if err == nil && result.Page != nil && request.Kind == "roots" {
			personal := personalImportBoundaryID(trust.WorkspaceID, uuid.MustParse(request.AccountID)).String()
			for i := range result.Page.Entries {
				result.Page.Entries[i].Personal = result.Page.Entries[i].BoundaryID == personal
			}
		}
		return err
	})
	return result, err
}

func parseAccountSuspensionReply(row [][]byte, request AccountSuspensionRequest) (AccountSuspensionReply, error) {
	status := string(row[0])
	switch status {
	case "busy", "stale", "unavailable", "not-recorded":
		if row[1] == nil {
			return AccountSuspensionReply{Status: status}, nil
		}
	case "ready":
		if page, err := parseAccountSuspensionPage(row[1], request); err == nil {
			return AccountSuspensionReply{Status: status, Page: page}, nil
		}
	}
	return AccountSuspensionReply{}, ErrAdmissionResponse
}

func parseAccountSuspensionPage(raw []byte, request AccountSuspensionRequest) (*AccountSuspensionPage, error) {
	wire := struct {
		AccountID string          `json:"accountId"`
		Kind      string          `json:"kind"`
		Revision  string          `json:"revision"`
		Entries   json.RawMessage `json:"entries"`
	}{}
	if len(raw) > accountSuspensionPageBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, wire); err != nil || json.Unmarshal(raw, &wire) != nil ||
		wire.AccountID != request.AccountID || wire.Kind != request.Kind || (request.Revision != "" && wire.Revision != request.Revision) {
		return nil, ErrAdmissionResponse
	}
	if _, ok := treeNumber([]byte(wire.Revision), 1, math.MaxInt64); !ok {
		return nil, ErrAdmissionResponse
	}
	columns := 5
	switch request.Kind {
	case "roots":
		columns = 8
	case "groups":
		columns = 6
	}
	rows, err := snapshotRows(wire.Entries, adminInventoryLimit+1, columns)
	if err != nil {
		return nil, err
	}
	page := &AccountSuspensionPage{AccountID: wire.AccountID, Kind: wire.Kind, Revision: wire.Revision,
		Entries: make([]AccountSuspensionEntry, 0, min(len(rows), adminInventoryLimit))}
	before, _ := strconv.ParseUint(request.After, 10, 64)
	for _, row := range rows {
		position, ok := treeNumber(row[0], 1, math.MaxInt64)
		if !ok || position != before+1 {
			return nil, ErrAdmissionResponse
		}
		entry, err := parseAccountSuspensionEntry(row, request.Kind)
		if err != nil {
			return nil, err
		}
		if len(page.Entries) == adminInventoryLimit {
			page.After = page.Entries[adminInventoryLimit-1].Position
			break
		}
		page.Entries = append(page.Entries, entry)
		before = position
	}
	return page, nil
}

func parseAccountSuspensionEntry(row [][]byte, kind string) (AccountSuspensionEntry, error) {
	entry := AccountSuspensionEntry{Position: string(row[0])}
	if row[1] == nil {
		for _, part := range row[2:] {
			if part != nil {
				return entry, ErrAdmissionResponse
			}
		}
		return entry, nil
	}
	if _, ok := treeID(row[1]); !ok {
		return entry, ErrAdmissionResponse
	}
	if kind == "groups" {
		return parseSuspensionGroup(row, entry)
	}
	if _, ok := treeID(row[3]); !ok {
		return entry, ErrAdmissionResponse
	}
	entry.BoundaryID, entry.ID = string(row[1]), string(row[3])
	if kind == "web-sessions" {
		if string(row[2]) != "web-target" || !adminGroupText(string(row[4]), 4096) {
			return entry, ErrAdmissionResponse
		}
		entry.Kind, entry.Name = "web-target", string(row[4])
		return entry, nil
	}
	if kind == "passwords" {
		switch entry.Kind = string(row[2]); entry.Kind {
		case "credential", "node", "tunnel", "slot-value":
			if row[4] != nil && (len(row[4]) == 0 || adminGroupText(string(row[4]), 4096)) {
				entry.Name = string(row[4])
				return entry, nil
			}
		}
		return entry, ErrAdmissionResponse
	}
	status := string(row[7])
	_, versionOK := treeNumber(row[4], 1, math.MaxInt32)
	groups, groupsOK := treeNumber(row[6], 0, math.MaxInt32)
	source, directOK := adminInventoryChoice(row[5], "direct", "group")
	if !versionOK || !groupsOK || !directOK || (source == "group" && groups == 0) ||
		(status != "active" && status != "rotating" && status != "retired" && status != "pending") {
		return entry, ErrAdmissionResponse
	}
	switch string(row[2]) {
	case "1":
		entry.Kind = "view"
	case "2":
		entry.Kind = "secret"
	default:
		return entry, ErrAdmissionResponse
	}
	direct := source == "direct"
	entry.Revision, entry.Direct, entry.GroupCount, entry.Status = string(row[4]), &direct, string(row[6]), status
	return entry, nil
}

func parseSuspensionGroup(row [][]byte, entry AccountSuspensionEntry) (AccountSuspensionEntry, error) {
	status := string(row[4])
	switch status {
	case "needs-removal", "waiting", "queued", "resolved":
	default:
		return entry, ErrAdmissionResponse
	}
	_, revisionOK := treeNumber(row[3], 1, math.MaxInt64)
	_, validJob := treeID(row[5])
	if !revisionOK || !adminGroupText(string(row[2]), 1024) ||
		(status == "queued" && !validJob) || (status != "queued" && row[5] != nil) {
		return entry, ErrAdmissionResponse
	}
	entry.Kind, entry.ID, entry.Name, entry.Revision, entry.Status, entry.JobID =
		"group", string(row[1]), string(row[2]), string(row[3]), status, string(row[5])
	return entry, nil
}
