package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const adminGroupsAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea)') IS NOT NULL)::text`
const adminGroupsSQL = `SELECT status,payload::text FROM wormhole_api_v1.admin_groups(
 pg_catalog.decode($1,'hex'),$2,$3::uuid,$4::bigint,$5,$6,$7::uuid,$8::uuid,
 pg_catalog.decode($9,'hex'),pg_catalog.decode($10,'hex'))`
const adminGroupPageBytes = 192 * 1024

type AdminGroupRequest struct {
	Action   string `json:"action"`
	GroupID  string `json:"groupId,omitempty"`
	Revision string `json:"revision,omitempty"`
	Name     string `json:"name,omitempty"`
	Login    string `json:"login,omitempty"`
	MemberID string `json:"memberId,omitempty"`
	After    string `json:"after,omitempty"`
}

type AdminGroupEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Revision string `json:"revision,omitempty"`
	Login    string `json:"login,omitempty"`
	Status   string `json:"status,omitempty"`
}

type AdminGroupPage struct {
	Entries []AdminGroupEntry `json:"entries"`
	After   string            `json:"after,omitempty"`
}

type AdminGroupReply struct {
	Status string          `json:"status"`
	Page   *AdminGroupPage `json:"page,omitempty"`
}

func adminGroupText(text string, max int) bool {
	return text != "" && len(text) <= max && utf8.ValidString(text) && strings.IndexFunc(text, unicode.IsControl) < 0
}

func (r AdminGroupRequest) Valid() bool {
	if r.Action == "list" {
		return r.GroupID == "" && r.Revision == "" && r.Name == "" && r.Login == "" && r.MemberID == "" && validAdminGroupCursor(r.After)
	}
	if _, ok := treeID([]byte(r.GroupID)); !ok {
		return false
	}
	if r.Action == "create" {
		if r.Revision != "" {
			return false
		}
	} else if _, ok := treeNumber([]byte(r.Revision), 1, math.MaxInt64); !ok {
		return false
	}
	if r.Action != "members" && r.After != "" {
		return false
	}
	if r.Action != "create" && r.Action != "rename" && r.Name != "" ||
		r.Action != "add-member" && r.Login != "" ||
		r.Action != "remove-member" && r.MemberID != "" {
		return false
	}
	switch r.Action {
	case "members":
		return validAdminGroupCursor(r.After)
	case "create", "rename":
		return adminGroupText(r.Name, 256) && strings.TrimSpace(r.Name) == r.Name
	case "add-member":
		return adminGroupText(r.Login, 256)
	case "remove-member":
		_, ok := treeID([]byte(r.MemberID))
		return ok
	case "delete":
		return true
	}
	return false
}

func validAdminGroupCursor(after string) bool {
	_, ok := treeID([]byte(after))
	return after == "" || ok
}

func (s *Session) AdminGroupsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, adminGroupsAvailableSQL)
}

// AdminGroups binds each read or edit to the signed policy and account state
// verified by the native owner before this capability-scoped transaction.
func (s *Session) AdminGroups(ctx context.Context, trust TrustState, request AdminGroupRequest) (result AdminGroupReply, err error) {
	if !request.Valid() {
		return result, ErrConfiguration
	}
	args := [][]byte{[]byte(request.Action)}
	for _, value := range []string{request.GroupID, request.Revision, request.Name, request.Login, request.MemberID, request.After} {
		args = append(args, adminArgument(value))
	}
	err = s.queryAdministration(ctx, trust, adminGroupsSQL, args, adminGroupPageBytes, 2, func(row [][]byte) error {
		result, err = parseAdminGroupReply(row, request)
		return err
	})
	return result, err
}

func adminArgument(value string) []byte {
	if value == "" {
		return nil
	}
	return []byte(value)
}

func (s *Session) queryAdministration(ctx context.Context, trust TrustState, statement string, args [][]byte, payloadLimit, columns int, decode func([][]byte) error) error {
	if ctx == nil || !trust.valid() || trust.Account == nil || !trust.Account.Active {
		return ErrConfiguration
	}
	signed, err := vault.EncodeUserKeyState(*trust.Account)
	if err != nil {
		return err
	}
	state := sha256.Sum256(signed)
	args = append(args, hex.AppendEncode(nil, trust.PolicyDigest), hex.AppendEncode(nil, state[:]))
	return s.queryAuthenticated(ctx, statement, args, payloadLimit, columns, func(rows [][][]byte, admission AdmissionRequest) error {
		if admission.WorkspaceID != trust.WorkspaceID || admission.UserID != trust.UserID || admission.DeviceID != trust.DeviceID ||
			len(rows) != 1 || len(rows[0]) != columns {
			return ErrAdmissionResponse
		}
		return decode(rows[0])
	})
}

func parseAdminGroupReply(row [][]byte, request AdminGroupRequest) (result AdminGroupReply, err error) {
	result.Status = string(row[0])
	reading := request.Action == "list" || request.Action == "members"
	if result.Status == "ready" && reading {
		result.Page, err = parseAdminGroupPage(row[1], request)
		return result, err
	}
	if row[1] != nil {
		return AdminGroupReply{}, ErrAdmissionResponse
	}
	switch result.Status {
	case "stale", "unavailable", "busy":
		return result, nil
	case "changed", "unchanged":
		if !reading {
			return result, nil
		}
	case "group-in-use":
		if request.Action == "delete" {
			return result, nil
		}
	case "key-change-required":
		if request.Action == "delete" || request.Action == "add-member" || request.Action == "remove-member" {
			return result, nil
		}
	case "account-unavailable":
		if request.Action == "add-member" {
			return result, nil
		}
	}
	return AdminGroupReply{}, ErrAdmissionResponse
}

func parseAdminGroupPage(raw []byte, request AdminGroupRequest) (*AdminGroupPage, error) {
	if len(raw) > adminGroupPageBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	rows, err := snapshotRows(raw, adminInventoryLimit+1, 3)
	if err != nil {
		return nil, err
	}
	page := &AdminGroupPage{Entries: make([]AdminGroupEntry, 0, min(len(rows), adminInventoryLimit))}
	after := request.After
	for _, row := range rows {
		_, idOK := treeID(row[0])
		id, name, value := string(row[0]), string(row[1]), string(row[2])
		if !idOK || id <= after {
			return nil, ErrAdmissionResponse
		}
		after = id
		entry := AdminGroupEntry{ID: id}
		if request.Action == "list" {
			_, revisionOK := treeNumber(row[2], 1, math.MaxInt64)
			if !adminGroupText(name, 1024) || !revisionOK {
				return nil, ErrAdmissionResponse
			}
			entry.Name, entry.Revision = name, value
		} else {
			status, ok := adminInventoryChoice(row[2], "disabled", "enabled")
			if !adminGroupText(name, 256) || !ok {
				return nil, ErrAdmissionResponse
			}
			entry.Login, entry.Status = name, status
		}
		if len(page.Entries) == adminInventoryLimit {
			page.After = page.Entries[adminInventoryLimit-1].ID
		} else {
			page.Entries = append(page.Entries, entry)
		}
	}
	return page, nil
}
