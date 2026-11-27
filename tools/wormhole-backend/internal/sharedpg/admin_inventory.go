package sharedpg

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const adminInventoryLimit = 25
const adminInventoryTime = "2006-01-02T15:04:05.000000Z"
const adminInventoryMaxBytes = 768 * 1024
const adminInventorySupportedSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamp with time zone)') IS NOT NULL)::text`
const adminInventorySQL = `SELECT workspace_id::text,user_id::text,device_id::text,payload::text
 FROM wormhole_api_v1.admin_inventory(pg_catalog.decode($1,'hex'),$2,$3::uuid,$4::timestamptz)`
const unencryptedClientsSupportedSQL = `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.unencrypted_clients(bytea,uuid)') IS NOT NULL)::text`
const unencryptedClientsSQL = `SELECT workspace_id::text,user_id::text,device_id::text,payload::text
 FROM wormhole_api_v1.unencrypted_clients(pg_catalog.decode($1,'hex'),$2::uuid)`

var adminInventoryEvent = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var adminInventoryAppVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$`)

type AdminInventoryCursor struct {
	ID uuid.UUID `json:"id"`
	At string    `json:"at,omitempty"`
}

type AdminInventoryRequest struct {
	Kind string                `json:"kind"`
	Next *AdminInventoryCursor `json:"next,omitempty"`
}

type AdminInventoryEntry struct {
	AdminInventoryCursor
	Login      string `json:"login"`
	Name       string `json:"name,omitempty"`
	Role       string `json:"role,omitempty"`
	Status     string `json:"status,omitempty"`
	DeviceID   string `json:"deviceId,omitempty"`
	AppVersion string `json:"appVersion,omitempty"`
	Transport  string `json:"transport,omitempty"`
	ActorID    string `json:"actorId,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
	Action     string `json:"action,omitempty"`
	Source     string `json:"source,omitempty"`
}

type AdminInventoryPage struct {
	Kind    string                `json:"kind"`
	Entries []AdminInventoryEntry `json:"entries"`
	Next    *AdminInventoryCursor `json:"next,omitempty"`
}

func (r AdminInventoryRequest) Valid() bool {
	switch r.Kind {
	case "accounts", "devices", "my-devices", "unencrypted-clients", "sessions", "audit":
	default:
		return false
	}
	if r.Next == nil {
		return true
	}
	if r.Kind == "sessions" || r.Kind == "audit" {
		return r.Next.ID != uuid.Nil && validAdminTime(r.Next.At)
	}
	return r.Next.ID != uuid.Nil && r.Next.At == ""
}

func validAdminTime(value string) bool {
	parsed, err := time.Parse(adminInventoryTime, value)
	return err == nil && parsed.Year() > 0 && parsed.Format(adminInventoryTime) == value
}

func (s *Session) AdminInventorySupported(ctx context.Context, kind string) (bool, error) {
	switch kind {
	case "my-devices":
		return s.WorkspaceAccessSupported(ctx)
	case "unencrypted-clients":
		return s.serverCapability(ctx, unencryptedClientsSupportedSQL)
	}
	return s.serverCapability(ctx, adminInventorySupportedSQL)
}

// AdminInventory reads server policy and audit observations. SQL reauthorizes
// every page. A nil page is an expected denial and leaves the session usable.
func (s *Session) AdminInventory(ctx context.Context, request AdminInventoryRequest) (*AdminInventoryPage, error) {
	if ctx == nil || !request.Valid() {
		return nil, ErrConfiguration
	}
	var after, before []byte
	if cursor := request.Next; cursor != nil {
		after = []byte(cursor.ID.String())
		if cursor.At != "" {
			before = []byte(cursor.At)
		}
	}
	query := adminInventorySQL
	args := [][]byte{[]byte(request.Kind), after, before}
	if request.Kind == "unencrypted-clients" {
		query = unencryptedClientsSQL
		args = [][]byte{after}
	}
	var page *AdminInventoryPage
	err := s.queryAuthenticated(ctx, query, args, adminInventoryMaxBytes, 4, func(rows [][][]byte, admission AdmissionRequest) error {
		if len(rows) != 1 || len(rows[0]) != 4 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		if string(row[0]) != admission.WorkspaceID.String() || string(row[1]) != admission.UserID.String() ||
			string(row[2]) != admission.DeviceID.String() {
			return ErrAdmissionResponse
		}
		if row[3] == nil {
			return nil
		}
		var err error
		page, err = parseAdminInventory(row[3], request)
		return err
	})
	return page, err
}

func parseAdminInventory(raw []byte, request AdminInventoryRequest) (*AdminInventoryPage, error) {
	columns := map[string]int{"accounts": 5, "devices": 5, "my-devices": 5, "unencrypted-clients": 5, "sessions": 6, "audit": 8}[request.Kind]
	if columns == 0 || len(raw) > adminInventoryMaxBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	rows, err := snapshotRows(raw, adminInventoryLimit+1, columns)
	if err != nil {
		return nil, err
	}
	page := &AdminInventoryPage{Kind: request.Kind, Entries: make([]AdminInventoryEntry, 0, min(len(rows), adminInventoryLimit))}
	before := request.Next
	for _, row := range rows {
		entry, ok := parseAdminInventoryEntry(request.Kind, row)
		if !ok {
			return nil, ErrAdmissionResponse
		}
		if before != nil {
			order := bytes.Compare(entry.ID[:], before.ID[:])
			switch request.Kind {
			case "sessions", "audit":
				if entry.At > before.At || (entry.At == before.At && order >= 0) {
					return nil, ErrAdmissionResponse
				}
			default:
				if order <= 0 {
					return nil, ErrAdmissionResponse
				}
			}
		}
		if len(page.Entries) == adminInventoryLimit {
			cursor := page.Entries[adminInventoryLimit-1].AdminInventoryCursor
			if request.Kind != "sessions" && request.Kind != "audit" {
				cursor.At = ""
			}
			page.Next = &cursor
		} else {
			page.Entries = append(page.Entries, entry)
		}
		before = &entry.AdminInventoryCursor
	}
	return page, nil
}

func parseAdminInventoryEntry(kind string, row [][]byte) (entry AdminInventoryEntry, ok bool) {
	id, ok := treeID(row[0])
	if !ok {
		return entry, false
	}
	entry.ID, entry.Login = id, string(row[1])
	switch kind {
	case "accounts":
		entry.Name = string(row[2])
		entry.Role, ok = adminInventoryChoice(row[3], "administrator", "member")
		if !ok {
			return entry, false
		}
		entry.Status, ok = adminInventoryChoice(row[4], "disabled", "enabled")
	case "devices", "my-devices", "unencrypted-clients":
		entry.Name, entry.Status, entry.At = string(row[2]), string(row[3]), string(row[4])
		ok = (entry.Status == "active" || entry.Status == "pending" || entry.Status == "revoked") && validAdminTime(entry.At)
	case "sessions":
		if _, ok = treeID(row[2]); !ok {
			return entry, false
		}
		entry.DeviceID, entry.AppVersion, entry.At = string(row[2]), string(row[3]), string(row[4])
		entry.Transport, ok = adminInventoryChoice(row[5], "tls", "unencrypted")
		ok = ok && len(entry.AppVersion) <= 64 && adminInventoryAppVersion.MatchString(entry.AppVersion) && validAdminTime(entry.At)
	case "audit":
		_, actorOK := treeID(row[1])
		_, sessionOK := treeID(row[2])
		entry.ActorID, entry.SessionID, entry.Login = string(row[1]), string(row[2]), string(row[3])
		entry.Action, entry.Status, entry.Source, entry.At = string(row[4]), string(row[5]), string(row[6]), string(row[7])
		ok = actorOK && sessionOK && adminInventoryEvent.MatchString(entry.Action) && adminInventoryEvent.MatchString(entry.Status) &&
			(entry.Source == "ui" || entry.Source == "mcp") && validAdminTime(entry.At)
	}
	return entry, ok && (kind == "audit" || entry.Login != "") && len(entry.Login) <= 256 && len(entry.Name) <= 4096 &&
		strings.IndexFunc(entry.Login, unicode.IsControl) < 0 && strings.IndexFunc(entry.Name, unicode.IsControl) < 0
}

func adminInventoryChoice(raw []byte, yes, no string) (string, bool) {
	switch string(raw) {
	case "true":
		return yes, true
	case "false":
		return no, true
	default:
		return "", false
	}
}
