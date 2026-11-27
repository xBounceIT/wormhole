package sharedpg

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const webSessionViewsAvailableSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.open_web_session_view(bytea,uuid)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.check_web_session_views(bytea,uuid[])') IS NOT NULL)::text`

const openWebSessionViewSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,generation::text
FROM wormhole_api_v1.open_web_session_view(pg_catalog.decode($1,'hex'),$2::uuid)`

const checkWebSessionViewsSQL = `SELECT workspace_id::text,user_id::text,device_id::text,generations::text
FROM wormhole_api_v1.check_web_session_views(pg_catalog.decode($1,'hex'),$2::uuid[])`

const setWebSessionCheckpointSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,generation::text,accepted::text
FROM wormhole_api_v1.set_web_session_checkpoint(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid,$4::boolean)`

const maxWebSessionViewReply = 4096

func (s *Session) WebSessionViewsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, webSessionViewsAvailableSQL)
}

func (s *Session) WebSessionCheckpointsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.set_web_session_checkpoint(bytea,uuid,uuid,boolean)') IS NOT NULL)::text`)
}

// SetWebSessionCheckpoint reports presence for this device and generation.
// The workspace receives an authority ID and a boolean, with no archive data.
func (s *Session) SetWebSessionCheckpoint(ctx context.Context, node, generation uuid.UUID, present bool) (bool, error) {
	if ctx == nil || node == uuid.Nil || generation == uuid.Nil {
		return false, ErrConfiguration
	}
	accepted := false
	err := s.queryConnection(ctx, node, setWebSessionCheckpointSQL, [][]byte{[]byte(generation.String()), []byte(strconv.FormatBool(present))}, 256, 6, func(rows [][][]byte, request AdmissionRequest) error {
		var err error
		accepted, err = parseWebSessionCheckpoint(rows, request, node, generation)
		return err
	})
	return err == nil && accepted, err
}

func parseWebSessionCheckpoint(rows [][][]byte, request AdmissionRequest, node, generation uuid.UUID) (bool, error) {
	if !validWebSessionViewResponse(rows, request, 6) || string(rows[0][3]) != node.String() || string(rows[0][4]) != generation.String() {
		return false, ErrAdmissionResponse
	}
	switch string(rows[0][5]) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, ErrAdmissionResponse
	}
}

// OpenWebSessionView is called only after native plan verification. A nil
// generation is an expected denial, with no authority created.
func (s *Session) OpenWebSessionView(ctx context.Context, node uuid.UUID) (uuid.UUID, error) {
	if ctx == nil || node == uuid.Nil {
		return uuid.Nil, ErrConfiguration
	}
	var generation uuid.UUID
	err := s.queryConnection(ctx, node, openWebSessionViewSQL, nil, 256, 5, func(rows [][][]byte, request AdmissionRequest) error {
		if !validWebSessionViewResponse(rows, request, 5) || string(rows[0][3]) != node.String() {
			return ErrAdmissionResponse
		}
		if rows[0][4] != nil {
			id, valid := treeID(rows[0][4])
			if !valid {
				return ErrAdmissionResponse
			}
			generation = id
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return generation, nil
}

// CheckWebSessionViews returns the current generation of each still-visible
// tracked node. An omitted node has no retained authority. Lookup never
// registers it again after a revoke and regrant.
func (s *Session) CheckWebSessionViews(ctx context.Context, nodes []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	if ctx == nil || len(nodes) == 0 || len(nodes) > MaxTreePage {
		return nil, ErrConfiguration
	}
	requested := make(map[uuid.UUID]struct{}, len(nodes))
	ids := make([]string, 0, len(nodes))
	for _, id := range nodes {
		if _, duplicate := requested[id]; id == uuid.Nil || duplicate {
			return nil, ErrConfiguration
		}
		requested[id] = struct{}{}
		ids = append(ids, id.String())
	}
	var generations map[uuid.UUID]uuid.UUID
	argument := []byte("{" + strings.Join(ids, ",") + "}")
	err := s.queryAuthenticated(ctx, checkWebSessionViewsSQL, [][]byte{argument}, maxWebSessionViewReply, 4, func(rows [][][]byte, request AdmissionRequest) error {
		if !validWebSessionViewResponse(rows, request, 4) {
			return ErrAdmissionResponse
		}
		var e error
		generations, e = parseWebSessionViewGenerations(rows[0][3], requested)
		return e
	})
	if err != nil {
		return nil, err
	}
	return generations, nil
}

func validWebSessionViewResponse(rows [][][]byte, request AdmissionRequest, columns int) bool {
	return len(rows) == 1 && len(rows[0]) == columns &&
		string(rows[0][0]) == request.WorkspaceID.String() &&
		string(rows[0][1]) == request.UserID.String() && string(rows[0][2]) == request.DeviceID.String()
}

func parseWebSessionViewGenerations(payload []byte, requested map[uuid.UUID]struct{}) (map[uuid.UUID]uuid.UUID, error) {
	var entries [][]string
	if len(payload) > maxWebSessionViewReply || json.Unmarshal(payload, &entries) != nil ||
		entries == nil || len(entries) > len(requested) {
		return nil, ErrAdmissionResponse
	}
	generations := make(map[uuid.UUID]uuid.UUID, len(entries))
	after := ""
	for _, entry := range entries {
		if len(entry) != 2 || entry[0] <= after {
			return nil, ErrAdmissionResponse
		}
		node, validNode := treeID([]byte(entry[0]))
		generation, validGeneration := treeID([]byte(entry[1]))
		if _, expected := requested[node]; !expected || !validNode || !validGeneration {
			return nil, ErrAdmissionResponse
		}
		generations[node] = generation
		after = entry[0]
	}
	return generations, nil
}
