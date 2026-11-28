package sharedpg

import (
	"context"
	"math"

	"github.com/google/uuid"
)

const workspaceAccessSignature = "wormhole_api_v1.workspace_access(bytea,text,uuid,bigint,bytea,bytea)"
const workspaceAccessAvailableSQL = "SELECT (pg_catalog.to_regprocedure('" + workspaceAccessSignature + "') IS NOT NULL)::text"
const workspaceAccessSQL = `SELECT status,payload::text FROM wormhole_api_v1.workspace_access(
	pg_catalog.decode($1,'hex'),$2,$3::uuid,$4::bigint,pg_catalog.decode($5,'hex'),pg_catalog.decode($6,'hex'))`
const workspaceAccessMaxBytes = 32 * 1024

type WorkspaceAccessRequest struct {
	Action   string `json:"action"`
	TargetID string `json:"targetId"`
	Revision string `json:"revision,omitempty"`
}

func (r WorkspaceAccessRequest) Valid() bool {
	switch r.Action {
	case "disable-account", "enable-account", "revoke-device":
	default:
		return false
	}
	if _, ok := treeID([]byte(r.TargetID)); !ok {
		return false
	}
	_, validRevision := treeNumber([]byte(r.Revision), 1, math.MaxInt64)
	return r.Revision == "" || validRevision
}

type WorkspaceAccessReview struct {
	WorkspaceAccessRequest
	Login         string `json:"login"`
	Name          string `json:"name"`
	CurrentDevice bool   `json:"currentDevice"`
}

type WorkspaceAccessReply struct {
	Status        string                 `json:"status"`
	Review        *WorkspaceAccessReview `json:"review,omitempty"`
	CurrentDevice bool                   `json:"currentDevice,omitempty"`
}

func (s *Session) WorkspaceAccessSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, workspaceAccessAvailableSQL)
}

func (s *Session) WorkspaceAccess(ctx context.Context, trust TrustState, request WorkspaceAccessRequest) (WorkspaceAccessReply, error) {
	var result WorkspaceAccessReply
	if !request.Valid() {
		return result, ErrConfiguration
	}
	args := [][]byte{[]byte(request.Action), []byte(request.TargetID), adminArgument(request.Revision)}
	err := s.queryAdministration(ctx, trust, workspaceAccessSQL, args, workspaceAccessMaxBytes, 2, func(row [][]byte) error {
		var err error
		result, err = parseWorkspaceAccessReply(row, request, trust.DeviceID)
		return err
	})
	return result, err
}

func parseWorkspaceAccessReply(row [][]byte, request WorkspaceAccessRequest, currentDevice uuid.UUID) (WorkspaceAccessReply, error) {
	status := string(row[0])
	thisDevice := request.Action == "revoke-device" && request.TargetID == currentDevice.String()
	if row[1] == nil {
		switch status {
		case "unavailable", "busy", "stale", "unchanged":
			return WorkspaceAccessReply{Status: status}, nil
		case "personal-recovery-required":
			if request.Action == "enable-account" {
				return WorkspaceAccessReply{Status: status}, nil
			}
		case "changed":
			if request.Revision != "" {
				return WorkspaceAccessReply{Status: status, CurrentDevice: thisDevice}, nil
			}
		}
	}
	if status != "review" || request.Revision != "" || len(row[1]) > workspaceAccessMaxBytes {
		return WorkspaceAccessReply{}, ErrAdmissionResponse
	}
	fields, err := snapshotOptionalRow(row[1], 6)
	if err != nil || len(fields) != 6 {
		return WorkspaceAccessReply{}, ErrAdmissionResponse
	}
	confirmed := WorkspaceAccessRequest{Action: string(fields[0]), TargetID: string(fields[1]), Revision: string(fields[2])}
	login, name := string(fields[3]), string(fields[4])
	reportedCurrent, ok := adminInventoryChoice(fields[5], "true", "false")
	if !confirmed.Valid() || confirmed.Revision == "" || confirmed.TargetID != request.TargetID ||
		confirmed.Action != request.Action || !adminGroupText(login, 256) ||
		fields[4] == nil || (name != "" && !adminGroupText(name, 4096)) ||
		!ok || (reportedCurrent == "true") != thisDevice {
		return WorkspaceAccessReply{}, ErrAdmissionResponse
	}
	return WorkspaceAccessReply{Status: status, Review: &WorkspaceAccessReview{
		WorkspaceAccessRequest: confirmed, Login: login, Name: name, CurrentDevice: thisDevice,
	}}, nil
}
