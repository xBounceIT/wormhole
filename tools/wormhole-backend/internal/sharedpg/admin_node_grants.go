package sharedpg

import (
	"context"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
)

const nodeGrantsSupportedSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)') IS NOT NULL)::text`
const adminNodeGrantsSQL = `SELECT status,epoch::text,change_seq::text,payload::text, CASE WHEN status='ready' THEN ` + nodeEditingAPI + `::text END
 FROM wormhole_api_v1.manage_node_grants(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4,$5::uuid,$6::bigint,
 $7::bigint,$8::uuid,$9,$10::bigint,$11::integer,pg_catalog.decode($12,'hex'),pg_catalog.decode($13,'hex'))`

type AdminNodeGrantRequest struct {
	NodeID        string            `json:"nodeId"`
	NodeRevision  string            `json:"nodeRevision"`
	Kind          string            `json:"kind"`
	After         string            `json:"after,omitempty"`
	Epoch         string            `json:"epoch,omitempty"`
	ChangeSeq     string            `json:"changeSeq,omitempty"`
	SubjectID     string            `json:"subjectId,omitempty"`
	Login         string            `json:"login,omitempty"`
	GrantRevision string            `json:"grantRevision,omitempty"`
	Mask          *permissions.Mask `json:"mask,omitempty"`
}

type AdminNodeGrant struct {
	SubjectID string           `json:"subjectId"`
	Label     string           `json:"label"`
	Revision  string           `json:"revision"`
	Mask      permissions.Mask `json:"mask"`
}

type AdminNodeGrantPage struct {
	Epoch                  string           `json:"epoch"`
	ChangeSeq              string           `json:"changeSeq"`
	Grants                 []AdminNodeGrant `json:"grants"`
	After                  string           `json:"after,omitempty"`
	RedirectRequiresReveal bool             `json:"redirectRequiresReveal,omitempty"`
}

type AdminNodeGrantReply struct {
	Status string              `json:"status"`
	Page   *AdminNodeGrantPage `json:"page,omitempty"`
}

func (r AdminNodeGrantRequest) Valid() bool {
	_, nodeOK := treeID([]byte(r.NodeID))
	_, versionOK := treeNumber([]byte(r.NodeRevision), 1, math.MaxInt64)
	if !nodeOK || !versionOK || (r.Kind != "account" && r.Kind != "group") || (r.Epoch == "") != (r.ChangeSeq == "") {
		return false
	}
	if r.Epoch != "" {
		_, epochOK := treeNumber([]byte(r.Epoch), 1, math.MaxInt64)
		_, seqOK := treeNumber([]byte(r.ChangeSeq), 0, math.MaxInt64)
		if !epochOK || !seqOK {
			return false
		}
	}
	if r.Mask == nil {
		return r.SubjectID == "" && r.Login == "" && r.GrantRevision == "" &&
			(r.After == "") == (r.Epoch == "") && validAdminGroupCursor(r.After)
	}
	revision, ok := treeNumber([]byte(r.GrantRevision), 0, math.MaxInt64)
	if !ok || r.After != "" || r.Epoch == "" || *r.Mask > permissions.All || (revision == 0 && *r.Mask == 0) {
		return false
	}
	if r.Login != "" {
		return r.SubjectID == "" && r.Kind == "account" && revision == 0 && adminGroupText(r.Login, 256)
	}
	_, ok = treeID([]byte(r.SubjectID))
	return ok
}

func (s *Session) AdminNodeGrantsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, nodeGrantsSupportedSQL)
}

func (s *Session) AdminNodeGrants(ctx context.Context, trust TrustState, request AdminNodeGrantRequest) (result AdminNodeGrantReply, err error) {
	if !request.Valid() {
		return result, ErrConfiguration
	}
	var args [][]byte
	for _, value := range []string{request.NodeID, request.NodeRevision, request.Kind, request.After, request.Epoch, request.ChangeSeq,
		request.SubjectID, request.Login, request.GrantRevision} {
		args = append(args, adminArgument(value))
	}
	var mask []byte
	if request.Mask != nil {
		mask = strconv.AppendUint(nil, uint64(*request.Mask), 10)
	}
	args = append(args, mask)
	err = s.queryAdministration(ctx, trust, adminNodeGrantsSQL, args, adminGroupPageBytes, 5, func(row [][]byte) error {
		result, err = parseAdminNodeGrantReply(row, request)
		return err
	})
	if err != nil {
		return AdminNodeGrantReply{}, err
	}
	return result, nil
}

func parseAdminNodeGrantReply(row [][]byte, request AdminNodeGrantRequest) (AdminNodeGrantReply, error) {
	if len(row) != 5 {
		return AdminNodeGrantReply{}, ErrAdmissionResponse
	}
	status := string(row[0])
	if status == "ready" && request.Mask == nil {
		if string(row[4]) != "true" && string(row[4]) != "false" {
			return AdminNodeGrantReply{}, ErrAdmissionResponse
		}
		page, err := parseAdminNodeGrantPage(row[1:4], request)
		if err != nil {
			return AdminNodeGrantReply{}, err
		}
		page.RedirectRequiresReveal = string(row[4]) == "true"
		return AdminNodeGrantReply{Status: status, Page: page}, nil
	}
	if row[1] != nil || row[2] != nil || row[3] != nil || row[4] != nil {
		return AdminNodeGrantReply{}, ErrAdmissionResponse
	}
	switch status {
	case "busy", "unavailable", "stale":
		return AdminNodeGrantReply{Status: status}, nil
	case "changed", "unchanged", "subject-unavailable", "signed-grant", "cannot-delegate":
		if request.Mask != nil {
			return AdminNodeGrantReply{Status: status}, nil
		}
	}
	return AdminNodeGrantReply{}, ErrAdmissionResponse
}

func parseAdminNodeGrantPage(row [][]byte, request AdminNodeGrantRequest) (*AdminNodeGrantPage, error) {
	_, epochOK := treeNumber(row[0], 1, math.MaxInt64)
	_, sequenceOK := treeNumber(row[1], 0, math.MaxInt64)
	epoch, sequence := string(row[0]), string(row[1])
	raw := row[2]
	if !epochOK || !sequenceOK || (request.Epoch != "" && (epoch != request.Epoch || sequence != request.ChangeSeq)) ||
		len(raw) > adminGroupPageBytes || !utf8.Valid(raw) {
		return nil, ErrAdmissionResponse
	}
	rows, err := snapshotRows(raw, adminInventoryLimit+1, 4)
	if err != nil {
		return nil, err
	}
	page := &AdminNodeGrantPage{Epoch: epoch, ChangeSeq: sequence, Grants: make([]AdminNodeGrant, 0, min(len(rows), adminInventoryLimit))}
	after := request.After
	labelLimit := 256
	if request.Kind == "group" {
		labelLimit = 1024
	}
	for _, columns := range rows {
		id, label := string(columns[0]), string(columns[1])
		_, idOK := treeID(columns[0])
		mask, maskOK := treeNumber(columns[2], 1, uint64(permissions.All))
		_, revisionOK := treeNumber(columns[3], 1, math.MaxInt64)
		if !idOK || id <= after || !adminGroupText(label, labelLimit) || !maskOK || !revisionOK {
			return nil, ErrAdmissionResponse
		}
		after = id
		if len(page.Grants) == adminInventoryLimit {
			page.After = page.Grants[adminInventoryLimit-1].SubjectID
		} else {
			page.Grants = append(page.Grants, AdminNodeGrant{id, label, string(columns[3]), permissions.Mask(mask)})
		}
	}
	return page, nil
}
