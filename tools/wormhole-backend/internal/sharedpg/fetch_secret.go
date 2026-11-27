package sharedpg

import (
	"context"
	"math"
	"strconv"

	"github.com/google/uuid"
)

const fetchSecretSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.fetch_secret(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid)`

const fetchSecretPathSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.fetch_secret_path(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid,$4::text)`

// FetchSecret consumes a committed BeginUse ticket, returning only ciphertext
// and unverified public signing material. Never retry automatically: even a lost
// response may have spent its rollback-resistant ticket. The vault must verify
// and durably publish trust observations before any private-key operation.
func (s *Session) FetchSecret(ctx context.Context, intent UseIntent) (*UnverifiedCredentialRelease, error) {
	return s.fetchSecret(ctx, intent, false)
}

// FetchTunnelSecret accepts the web tunnel ticket. The owner still verifies
// the graph and opens it through WithTunnelValues after committing trust.
func (s *Session) FetchTunnelSecret(ctx context.Context, intent UseIntent) (*UnverifiedCredentialRelease, error) {
	return s.fetchSecret(ctx, intent, true)
}

func (s *Session) fetchSecret(ctx context.Context, intent UseIntent, tunnel bool) (*UnverifiedCredentialRelease, error) {
	if ctx == nil || intent.Node == uuid.Nil || intent.Ticket == uuid.Nil || intent.Epoch == 0 || intent.Epoch > math.MaxInt64 || intent.ChangeSeq > math.MaxInt64 || intent.ExpiresAt <= 0 {
		return nil, ErrConfiguration
	}
	statement := fetchSecretSQL
	args := [][]byte{[]byte(intent.Ticket.String())}
	if intent.Path != "" {
		if !credentialReleasePath(intent.Path) && !(tunnel && intent.Path == WebConnectionPlanPath) {
			return nil, ErrConfiguration
		}
		statement, args = fetchSecretPathSQL, append(args, []byte(intent.Path))
	}
	var result *UnverifiedCredentialRelease
	err := s.queryConnection(ctx, intent.Node, statement, args, MaxCredentialReleaseBytes, 8, func(rows [][][]byte, r AdmissionRequest) error {
		var e error
		result, e = parseSecretRelease(rows, r, intent)
		return e
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseSecretRelease(rows [][][]byte, request AdmissionRequest, intent UseIntent) (*UnverifiedCredentialRelease, error) {
	payload, err := secretReleasePayload(rows, request, intent)
	if err != nil {
		return nil, err
	}
	graph, err := parseCredentialRelease(payload, request, intent.Node, intent.Epoch, intent.ChangeSeq)
	if err != nil {
		return nil, err
	}
	if graph.metadata.records.Path != intent.Path {
		return nil, ErrAdmissionResponse
	}
	return graph, nil
}

func secretReleasePayload(rows [][][]byte, request AdmissionRequest, intent UseIntent) ([]byte, error) {
	if len(rows) != 1 || len(rows[0]) != 8 {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	if string(r[0]) != request.WorkspaceID.String() || string(r[1]) != request.UserID.String() || string(r[2]) != request.DeviceID.String() || string(r[3]) != intent.Node.String() || string(r[4]) != intent.Ticket.String() || string(r[5]) != strconv.FormatUint(intent.Epoch, 10) || string(r[6]) != strconv.FormatUint(intent.ChangeSeq, 10) {
		return nil, ErrAdmissionResponse
	}
	return r[7], nil
}
