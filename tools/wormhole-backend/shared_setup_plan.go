package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxSharedSetupPlan = 512 * 1024

const (
	setupPrepared  = "prepared"
	setupExported  = "exported"
	setupSubmitted = "submitted"
)

type sharedSetupSummary struct {
	WorkspaceID string `json:"workspaceId"`
	RoleTag     string `json:"roleTag"`
	Hosting     string `json:"hosting"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Database    string `json:"database"`
	State       string `json:"state"`
}

// Protect the deployment coordinates and the factor-sealed TLS draft so a
// resumed attempt retains the original database and certificate authority.
type sharedSetupPlan struct {
	FormatVersion uint16                      `json:"formatVersion"`
	PathDigest    [32]byte                    `json:"pathDigest"`
	Summary       sharedSetupSummary          `json:"summary"`
	CAPEM         []byte                      `json:"caPem"`
	TLS           *sharedpg.WorkspaceTLSDraft `json:"tls,omitempty"`
	ServerKit     *sharedSetupServerKit       `json:"serverKit,omitempty"`
}

func sharedSetupPlanPath(db string) string { return db + ".shared-setup" }

func (p sharedSetupPlan) valid(path string) bool {
	s := p.Summary
	return p.FormatVersion == 1 && p.PathDigest == sha256.Sum256([]byte(path)) &&
		(s.Hosting == "self-hosted" || s.Hosting == "managed") &&
		(p.TLS == nil || (s.Hosting == "self-hosted" && len(p.TLS.ServerPEM) > 0 && bytes.Equal(p.CAPEM, p.TLS.CAPEM()))) &&
		(p.ServerKit == nil || (p.TLS != nil && p.ServerKit.valid(s.WorkspaceID))) &&
		(s.State == setupPrepared || s.State == setupExported || s.State == setupSubmitted) &&
		deploy.ValidateIdentity(s.RoleTag, s.WorkspaceID) == nil &&
		sharedpg.ValidateDeploymentTarget(sharedpg.Endpoint{Host: s.Host, Port: s.Port}, s.Database, p.CAPEM) == nil
}

func createSharedSetupPlan(path string, summary sharedSetupSummary, caPEM []byte) (sharedSetupPlan, error) {
	plan := newSharedSetupPlan(path, summary)
	plan.CAPEM = caPEM
	if !plan.valid(path) {
		return sharedSetupPlan{}, sharedpg.ErrConfiguration
	}
	return plan, nil
}

func newSharedSetupPlan(path string, summary sharedSetupSummary) sharedSetupPlan {
	var tag [10]byte
	// Public coordinates from independent randomness. A stale UI cannot choose
	// the identity or reuse an identity from a previous deployment.
	rand.Read(tag[:])
	summary.RoleTag = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tag[:]))
	summary.WorkspaceID = uuid.NewString()
	summary.State = setupPrepared
	return sharedSetupPlan{FormatVersion: 1, PathDigest: sha256.Sum256([]byte(path)), Summary: summary}
}

func readSharedSetupPlan(path string, protection sharedStartupProtection) (sharedSetupPlan, error) {
	sealed, err := readSharedTrustBytes(path, 2*maxSharedSetupPlan)
	if err != nil {
		return sharedSetupPlan{}, err
	}
	if len(sealed) == 0 || len(sealed) > 2*maxSharedSetupPlan || protection.unprotect == nil {
		return sharedSetupPlan{}, errSharedTrustStorage
	}
	raw, err := protection.unprotect(path, sealed)
	defer vault.Wipe(raw)
	var plan sharedSetupPlan
	if err != nil || len(raw) == 0 || len(raw) > maxSharedSetupPlan || json.Unmarshal(raw, &plan) != nil || !plan.valid(path) {
		return sharedSetupPlan{}, errSharedTrustStorage
	}
	canonical, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(canonical, raw) {
		return sharedSetupPlan{}, errSharedTrustStorage
	}
	return plan, nil
}

// The caller holds the exclusive setup lock. Re-publish a matching prepared
// plan before a later action so an uncertain write can never authorize DDL.
func writeSharedSetupPlan(path string, plan sharedSetupPlan, protection sharedStartupProtection) error {
	if protection.protect == nil {
		return errSharedTrustStorage
	}
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > maxSharedSetupPlan {
		return errSharedTrustStorage
	}
	defer vault.Wipe(raw)
	sealed, err := protection.protect(path, raw)
	if err != nil || len(sealed) == 0 || len(sealed) > 2*maxSharedSetupPlan {
		return errSharedTrustStorage
	}
	if err := writePrivateFileAtomic(path, sealed); err != nil {
		if privateFileDestinationWasReplaced(err) {
			return errSharedTrustCommitUncertain
		}
		return errSharedTrustStorage
	}
	return nil
}

func discardSharedSetupPlan(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustStorage
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return errSharedTrustCommitUncertain
	}
	return nil
}
