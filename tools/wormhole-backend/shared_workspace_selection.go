package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxSharedWorkspaceSelectionBytes = 4096

type sharedWorkspaceSelection struct {
	Version     uint16    `json:"version"`
	PathDigest  [32]byte  `json:"pathDigest"`
	WorkspaceID uuid.UUID `json:"workspaceId"`
	DeviceID    uuid.UUID `json:"deviceId"`
	VaultID     string    `json:"vaultId"`
}

func sharedWorkspaceSelectionPath(source string) string { return source + ".shared-selection" }

// The separate parent directory gives the two native owners separate keys,
// browser-state metadata, and workspace locks. No renderer supplies either path.
func localSharedWorkspaceDatabase(source string) string {
	return filepath.Join(source+".shared-workspace", "workspace.db")
}

func (s sharedWorkspaceSelection) valid(source string) bool {
	id, err := uuid.Parse(s.VaultID)
	return filepath.IsAbs(source) && filepath.Clean(source) == source && s.Version == 1 &&
		s.PathDigest == sha256.Sum256([]byte(source)) && s.WorkspaceID != uuid.Nil && s.DeviceID != uuid.Nil &&
		err == nil && id != uuid.Nil && id.String() == s.VaultID
}

func (s sharedWorkspaceSelection) matches(anchor sharedStartupAnchor) bool {
	return s.WorkspaceID == anchor.Binding.WorkspaceID && s.DeviceID == anchor.Binding.DeviceID && s.VaultID == anchor.VaultID
}

func readSharedWorkspaceSelection(source string, protection sharedStartupProtection) (*sharedWorkspaceSelection, error) {
	path := sharedWorkspaceSelectionPath(source)
	sealed, err := readSharedTrustBytes(path, maxSharedWorkspaceSelectionBytes)
	if errors.Is(err, errSharedTrustMissing) {
		return nil, nil
	}
	if err != nil || len(sealed) == 0 || len(sealed) > maxSharedWorkspaceSelectionBytes || protection.unprotect == nil {
		return nil, errSharedTrustStorage
	}
	raw, err := protection.unprotect(path, sealed)
	defer vault.Wipe(raw)
	var s sharedWorkspaceSelection
	if err != nil || len(raw) == 0 || len(raw) > maxSharedWorkspaceSelectionBytes || json.Unmarshal(raw, &s) != nil || !s.valid(source) {
		return nil, errSharedTrustStorage
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errSharedTrustStorage
	}
	return &s, nil
}

// Called only after the destination has completed ordinary admission and its
// confirmed startup anchor is durable. An exact retry can confirm a lost reply.
func publishSharedWorkspaceSelection(source string, anchor sharedStartupAnchor, protection sharedStartupProtection) error {
	s := sharedWorkspaceSelection{Version: 1, PathDigest: sha256.Sum256([]byte(source)), WorkspaceID: anchor.Binding.WorkspaceID, DeviceID: anchor.Binding.DeviceID, VaultID: anchor.VaultID}
	if !s.valid(source) || protection.protect == nil {
		return errSharedTrustStorage
	}
	if previous, err := readSharedWorkspaceSelection(source, protection); err != nil {
		return err
	} else if previous != nil {
		if *previous != s {
			return errSharedTrustConflict
		}
		return privateFileDirectorySync(filepath.Dir(source))
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return errSharedTrustStorage
	}
	path := sharedWorkspaceSelectionPath(source)
	sealed, err := protection.protect(path, raw)
	if err != nil || len(sealed) == 0 || len(sealed) > maxSharedWorkspaceSelectionBytes {
		return errSharedTrustStorage
	}
	if err := publishSharedSetupFile(path, sealed); err != nil {
		return errSharedTrustStorage
	}
	return nil
}

// A selected destination is resolved once per native process. Corruption,
// substitution, or a missing target never re-enables the former local source.
func resolveVaultWorkspace(source string, protection sharedStartupProtection) (string, *sharedWorkspaceSelection, error) {
	s, err := readSharedWorkspaceSelection(source, protection)
	if err != nil {
		return "", nil, err
	}
	if s == nil {
		return source, nil, nil
	}
	target := localSharedWorkspaceDatabase(source)
	if _, err := captureInitialJoinDirectory(filepath.Dir(target)); err != nil {
		return "", nil, err
	}
	if _, err := captureInitialJoinDirectory(sharedWorkspaceDirectory(target)); err != nil {
		return "", nil, err
	}
	anchor, err := readSharedStartupAnchor(sharedWorkspaceTrustPath(target), protection)
	if err != nil || !s.matches(anchor) {
		return "", nil, errSharedTrustStorage
	}
	return target, s, nil
}
