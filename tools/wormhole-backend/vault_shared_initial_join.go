package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type sharedInitialAccountPreparation interface {
	sharedInitialEnrollment
	TakeDeviceAccount(context.Context) (*sharedpg.UnlockedDeviceAccount, error)
	Close() error
}

type sharedInitialInvitationSession interface {
	sharedInvitationCommitSession
	OpenInitialInvitation(context.Context, sharedpg.Invitation, []byte, vault.Profile, vault.Profile, bool) error
	prepareInitial(context.Context, sharedpg.Invitation, []byte, []byte, []byte, string, vault.Profile, vault.Profile) (sharedInitialAccountPreparation, error)
}

type nativeSharedInitialInvitation struct{ *sharedpg.Session }

func (s nativeSharedInitialInvitation) prepareInitial(ctx context.Context, i sharedpg.Invitation, code, password, ask []byte, name string, osFloor, userFloor vault.Profile) (sharedInitialAccountPreparation, error) {
	p, err := s.PrepareInitialEnrollment(ctx, i, code, password, ask, name, osFloor, userFloor)
	if p == nil {
		return nil, err
	}
	return p, err
}

type sharedInitialJoinInput struct {
	importPlan             *workspaceimport.Plan
	invitation             sharedpg.Invitation
	code, password, ask    []byte
	deviceName, appVersion string
	acknowledgeTLSOff      bool
}

func (input *sharedInitialJoinInput) wipe() {
	vault.Wipe(input.code)
	vault.Wipe(input.password)
	vault.Wipe(input.ask)
}

func (input sharedInitialJoinInput) valid() bool {
	i := input.invitation
	return i.Enrollment != nil && len(input.code) == vault.InviteCodeBytes && len(input.password) > 0 && len(input.password) <= 1024 &&
		(len(input.ask) == 0 || len(input.ask) == 32) && len(input.deviceName) > 0 && len(input.deviceName) <= 4096 &&
		utf8.ValidString(input.deviceName) && strings.IndexFunc(input.deviceName, unicode.IsControl) < 0 &&
		(sharedpg.AdmissionRequest{API: 1, AppVersion: input.appVersion, Source: "ui", WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID, DeviceID: i.Enrollment.Context.InviteID}).Validate() == nil
}

func decodeSharedInitialJoin(payload []byte) (input sharedInitialJoinInput, err error) {
	var token string
	var code, password, ask json.RawMessage
	defer func() {
		vault.Wipe(code)
		vault.Wipe(password)
		vault.Wipe(ask)
		if err != nil {
			input.wipe()
		}
	}()
	if len(payload) > 2*sharedpg.MaxInvitationBytes+16384 || decodeVaultObject(payload, map[string]any{
		"invitation": &token, "code": &code, "password": &password, "ask": &ask,
		"deviceName": &input.deviceName, "appVersion": &input.appVersion, "acknowledgeTLSOff": &input.acknowledgeTLSOff,
	}, "invitation", "code", "password", "deviceName", "appVersion", "acknowledgeTLSOff") != nil {
		return input, vaultwire.ErrProtocol
	}
	for _, field := range []struct {
		raw json.RawMessage
		out *[]byte
	}{{code, &input.code}, {password, &input.password}, {ask, &input.ask}} {
		if len(field.raw) != 0 && (field.raw[0] != '"' || json.Unmarshal(field.raw, field.out) != nil) {
			return input, vaultwire.ErrProtocol
		}
	}
	if len(token) > 2*sharedpg.MaxInvitationBytes || (len(ask) != 0 && len(input.ask) != 32) {
		return input, vaultwire.ErrProtocol
	}
	input.invitation, err = parseInitialSharedInvitation(token)
	if err != nil {
		return input, err
	}
	// This only validates client metadata before connecting. No device identity
	// is accepted here: the coordinator replaces all IDs from native preparation.
	if !input.valid() {
		return input, vaultwire.ErrProtocol
	}
	return input, nil
}

// Own preparation and transport until every cleanup confirms. In particular,
// a failed never-submitted discard still needs the protected preparation roots.
type vaultSharedInitialJoin struct {
	invitation  sharedInitialInvitationSession
	prepared    sharedInitialAccountPreparation
	coordinator *sharedInvitationJoin
	directory   os.FileInfo
	path        string
}

// Capture through a handle: Windows Lstat may defer loading a file ID until a
// later SameFile call, when the original path can already name another directory.
func captureInitialJoinDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errSharedTrustStorage
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, errSharedTrustStorage
	}
	opened, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(info, opened) {
		return nil, errSharedTrustStorage
	}
	return opened, nil
}

func (p *vaultSharedInitialJoin) close() error {
	var err error
	if p.coordinator != nil {
		if published := p.coordinator.publication; published != nil {
			if published.published {
				p.directory = published.directory
			} else {
				err = published.cleanup()
			}
		}
		if p.coordinator.preparation != nil && !p.coordinator.submitted {
			if p.prepared == nil {
				err = errors.Join(err, sharedpg.ErrConfiguration)
			} else {
				err = errors.Join(err, p.prepared.BorrowDeviceStorage(func(storage []byte, _ vault.SlotFile, _ []byte) error {
					return p.prepared.Borrow(func(_ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, _ *sharedpg.PreparedInvitationCommit) error {
						return root.Use(func(key []byte) error {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()
							return p.coordinator.DiscardDevicePreparation(ctx, key, storage)
						})
					})
				}))
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = errors.Join(err, p.coordinator.Close(ctx))
		cancel()
	}
	if p.invitation != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := p.invitation.Close(ctx)
		cancel()
		err = errors.Join(err, closeErr)
		if closeErr == nil {
			p.invitation = nil
		}
	}
	if err != nil {
		return err
	}
	if p.prepared != nil {
		if err := p.prepared.Close(); err != nil {
			return err
		}
		p.prepared = nil
	}
	if p.directory != nil && (p.coordinator == nil || !p.coordinator.submitted) {
		var err error
		if p.coordinator != nil && p.coordinator.publication != nil {
			err = p.coordinator.publication.cleanup()
		} else {
			err = p.removeEmptyPreparationDirectory()
		}
		if err != nil {
			return err
		}
	}
	p.directory = nil
	return nil
}

// Remove only this attempt's empty directory and empty lock placeholder, never
// an enrollment snapshot, remote outcome, unknown file or replaced directory.
func (p *vaultSharedInitialJoin) removeEmptyPreparationDirectory() error {
	actual, err := os.Lstat(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return privateFileDirectorySync(filepath.Dir(p.path))
	}
	if err != nil || !actual.IsDir() || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(actual, p.directory) {
		return errSharedTrustConflict
	}
	directory, err := os.Open(p.path)
	if err != nil {
		return errSharedInvitationPreparationCleanup
	}
	opened, statErr := directory.Stat()
	entries, readErr := directory.ReadDir(2)
	closeErr := directory.Close()
	if statErr != nil || !os.SameFile(opened, p.directory) || (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > 1 {
		return errSharedInvitationPreparationCleanup
	}
	if len(entries) == 1 {
		info, err := entries[0].Info()
		if err != nil || entries[0].Name() != "device.trust.lock" || !info.Mode().IsRegular() || info.Size() != 0 {
			return errSharedTrustConflict
		}
		if err := os.Remove(filepath.Join(p.path, entries[0].Name())); err != nil {
			return errSharedInvitationPreparationCleanup
		}
	}
	if err := os.Remove(p.path); err != nil {
		return errSharedInvitationPreparationCleanup
	}
	return privateFileDirectorySync(filepath.Dir(p.path))
}

func (h *vaultFoundationHandler) joinSharedInitial(ctx context.Context, payload []byte) (result json.RawMessage, err error) {
	input, err := decodeSharedInitialJoin(payload)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	return h.joinSharedInitialInput(ctx, input)
}

func (h *vaultFoundationHandler) joinSharedInitialInput(ctx context.Context, input sharedInitialJoinInput) (result json.RawMessage, err error) {
	if ctx == nil || h.closed || h.shared != nil || h.owner != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil || h.migrationQuiesced || !filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath || !input.valid() {
		return nil, vaultwire.ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(floor); err != nil {
		return nil, err
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	p := &vaultSharedInitialJoin{path: sharedWorkspaceDirectory(h.databasePath)}
	s := &vaultSharedSession{release: release, initial: p}
	h.shared = s
	defer func() {
		if err != nil {
			if cleanup := s.close(); cleanup != nil {
				err = h.retire(errors.Join(err, cleanup))
			} else {
				h.shared = nil
			}
		}
	}()
	if err := requireNewVaultWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	factory := h.sharedInvitationFactory
	if factory == nil {
		factory = func() sharedInitialInvitationSession { return nativeSharedInitialInvitation{sharedpg.NewSession()} }
	}
	p.invitation = factory()
	if p.invitation == nil {
		return nil, sharedpg.ErrConfiguration
	}
	i := input.invitation
	if err := p.invitation.OpenInitialInvitation(ctx, i, input.code, floor, vault.Default, input.acknowledgeTLSOff); err != nil {
		return nil, err
	}
	p.prepared, err = p.invitation.prepareInitial(ctx, i, input.code, input.password, input.ask, input.deviceName, floor, vault.Default)
	if err != nil {
		return nil, err
	}
	if p.prepared == nil {
		return nil, sharedpg.ErrConfiguration
	}
	admission := h.sharedFactory
	if admission == nil {
		admission = newSharedAdmissionController
	}
	p.coordinator = newSharedInvitationJoinWithSession(p.invitation, func() sharedJoinRecovery {
		controller := admission()
		if controller == nil {
			return nil
		}
		return controller
	})
	p.invitation = nil // the coordinator now owns the temporary connection
	// Invitations without signed topology use a single polling connection.
	// Device admission applies the organisation's policy after verification.
	o := sharedAdmissionOptions{TrustPath: sharedWorkspaceTrustPath(h.databasePath), OSFloor: floor, UserFloor: vault.Default, MinimumRevision: 1, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: input.appVersion, Source: "ui"}, Settings: sharedpg.Settings{Endpoints: append([]sharedpg.Endpoint(nil), i.Endpoints...), Database: i.Database, TLS: i.TLS, CAPEM: bytes.Clone(i.CAPEM), Profile: floor, Changes: sharedpg.ChangePolicy{TransactionPooler: true}}}
	err = p.prepared.Borrow(func(_ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, commit *sharedpg.PreparedInvitationCommit) error {
		o.Binding = root.Binding()
		if o.Binding.WorkspaceID != i.WorkspaceID || o.Binding.UserID != i.Enrollment.Context.UserID {
			return sharedpg.ErrTrustState
		}
		o.Request.WorkspaceID, o.Request.UserID, o.Request.DeviceID = o.Binding.WorkspaceID, o.Binding.UserID, o.Binding.DeviceID
		if i.FormatVersion == 3 {
			pending, err := commit.PendingEnrollment(o.Binding)
			if err != nil {
				return err
			}
			trust, err := pending.Trust.AccountTrust()
			if err != nil {
				return err
			}
			o.Settings.TLSBundle, err = i.AuthenticatedTLSBundle(trust.Organisation, trust.Signer)
			if err != nil {
				return err
			}
		}
		return o.Request.Validate()
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.coordinator.initialInvitation = &i
	protection := h.startupProtection()
	joined, err := p.coordinator.joinPreparedWithStartup(ctx, o, p.prepared, &protection)
	if err != nil {
		return nil, err
	}
	if joined == nil || !joined.Confirmed {
		return nil, sharedpg.ErrAdmissionResponse
	}
	account, err := p.prepared.TakeDeviceAccount(ctx)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, sharedpg.ErrConfiguration
	}
	s.selected = &sharedSelectedDevice{account: account, options: o, mode: sharedDeviceOrdinary}
	if err := p.close(); err != nil {
		return nil, err
	}
	s.initial = nil
	s.controller = admission()
	if s.controller == nil {
		return nil, sharedpg.ErrConfiguration
	}
	s.controller.catalogChanged = h.notifySharedCatalog
	if err := s.selected.Open(ctx, s.controller); err != nil {
		return nil, err
	}
	return h.publishSharedAdmission(ctx, s, i.WorkspaceID.String(), 0)
}
