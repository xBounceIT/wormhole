package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxBitwardenBrowserJSON = 8 * 1024 * 1024
const maxBitwardenBrowserProfiles = 32
const maxBitwardenBrowserCache = 64 * 1024 * 1024

// Native-only borrowed snapshot. It must be sealed to the owning extension
// before leaving Go; never marshal it as an ordinary IPC response. The byte
// slices are wiped after use, and callbacks cannot reenter the owner.
type BitwardenBrowserSnapshot struct {
	Revision, ProfileRevision uint64
	Restore                   bool
	LocalJSON, SessionJSON    []byte
}

func (BitwardenBrowserSnapshot) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

type browserSealedState struct {
	ID     string
	Size   int
	Chunks []vault.Envelope
}
type bitwardenBrowserProfile struct {
	Revision       uint64
	Local, Session browserSealedState
}
type bitwardenBrowserRuntime struct {
	Revision, PersistedRevision, StorageRevision uint64
	LocalHash                                    [32]byte
	Session                                      browserSealedState
	Profiles                                     map[string]bitwardenBrowserProfile
}

// Matches the migrated legacy record. Session state is deliberately absent.
type bitwardenBrowserRecord struct {
	SchemaVersion int
	Revision      uint64
	LocalJson     string
}

func browserObject(raw []byte) (map[string]json.RawMessage, error) {
	return browserObjectLimit(raw, MaxBitwardenBrowserJSON)
}
func browserObjectLimit(raw []byte, maximum int) (map[string]json.RawMessage, error) {
	if len(raw) < 2 || len(raw) > maximum || !utf8.Valid(raw) {
		return nil, vault.ErrFormat
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, vault.ErrFormat
	}
	out := make(map[string]json.RawMessage)
	valid := false
	defer func() {
		if !valid {
			wipeBrowserObject(out)
		}
	}()
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, vault.ErrFormat
		}
		name, ok := key.(string)
		if !ok || len(out) >= 65536 {
			return nil, vault.ErrFormat
		}
		if _, exists := out[name]; exists {
			return nil, vault.ErrFormat
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			vault.Wipe(value)
			return nil, vault.ErrFormat
		}
		var compact bytes.Buffer
		if json.Compact(&compact, value) != nil {
			vault.Wipe(value)
			vault.Wipe(compact.Bytes())
			return nil, vault.ErrFormat
		}
		vault.Wipe(value)
		out[name] = compact.Bytes()
	}
	if _, err = d.Token(); err != nil {
		return nil, vault.ErrFormat
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, vault.ErrFormat
	}
	valid = true
	return out, nil
}
func wipeBrowserObject(value map[string]json.RawMessage) {
	for _, v := range value {
		vault.Wipe(v)
	}
}
func encodeBrowserObject(value map[string]json.RawMessage) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil, vault.ErrFormat
	}
	raw := bytes.TrimSpace(buffer.Bytes())
	if len(raw) > MaxBitwardenBrowserJSON {
		vault.Wipe(buffer.Bytes())
		return nil, vault.ErrFormat
	}
	return raw, nil
}
func normalizeBrowserObject(raw []byte) ([]byte, error) {
	value, err := browserObject(raw)
	if err != nil {
		return nil, err
	}
	defer wipeBrowserObject(value)
	return encodeBrowserObject(value)
}

// Apply changed keys only while their shared value still equals this profile's
// base. Explicit deletion always wins over a simultaneous token refresh.
func mergeBrowserObject(base, incoming, current []byte) ([]byte, error) {
	before, err := browserObject(base)
	if err != nil {
		return nil, err
	}
	defer wipeBrowserObject(before)
	after, err := browserObject(incoming)
	if err != nil {
		return nil, err
	}
	defer wipeBrowserObject(after)
	latest, err := browserObject(current)
	if err != nil {
		return nil, err
	}
	defer wipeBrowserObject(latest)
	for key, value := range after {
		if !bytes.Equal(value, before[key]) && bytes.Equal(latest[key], before[key]) {
			vault.Wipe(latest[key])
			latest[key] = bytes.Clone(value)
		}
	}
	for key := range before {
		if _, exists := after[key]; !exists {
			vault.Wipe(latest[key])
			delete(latest, key)
		}
	}
	return encodeBrowserObject(latest)
}
func wipeBrowserSealed(state browserSealedState) {
	for _, chunk := range state.Chunks {
		vault.Wipe(chunk.Ciphertext)
		vault.Wipe(chunk.Nonce)
	}
}
func browserSealedBytes(state browserSealedState) int {
	size := 0
	for _, chunk := range state.Chunks {
		size += len(chunk.Ciphertext) + len(chunk.Nonce)
	}
	return size
}
func browserProfileBytes(profile bitwardenBrowserProfile) int {
	return browserSealedBytes(profile.Local) + browserSealedBytes(profile.Session)
}
func (o *Owner) browserCacheBytes() int {
	if o.bitwarden == nil {
		return 0
	}
	size := browserSealedBytes(o.bitwarden.Session)
	for _, profile := range o.bitwarden.Profiles {
		size += browserProfileBytes(profile)
	}
	return size
}
func (o *Owner) clearBitwardenBrowser() {
	if o.bitwarden == nil {
		return
	}
	wipeBrowserSealed(o.bitwarden.Session)
	for _, profile := range o.bitwarden.Profiles {
		wipeBrowserSealed(profile.Local)
		wipeBrowserSealed(profile.Session)
	}
	o.bitwarden = nil
}
func (o *Owner) browserBinding(id, scope, area string, index int) vault.Binding {
	identity := o.store.Identity()
	return vault.Binding{WorkspaceID: identity.WorkspaceID, Table: "BitwardenBrowserRuntime", OwnerID: scope, Field: identity.FileID + ":" + id + ":" + area + ":" + strconv.Itoa(index), KeyID: identity.Root.ID, KeyVersion: identity.Root.Version}
}
func (o *Owner) sealBrowserState(scope, area string, raw []byte) (browserSealedState, error) {
	state := browserSealedState{ID: uuid.NewString(), Size: len(raw)}
	err := o.root.With(func(root []byte) error {
		binding := o.browserBinding(state.ID, scope, area, 0)
		key, err := vault.DeriveKey(root, []byte(binding.WorkspaceID+":"+state.ID), vault.PurposeBrowserState)
		if err != nil {
			return err
		}
		defer vault.Wipe(key)
		for start := 0; start < len(raw); start += vault.MaxSecretBytes {
			chunk, err := vault.Seal(key, o.browserBinding(state.ID, scope, area, len(state.Chunks)), raw[start:min(start+vault.MaxSecretBytes, len(raw))])
			if err != nil {
				return err
			}
			state.Chunks = append(state.Chunks, chunk)
		}
		return nil
	})
	if err != nil {
		wipeBrowserSealed(state)
		return browserSealedState{}, err
	}
	return state, nil
}
func (o *Owner) openBrowserState(state browserSealedState, scope, area string) ([]byte, error) {
	if state.ID == "" {
		if state.Size != 0 || len(state.Chunks) != 0 {
			return nil, vault.ErrFormat
		}
		return []byte("{}"), nil
	}
	if !browserProfileID(state.ID) || state.Size < 2 || state.Size > MaxBitwardenBrowserJSON || len(state.Chunks) != (state.Size+vault.MaxSecretBytes-1)/vault.MaxSecretBytes {
		return nil, vault.ErrFormat
	}
	raw := make([]byte, state.Size)
	err := o.root.With(func(root []byte) error {
		binding := o.browserBinding(state.ID, scope, area, 0)
		key, err := vault.DeriveKey(root, []byte(binding.WorkspaceID+":"+state.ID), vault.PurposeBrowserState)
		if err != nil {
			return err
		}
		defer vault.Wipe(key)
		for i, envelope := range state.Chunks {
			chunk, err := vault.Open(key, o.browserBinding(state.ID, scope, area, i), envelope)
			if err != nil {
				return err
			}
			start := i * vault.MaxSecretBytes
			if len(chunk) != min(vault.MaxSecretBytes, len(raw)-start) {
				vault.Wipe(chunk)
				return vault.ErrAuthentication
			}
			copy(raw[start:], chunk)
			vault.Wipe(chunk)
		}
		return nil
	})
	if err != nil {
		vault.Wipe(raw)
		return nil, err
	}
	return raw, nil
}
func (o *Owner) bitwardenBrowserCurrent(ctx context.Context) ([]byte, []byte, error) {
	security, err := o.readSecurityProfile(ctx)
	if err != nil {
		return nil, nil, err
	}
	if security.Effective != vault.Default && security.Effective != vault.Standard {
		return nil, nil, vault.ErrPolicy
	}
	workspace := o.store.Identity().WorkspaceID
	minimum := uint64(0)
	if o.bitwarden != nil {
		minimum = o.bitwarden.StorageRevision
	}
	state, err := o.readLocalState(ctx, "bitwarden-browser", workspace)
	if errors.Is(err, vaultstore.ErrMissing) && minimum == 0 {
		if o.bitwarden == nil {
			o.bitwarden = &bitwardenBrowserRuntime{Profiles: make(map[string]bitwardenBrowserProfile), LocalHash: sha256.Sum256([]byte("{}"))}
		}
		session, err := o.openBrowserState(o.bitwarden.Session, workspace, "shared-session")
		return []byte("{}"), session, err
	}
	if err != nil {
		if errors.Is(err, vaultstore.ErrMissing) {
			err = vault.ErrRollback
		}
		return nil, nil, err
	}
	if state.Deleted || state.RowVersion < minimum {
		return nil, nil, vault.ErrRollback
	}
	var local []byte
	var revision uint64
	err = o.withLocalState(ctx, "bitwarden-browser", workspace, state.RowVersion, func(raw []byte) error {
		var record bitwardenBrowserRecord
		fields, e := browserObjectLimit(raw, 6*MaxBitwardenBrowserJSON+1024)
		if e != nil {
			return e
		}
		defer wipeBrowserObject(fields)
		if len(fields) != 3 || json.Unmarshal(fields["SchemaVersion"], &record.SchemaVersion) != nil || json.Unmarshal(fields["Revision"], &record.Revision) != nil || json.Unmarshal(fields["LocalJson"], &record.LocalJson) != nil || record.SchemaVersion != 1 || record.Revision == 0 || record.Revision > math.MaxInt64 {
			return vault.ErrFormat
		}
		revision = record.Revision
		local, err = normalizeBrowserObject([]byte(record.LocalJson))
		return err
	})
	if err != nil {
		vault.Wipe(local)
		return nil, nil, err
	}
	hash := sha256.Sum256(local)
	if o.bitwarden != nil && (revision < o.bitwarden.PersistedRevision || (revision == o.bitwarden.PersistedRevision && hash != o.bitwarden.LocalHash)) {
		vault.Wipe(local)
		return nil, nil, vault.ErrRollback
	}
	if o.bitwarden != nil && state.RowVersion != minimum {
		vault.Wipe(local)
		return nil, nil, vaultstore.ErrConflict
	}
	if o.bitwarden == nil {
		o.bitwarden = &bitwardenBrowserRuntime{Revision: revision, Profiles: make(map[string]bitwardenBrowserProfile)}
	}
	session, err := o.openBrowserState(o.bitwarden.Session, workspace, "shared-session")
	if err != nil {
		vault.Wipe(local)
		return nil, nil, err
	}
	o.bitwarden.PersistedRevision, o.bitwarden.StorageRevision, o.bitwarden.LocalHash = revision, state.RowVersion, hash
	return local, session, nil
}
func (o *Owner) makeBrowserProfile(profileID string, local, session []byte, revision uint64) (bitwardenBrowserProfile, error) {
	profile := bitwardenBrowserProfile{Revision: revision}
	var err error
	profile.Local, err = o.sealBrowserState(profileID, "local-base", local)
	if err != nil {
		return bitwardenBrowserProfile{}, err
	}
	profile.Session, err = o.sealBrowserState(profileID, "session-base", session)
	if err != nil {
		wipeBrowserSealed(profile.Local)
		return bitwardenBrowserProfile{}, err
	}
	return profile, nil
}
func browserProfileID(id string) bool {
	value, err := uuid.Parse(id)
	return err == nil && value != uuid.Nil && value.String() == id
}

// ReadBitwardenBrowserState hydrates a native extension context. Both input
// buffers are its actual capture before restore, not an external revision marker.
// They are consumed on every return path. The encrypted merge base records what
// the context actually held, never the snapshot it has yet to apply. After restore
// the native controller captures again to acknowledge its actual resulting state.
func (o *Owner) ReadBitwardenBrowserState(ctx context.Context, profileID string, localJSON, sessionJSON []byte, use func(BitwardenBrowserSnapshot) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readBitwardenBrowserState(ctx, profileID, localJSON, sessionJSON, use)
}

func (o *Owner) readBitwardenBrowserState(ctx context.Context, profileID string, localJSON, sessionJSON []byte, use func(BitwardenBrowserSnapshot) error) error {
	defer vault.Wipe(localJSON)
	defer vault.Wipe(sessionJSON)
	if !browserProfileID(profileID) || use == nil {
		return vault.ErrFormat
	}
	incomingLocal, err := normalizeBrowserObject(localJSON)
	if err != nil {
		return err
	}
	defer vault.Wipe(incomingLocal)
	incomingSession, err := normalizeBrowserObject(sessionJSON)
	if err != nil {
		return err
	}
	defer vault.Wipe(incomingSession)
	local, session, err := o.bitwardenBrowserCurrent(ctx)
	if err != nil {
		return err
	}
	defer vault.Wipe(local)
	defer vault.Wipe(session)
	previous, exists := o.bitwarden.Profiles[profileID]
	if !exists && len(o.bitwarden.Profiles) >= maxBitwardenBrowserProfiles {
		return vault.ErrPolicy
	}
	next, err := o.makeBrowserProfile(profileID, incomingLocal, incomingSession, o.bitwarden.Revision)
	if err != nil {
		return err
	}
	if o.browserCacheBytes()-browserProfileBytes(previous)+browserProfileBytes(next) > maxBitwardenBrowserCache {
		wipeBrowserSealed(next.Local)
		wipeBrowserSealed(next.Session)
		return vault.ErrPolicy
	}
	snapshot := BitwardenBrowserSnapshot{Revision: o.bitwarden.Revision, ProfileRevision: o.bitwarden.Revision, Restore: !bytes.Equal(local, incomingLocal) || !bytes.Equal(session, incomingSession), LocalJSON: local, SessionJSON: session}
	if err = use(snapshot); err == nil {
		err = ctx.Err()
	}
	if err != nil {
		wipeBrowserSealed(next.Local)
		wipeBrowserSealed(next.Session)
		return err
	}
	wipeBrowserSealed(previous.Local)
	wipeBrowserSealed(previous.Session)
	o.bitwarden.Profiles[profileID] = next
	return nil
}

// CaptureBitwardenBrowserState consumes both buffers on every return path.
// Only local state is persisted, using the vault's atomic encrypted chunk store.
// Runtime/session and merge bases stay encrypted in this owner process.
func (o *Owner) CaptureBitwardenBrowserState(ctx context.Context, profileID string, sourceRevision uint64, localJSON, sessionJSON []byte, use func(BitwardenBrowserSnapshot) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.captureBitwardenBrowserState(ctx, profileID, sourceRevision, localJSON, sessionJSON, use)
}

func (o *Owner) captureBitwardenBrowserState(ctx context.Context, profileID string, sourceRevision uint64, localJSON, sessionJSON []byte, use func(BitwardenBrowserSnapshot) error) error {
	defer vault.Wipe(localJSON)
	defer vault.Wipe(sessionJSON)
	if !browserProfileID(profileID) || sourceRevision > math.MaxInt64 || use == nil {
		return vault.ErrFormat
	}
	local, session, err := o.bitwardenBrowserCurrent(ctx)
	if err != nil {
		return err
	}
	defer vault.Wipe(local)
	defer vault.Wipe(session)
	previous, exists := o.bitwarden.Profiles[profileID]
	if !exists || previous.Revision != sourceRevision {
		return vaultstore.ErrConflict
	}
	incomingLocal, err := normalizeBrowserObject(localJSON)
	if err != nil {
		return err
	}
	defer vault.Wipe(incomingLocal)
	incomingSession, err := normalizeBrowserObject(sessionJSON)
	if err != nil {
		return err
	}
	defer vault.Wipe(incomingSession)
	baseLocal, err := o.openBrowserState(previous.Local, profileID, "local-base")
	if err != nil {
		return err
	}
	defer vault.Wipe(baseLocal)
	baseSession, err := o.openBrowserState(previous.Session, profileID, "session-base")
	if err != nil {
		return err
	}
	defer vault.Wipe(baseSession)
	mergedLocal, err := mergeBrowserObject(baseLocal, incomingLocal, local)
	if err != nil {
		return err
	}
	defer vault.Wipe(mergedLocal)
	mergedSession, err := mergeBrowserObject(baseSession, incomingSession, session)
	if err != nil {
		return err
	}
	defer vault.Wipe(mergedSession)
	revision := o.bitwarden.Revision
	localChanged := !bytes.Equal(local, mergedLocal)
	changed := localChanged || !bytes.Equal(session, mergedSession)
	if changed {
		if revision >= math.MaxInt64 {
			return vault.ErrPolicy
		}
		revision++
	}
	next, err := o.makeBrowserProfile(profileID, incomingLocal, incomingSession, revision)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			wipeBrowserSealed(next.Local)
			wipeBrowserSealed(next.Session)
		}
	}()
	nextSession, err := o.sealBrowserState(o.store.Identity().WorkspaceID, "shared-session", mergedSession)
	if err != nil {
		return err
	}
	defer func() {
		if !retained {
			wipeBrowserSealed(nextSession)
		}
	}()
	// Delivery may fail after the global session commits. In that case the old
	// profile base must stay available for retry, so bound both retained states.
	afterCommit := o.browserCacheBytes() - browserSealedBytes(o.bitwarden.Session) + browserSealedBytes(nextSession)
	afterAcknowledgement := afterCommit - browserProfileBytes(previous) + browserProfileBytes(next)
	if max(afterCommit, afterAcknowledgement) > maxBitwardenBrowserCache {
		return vault.ErrPolicy
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Volatile background bookkeeping must not rewrite the persisted account/vault
	// snapshot. Its counter belongs to this owner lifetime; durable revisions
	// advance only when local state changes.
	if localChanged {
		payload, err := json.Marshal(bitwardenBrowserRecord{SchemaVersion: 1, Revision: revision, LocalJson: string(mergedLocal)})
		if err != nil {
			return vault.ErrFormat
		}
		defer vault.Wipe(payload)
		state, err := o.writeLocalState(ctx, "bitwarden-browser", o.store.Identity().WorkspaceID, payload, o.bitwarden.StorageRevision, false)
		if err != nil {
			return err
		}
		o.bitwarden.StorageRevision = state.RowVersion
		o.bitwarden.PersistedRevision = revision
	}
	wipeBrowserSealed(o.bitwarden.Session)
	o.bitwarden.Session = nextSession
	// Global state is committed before delivery. Failed delivery leaves the old
	// profile base intact so a retry cannot overwrite another profile's edits.
	o.bitwarden.Revision, o.bitwarden.LocalHash = revision, sha256.Sum256(mergedLocal)
	snapshot := BitwardenBrowserSnapshot{Revision: revision, ProfileRevision: revision, Restore: !bytes.Equal(mergedLocal, incomingLocal) || !bytes.Equal(mergedSession, incomingSession), LocalJSON: mergedLocal, SessionJSON: mergedSession}
	if err = use(snapshot); err == nil {
		err = ctx.Err()
	}
	// The committed session cache must survive a failed acknowledgement too.
	retained = true
	if err != nil {
		wipeBrowserSealed(next.Local)
		wipeBrowserSealed(next.Session)
		return err
	}
	wipeBrowserSealed(previous.Local)
	wipeBrowserSealed(previous.Session)
	// Restore is conditional in the extension. A newer token may prevent a
	// requested deletion from applying; treating the merged result as its base
	// would make that stale token look like a new login on the next capture.
	o.bitwarden.Profiles[profileID] = next
	return nil
}

func (o *Owner) CloseBitwardenBrowserProfile(profileID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !browserProfileID(profileID) {
		return vault.ErrFormat
	}
	var err error
	for _, stage := range o.bitwardenTransfers {
		if stage.context.ProfileID == profileID {
			err = errors.Join(err, o.retireBitwardenTransfer(stage))
		}
	}
	if o.bitwarden != nil {
		previous := o.bitwarden.Profiles[profileID]
		wipeBrowserSealed(previous.Local)
		wipeBrowserSealed(previous.Session)
		delete(o.bitwarden.Profiles, profileID)
	}
	return err
}
