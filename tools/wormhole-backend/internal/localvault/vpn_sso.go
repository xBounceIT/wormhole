package localvault

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const vpnSSOHeaderBytes = 48
const MaxVPNSSOArchiveBytes = vault.MaxVPNSSOArchiveBytes
const maxVPNSSOProfiles = 32
const maxVPNSSOFloors = 1024

// VPNSSOBinding is selected by the native, authenticated route resolver. It is
// not admission or Use authority. AccountID identifies the local user's account,
// including when WorkspaceID/FileID identify a shared workspace. The receiver is
// always that user's personal local Owner, never a workspace-shared key store.
// RouteDigest covers the complete upstream route; TrustDigest covers TLS policy,
// pins and CA material. Neither may be computed from renderer-supplied claims.
type VPNSSOBinding struct {
	WorkspaceID, FileID, TunnelID, AccountID string
	Kind                                     uint16
	ConfigurationVersion                     uint64
	GatewayOrigin, Realm                     string
	RouteDigest, TrustDigest                 [32]byte
}

func (b VPNSSOBinding) digest() ([32]byte, error) {
	for _, id := range []string{b.WorkspaceID, b.FileID, b.TunnelID, b.AccountID} {
		if !browserProfileID(id) {
			return [32]byte{}, vault.ErrFormat
		}
	}
	if len(b.GatewayOrigin) > 4096 {
		return [32]byte{}, vault.ErrFormat
	}
	u, err := url.Parse(b.GatewayOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != b.GatewayOrigin || strings.HasSuffix(u.Host, ":") {
		return [32]byte{}, vault.ErrFormat
	}
	if strings.ContainsAny(u.Host, "[]") || strings.Contains(u.Hostname(), ":") {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Is6() || !strings.HasPrefix(u.Host, "[") {
			return [32]byte{}, vault.ErrFormat
		}
	}
	if u.Port() != "" {
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return [32]byte{}, vault.ErrFormat
		}
	}
	if strings.IndexFunc(b.GatewayOrigin, func(r rune) bool { return r <= 32 || r >= 127 || r == '\\' || r == '%' }) >= 0 || !utf8.ValidString(b.Realm) || len(b.Realm) > 4096 || strings.IndexFunc(b.Realm, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || (b.Kind != 2 && b.Kind != 9) || b.ConfigurationVersion == 0 || b.ConfigurationVersion > math.MaxInt64 || b.RouteDigest == [32]byte{} || b.TrustDigest == [32]byte{} {
		return [32]byte{}, vault.ErrFormat
	}
	// A fixed-field structure has a deterministic representation. Lengths and
	// escaping are unambiguous, including realms containing separators/Unicode.
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, vault.ErrFormat
	}
	return sha256.Sum256(append([]byte("wormhole/v1/vpn-sso-binding\x00"), raw...)), nil
}

// VPNSSOCheckpoint is public metadata for the eventual protected device anchor.
// Zero means never observed; a tombstone has a nonzero revision and digest.
// Callers must persist observations before exposing restored storage. The owner
// additionally retains observations for its entire lifetime, including failures.
type VPNSSOCheckpoint struct {
	Revision uint64   `json:"revision,string"`
	Deleted  bool     `json:"deleted"`
	Digest   [32]byte `json:"digest"`
}

func (c VPNSSOCheckpoint) valid() bool {
	return c.Revision <= math.MaxInt64 && ((c.Revision == 0 && !c.Deleted && c.Digest == [32]byte{}) || (c.Revision > 0 && c.Digest != [32]byte{}))
}

// Archive is an opaque, versioned native browser-storage archive, not a cookie
// DTO or a VPN completion credential. The native serializer must capture/restore
// all supported storage and exclude attempt credentials. This persistence layer
// deliberately does not claim to implement that serializer or its transport.
// Borrowed bytes are wiped after use. Callbacks cannot reenter this owner.
type VPNSSOSnapshot struct {
	Checkpoint VPNSSOCheckpoint
	Archive    []byte
}

func (VPNSSOSnapshot) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

type vpnSSOProfile struct {
	Binding        [32]byte
	Scope          string
	Source         VPNSSOCheckpoint
	PolicySequence uint64
	Expires        time.Time
}

// VPNSSOFloor also records an authenticated manifest whose ciphertext could not
// be read. Its row revision may exceed the last fully verified checkpoint.
type VPNSSOFloor struct {
	Checkpoint VPNSSOCheckpoint `json:"checkpoint"`
	RowVersion uint64           `json:"rowVersion,string"`
}

func (o *Owner) vpnSSOSecurity(ctx context.Context) (SecurityProfile, error) {
	if ctx == nil {
		return SecurityProfile{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return SecurityProfile{}, err
	}
	read := o.readSecurityProfile
	if o.vpnSSONativeSecurity != nil {
		read = o.vpnSSONativeSecurity
	}
	s, err := read(ctx)
	if err != nil {
		return s, err
	}
	if s.Effective != vault.Default && s.Effective != vault.Standard {
		return s, vault.ErrPolicy
	}
	if s.Sequence == 0 || s.Sequence > math.MaxInt64 || s.Sequence < o.profileFloor {
		return s, vault.ErrRollback
	}
	o.profileFloor = max(o.profileFloor, s.Sequence)
	return s, nil
}

func vpnSSOScope(digest [32]byte) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, digest[:]).String()
}

func vpnSSOTombstone(digest [32]byte, revision uint64) VPNSSOCheckpoint {
	raw := append([]byte("wormhole/v1/vpn-sso-deleted\x00"), digest[:]...)
	raw = binary.BigEndian.AppendUint64(raw, revision)
	return VPNSSOCheckpoint{Revision: revision, Deleted: true, Digest: sha256.Sum256(raw)}
}

func (o *Owner) retainVPNSSOFloor(scope string, minimum VPNSSOCheckpoint) error {
	floor, exists := o.vpnSSOFloors[scope]
	if exists && minimum.Revision < floor.Checkpoint.Revision {
		return nil
	}
	if exists && minimum.Revision == floor.Checkpoint.Revision && minimum != floor.Checkpoint {
		return vault.ErrRollback
	}
	if !exists && len(o.vpnSSOFloors) >= maxVPNSSOFloors {
		return vault.ErrPolicy
	}
	if o.vpnSSOFloors == nil {
		o.vpnSSOFloors = make(map[string]VPNSSOFloor)
	}
	floor.Checkpoint = minimum
	floor.RowVersion = max(floor.RowVersion, minimum.Revision)
	o.vpnSSOFloors[scope] = floor
	return nil
}

func (o *Owner) observeVPNSSO(scope string, current VPNSSOCheckpoint) error {
	floor := o.vpnSSOFloors[scope]
	if current.Revision < floor.RowVersion || (current.Revision == floor.Checkpoint.Revision && current != floor.Checkpoint) {
		return vault.ErrRollback
	}
	o.vpnSSOFloors[scope] = VPNSSOFloor{Checkpoint: current, RowVersion: current.Revision}
	return nil
}

func (o *Owner) withVPNSSO(ctx context.Context, digest [32]byte, minimum VPNSSOCheckpoint, use func(VPNSSOSnapshot) error) error {
	scope := vpnSSOScope(digest)
	// A checkpoint supplied by the trusted native anchor is itself an
	// observation. Keep it even if the database is missing, corrupt or unreadable.
	if err := o.retainVPNSSOFloor(scope, minimum); err != nil {
		return err
	}
	state, err := o.readLocalState(ctx, "vpn-sso", scope)
	if err == nil {
		// Authentication is already complete. Retain the manifest revision even
		// if cancellation wins before any archive bytes can be assembled.
		floor := o.vpnSSOFloors[scope]
		if state.RowVersion < floor.RowVersion {
			return vault.ErrRollback
		}
		floor.RowVersion = state.RowVersion
		o.vpnSSOFloors[scope] = floor
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, vaultstore.ErrMissing) {
		if err := o.observeVPNSSO(scope, VPNSSOCheckpoint{}); err != nil {
			return err
		}
		return use(VPNSSOSnapshot{})
	}
	if err != nil {
		return err
	}
	if state.Deleted {
		c := vpnSSOTombstone(digest, state.RowVersion)
		if err := o.observeVPNSSO(scope, c); err != nil {
			return err
		}
		return use(VPNSSOSnapshot{Checkpoint: c})
	}
	return o.withLocalStateChunks(ctx, state, func(raw []byte) error {
		if len(raw) <= vpnSSOHeaderBytes || string(raw[:4]) != "VSS1" || string(raw[4:36]) != string(digest[:]) || binary.BigEndian.Uint64(raw[36:44]) != state.RowVersion || uint64(binary.BigEndian.Uint32(raw[44:48])) != uint64(len(raw)-vpnSSOHeaderBytes) {
			return vault.ErrAuthentication
		}
		c := VPNSSOCheckpoint{Revision: state.RowVersion, Digest: sha256.Sum256(raw)}
		if err := o.observeVPNSSO(scope, c); err != nil {
			return err
		}
		return use(VPNSSOSnapshot{Checkpoint: c, Archive: raw[vpnSSOHeaderBytes:]})
	})
}

// OpenVPNSSO reserves a native attempt and borrows the current archive. The
// reservation is published only after successful restore/acknowledgement. The
// immutable binding, revision and policy sequence remain attached to it. A later
// save cannot overwrite a concurrent login or resurrect a deleted session.
func (o *Owner) OpenVPNSSO(ctx context.Context, binding VPNSSOBinding, profileID string, minimum VPNSSOCheckpoint, use func(VPNSSOSnapshot) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.openVPNSSO(ctx, binding, profileID, minimum, use)
}

func (o *Owner) openVPNSSO(ctx context.Context, binding VPNSSOBinding, profileID string, minimum VPNSSOCheckpoint, use func(VPNSSOSnapshot) error) error {
	digest, err := binding.digest()
	if err != nil || !browserProfileID(profileID) || !minimum.valid() || use == nil {
		return vault.ErrFormat
	}
	security, err := o.vpnSSOSecurity(ctx)
	if err != nil {
		return err
	}
	for id, profile := range o.vpnSSOProfiles {
		if !time.Now().Before(profile.Expires) {
			delete(o.vpnSSOProfiles, id)
		}
	}
	if _, exists := o.vpnSSOProfiles[profileID]; exists || len(o.vpnSSOProfiles) >= maxVPNSSOProfiles {
		return vault.ErrPolicy
	}
	var source VPNSSOCheckpoint
	err = o.withVPNSSO(ctx, digest, minimum, func(snapshot VPNSSOSnapshot) error {
		source = snapshot.Checkpoint
		return use(snapshot)
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.vpnSSOProfiles == nil {
		o.vpnSSOProfiles = make(map[string]vpnSSOProfile)
	}
	o.vpnSSOProfiles[profileID] = vpnSSOProfile{Binding: digest, Scope: vpnSSOScope(digest), Source: source, PolicySequence: security.Sequence, Expires: time.Now().Add(5 * time.Minute)}
	return nil
}

// SaveVPNSSO consumes archive on every path. Only a confirmed native browser
// capture belongs here; a fresh VPN bearer must still pass its separate one-use
// completion flow. Successful save retires the reservation, including on reply
// loss. Failed writes preserve it for a matching retry until expiry/close.
func (o *Owner) SaveVPNSSO(ctx context.Context, binding VPNSSOBinding, profileID string, archive []byte) (VPNSSOCheckpoint, error) {
	defer vault.Wipe(archive)
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.saveVPNSSO(ctx, binding, profileID, archive)
}

// Caller holds o.mu and owns/wipes archive.
func (o *Owner) saveVPNSSO(ctx context.Context, binding VPNSSOBinding, profileID string, archive []byte) (VPNSSOCheckpoint, error) {
	digest, err := binding.digest()
	if err != nil || !browserProfileID(profileID) || len(archive) == 0 || len(archive) > MaxVPNSSOArchiveBytes {
		return VPNSSOCheckpoint{}, vault.ErrFormat
	}
	security, err := o.vpnSSOSecurity(ctx)
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	profile, exists := o.vpnSSOProfiles[profileID]
	if !exists || profile.Binding != digest || profile.PolicySequence != security.Sequence || !time.Now().Before(profile.Expires) {
		return VPNSSOCheckpoint{}, vault.ErrPolicy
	}
	if profile.Source.Revision >= math.MaxInt64 {
		return VPNSSOCheckpoint{}, vault.ErrPolicy
	}
	err = o.withVPNSSO(ctx, digest, profile.Source, func(current VPNSSOSnapshot) error {
		if current.Checkpoint != profile.Source {
			return vaultstore.ErrConflict
		}
		return nil
	})
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	raw := make([]byte, vpnSSOHeaderBytes+len(archive))
	defer vault.Wipe(raw)
	copy(raw[:4], "VSS1")
	copy(raw[4:36], digest[:])
	binary.BigEndian.PutUint64(raw[36:44], profile.Source.Revision+1)
	binary.BigEndian.PutUint32(raw[44:48], uint32(len(archive)))
	copy(raw[vpnSSOHeaderBytes:], archive)
	state, err := o.writeLocalState(ctx, "vpn-sso", profile.Scope, raw, profile.Source.Revision, false)
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	c := VPNSSOCheckpoint{Revision: state.RowVersion, Digest: sha256.Sum256(raw)}
	// The scope was admitted/observed at open and immediately above. Updating an
	// existing floor cannot fail after the durable commit.
	o.vpnSSOFloors[profile.Scope] = VPNSSOFloor{Checkpoint: c, RowVersion: c.Revision}
	delete(o.vpnSSOProfiles, profileID)
	return c, nil
}

// DeleteVPNSSO needs fresh authentication at its future native controller. It
// leaves an authenticated tombstone and invalidates earlier attempts by revision.
func (o *Owner) DeleteVPNSSO(ctx context.Context, binding VPNSSOBinding, expected VPNSSOCheckpoint) (VPNSSOCheckpoint, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	digest, err := binding.digest()
	if err != nil || !expected.valid() || expected.Revision == 0 {
		return VPNSSOCheckpoint{}, vault.ErrFormat
	}
	if _, err := o.vpnSSOSecurity(ctx); err != nil {
		return VPNSSOCheckpoint{}, err
	}
	err = o.withVPNSSO(ctx, digest, expected, func(current VPNSSOSnapshot) error {
		if current.Checkpoint != expected {
			return vaultstore.ErrConflict
		}
		return nil
	})
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	if expected.Deleted {
		return expected, nil
	}
	scope := vpnSSOScope(digest)
	state, err := o.writeLocalState(ctx, "vpn-sso", scope, nil, expected.Revision, true)
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	c := vpnSSOTombstone(digest, state.RowVersion)
	o.vpnSSOFloors[scope] = VPNSSOFloor{Checkpoint: c, RowVersion: c.Revision}
	return c, nil
}

func (o *Owner) CloseVPNSSO(profileID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !browserProfileID(profileID) {
		return vault.ErrFormat
	}
	var err error
	for _, stage := range o.vpnSSOTransfers {
		if stage.context.ProfileID == profileID {
			err = errors.Join(err, o.retireVPNSSOTransfer(stage))
		}
	}
	delete(o.vpnSSOProfiles, profileID)
	return err
}

// ObserveVPNSSO imports and returns a monotonic observation for the trusted
// native device anchor. Invoke before open, and again after every read/save/
// deletion outcome; persist the returned floor before releasing restored state
// or reporting a denial. A zero minimum only reads the resident floor. This API
// does not read archive bytes, grant Use or authenticate external checkpoint data.
// It remains available after a policy denial so authenticated observations can
// be anchored before shutdown; it needs neither storage access nor a weaker policy.
func (o *Owner) ObserveVPNSSO(ctx context.Context, binding VPNSSOBinding, minimum VPNSSOFloor) (VPNSSOFloor, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	digest, err := binding.digest()
	if err != nil || !minimum.Checkpoint.valid() || minimum.RowVersion < minimum.Checkpoint.Revision || minimum.RowVersion > math.MaxInt64 {
		return VPNSSOFloor{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return VPNSSOFloor{}, err
	}
	if o.closed {
		return VPNSSOFloor{}, vaultstore.ErrClosed
	}
	scope := vpnSSOScope(digest)
	return o.importVPNSSOFloor(scope, minimum)
}

// Caller holds o.mu. The source is the trusted native anchor, not a wire claim.
func (o *Owner) importVPNSSOFloor(scope string, minimum VPNSSOFloor) (VPNSSOFloor, error) {
	if !minimum.Checkpoint.valid() || minimum.RowVersion < minimum.Checkpoint.Revision || minimum.RowVersion > math.MaxInt64 {
		return VPNSSOFloor{}, vault.ErrFormat
	}
	if err := o.retainVPNSSOFloor(scope, minimum.Checkpoint); err != nil {
		return VPNSSOFloor{}, err
	}
	floor := o.vpnSSOFloors[scope]
	floor.RowVersion = max(floor.RowVersion, minimum.RowVersion)
	o.vpnSSOFloors[scope] = floor
	return floor, nil
}
