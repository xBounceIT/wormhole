package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const webSessionArchiveMagic = "WWS1"
const webSessionHeaderBytes = len(webSessionArchiveMagic) + sha256.Size
const indexedWebSessionMagic = "WWS2"
const indexedWebSessionHeaderBytes = webSessionHeaderBytes + 4*16
const sharedWebSessionMagic = "WWS3"
const sharedWebSessionHeaderBytes = indexedWebSessionHeaderBytes + 16

// WebSessionBinding comes from native admission and the verified browser plan.
// It omits transient browser or SOCKS endpoints, so a reconnect can safely use
// the same archive when the authenticated endpoint and route are unchanged.
type WebSessionBinding struct {
	WorkspaceID, FileID, AccountID, NodeID string
	Protocol, Host                         string
	Port                                   uint16
	IgnoreCertificateErrors                bool
	TunnelID                               string
	TunnelKind                             uint16
	TunnelRevision, ConfigurationVersion   uint64
	ViewGeneration                         string `json:",omitempty"`
}

func (b WebSessionBinding) scope() (string, error) {
	for _, id := range []string{b.WorkspaceID, b.FileID, b.AccountID, b.NodeID} {
		if !browserProfileID(id) {
			return "", vault.ErrFormat
		}
	}
	// Each device/account has one archive per node. A new target or route
	// invalidates its previous contents without resetting the CAS revision.
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("wormhole/v1/web-session/"+b.WorkspaceID+"/"+b.FileID+"/"+b.AccountID+"/"+b.NodeID)).String(), nil
}

func (b WebSessionBinding) digest() ([32]byte, error) {
	if b.ViewGeneration != "" && !browserProfileID(b.ViewGeneration) {
		return [32]byte{}, vault.ErrFormat
	}
	if (b.Protocol != "http" && b.Protocol != "https") || b.Host == "" || len(b.Host) > 1024 ||
		b.Port == 0 || strings.IndexFunc(b.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 ||
		(b.Protocol == "http" && b.IgnoreCertificateErrors) {
		return [32]byte{}, vault.ErrFormat
	}
	if b.TunnelID == "" {
		if b.TunnelKind != 0 || b.TunnelRevision != 0 || b.ConfigurationVersion != 0 {
			return [32]byte{}, vault.ErrFormat
		}
	} else if !browserProfileID(b.TunnelID) || b.TunnelKind > 9 || b.ConfigurationVersion == 0 ||
		b.TunnelRevision < b.ConfigurationVersion || b.TunnelRevision > math.MaxInt64 {
		return [32]byte{}, vault.ErrFormat
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, vault.ErrFormat
	}
	return sha256.Sum256(append([]byte("wormhole/v1/web-session-binding\x00"), raw...)), nil
}

func (b WebSessionBinding) Fingerprint() ([32]byte, error) {
	if _, err := b.scope(); err != nil {
		return [32]byte{}, err
	}
	return b.digest()
}

// WithWebSessionState lends authenticated archive bytes only to a synchronous
// native consumer. An empty result includes the current revision so that a
// replacement cannot overwrite a more recent checkpoint.
func (o *Owner) WithWebSessionState(ctx context.Context, b WebSessionBinding, use func(uint64, []byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil || use == nil {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, err := b.scope()
	if err != nil {
		return err
	}
	digest, err := b.digest()
	if err != nil {
		return err
	}
	state, err := o.readLocalState(ctx, vaultstore.LocalStateWebSession, scope)
	if errors.Is(err, vaultstore.ErrMissing) {
		return use(0, nil)
	}
	if err != nil {
		return err
	}
	if state.Deleted {
		return use(state.RowVersion, nil)
	}
	if state.Size <= webSessionHeaderBytes || state.Size > sharedWebSessionHeaderBytes+vault.MaxWebSessionArchiveBytes {
		return vault.ErrAuthentication
	}
	return o.withLocalStateChunks(ctx, state, func(payload []byte) error {
		header, err := parseWebSessionHeader(payload, state)
		if err != nil {
			return err
		}
		if !bytes.Equal(header.digest, digest[:]) {
			return use(state.RowVersion, nil)
		}
		if (header.generation != uuid.Nil || b.ViewGeneration != "") && header.generation.String() != b.ViewGeneration {
			return vault.ErrAuthentication
		}
		return use(state.RowVersion, payload[header.size:])
	})
}

func (o *Owner) SaveWebSessionState(ctx context.Context, b WebSessionBinding, expected uint64, archive []byte) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil || len(archive) == 0 || len(archive) > vault.MaxWebSessionArchiveBytes {
		return 0, vault.ErrFormat
	}
	scope, err := b.scope()
	if err != nil {
		return 0, err
	}
	digest, err := b.digest()
	if err != nil {
		return 0, err
	}
	magic, size := indexedWebSessionMagic, indexedWebSessionHeaderBytes
	if b.ViewGeneration != "" {
		magic, size = sharedWebSessionMagic, sharedWebSessionHeaderBytes
	}
	payload := make([]byte, 0, size+len(archive))
	payload = append(payload, magic...)
	payload = append(payload, digest[:]...)
	// The scope check already validated these coordinates.
	for _, value := range []string{b.WorkspaceID, b.FileID, b.AccountID, b.NodeID} {
		id := uuid.MustParse(value)
		payload = append(payload, id[:]...)
	}
	if b.ViewGeneration != "" {
		generation := uuid.MustParse(b.ViewGeneration)
		payload = append(payload, generation[:]...)
	}
	payload = append(payload, archive...)
	defer vault.Wipe(payload)
	state, err := o.writeLocalState(ctx, vaultstore.LocalStateWebSession, scope, payload, expected, false)
	return state.RowVersion, err
}

// ForgetWebSessionState erases a node's previous route state as well as its
// current route state. The native caller chooses the scope from authenticated
// account/device identity.
func (o *Owner) ForgetWebSessionState(ctx context.Context, b WebSessionBinding, expected uint64) (uint64, error) {
	if ctx == nil {
		return 0, vault.ErrFormat
	}
	scope, err := b.scope()
	if err != nil {
		return 0, err
	}
	state, err := o.DeleteLocalState(ctx, vaultstore.LocalStateWebSession, scope, expected)
	return state.RowVersion, err
}
