package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func nodeMAC(key []byte, identity vaultstore.Identity, node vaultstore.Node) ([]byte, error) {
	subkey, err := vault.DeriveKey(key, []byte(identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	node.Seal = nil
	body, err := json.Marshal(struct {
		Identity vaultstore.Identity `json:"identity"`
		Node     vaultstore.Node     `json:"node"`
	}{identity, node})
	if err != nil {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-node\x00"))
	mac.Write(body)
	return mac.Sum(nil), nil
}

func (o *Owner) verifyNode(n vaultstore.Node) error {
	if n.Validate() != nil {
		return vault.ErrFormat
	}
	root := o.store.Identity().Root
	if n.SealSignerKeyID != root.ID || n.SealSignerKeyVersion != root.Version {
		return vault.ErrAuthentication
	}
	return o.root.With(func(key []byte) error {
		mac, err := nodeMAC(key, o.store.Identity(), n)
		if err != nil {
			return err
		}
		if !hmac.Equal(mac, n.Seal) {
			return vault.ErrAuthentication
		}
		if o.vpnSSOObservingNodes {
			if o.vpnSSONodeFloors == nil {
				o.vpnSSONodeFloors = make(map[string]uint64)
			}
			o.nodeFloors[n.ID] = max(o.nodeFloors[n.ID], n.RowVersion)
			o.vpnSSONodeFloors[n.ID] = max(o.vpnSSONodeFloors[n.ID], o.nodeFloors[n.ID])
		}
		return nil
	})
}

func (o *Owner) nodeStore() (vaultstore.NodeStore, error) {
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	s, ok := o.store.(vaultstore.NodeStore)
	if !ok {
		return nil, vaultstore.ErrStorage
	}
	return s, nil
}

func (o *Owner) ReadNode(ctx context.Context, id string, minimum uint64) (vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return vaultstore.Node{}, err
	}
	n, err := s.ReadNode(ctx, id)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if n.ID != id {
		return vaultstore.Node{}, vault.ErrAuthentication
	}
	if err := o.verifyNode(n); err != nil {
		return vaultstore.Node{}, err
	}
	if n.RowVersion < minimum {
		return vaultstore.Node{}, vault.ErrRollback
	}
	if n.Deleted {
		return vaultstore.Node{}, vaultstore.ErrMissing
	}
	return n, nil
}

func (o *Owner) ListNodes(ctx context.Context, after string, limit int) ([]vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return nil, err
	}
	values, err := s.ListNodes(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	for _, n := range values {
		if err := o.verifyNode(n); err != nil {
			return nil, err
		}
		if n.Deleted {
			return nil, vault.ErrAuthentication
		}
	}
	return values, nil
}

func (o *Owner) PutNode(ctx context.Context, metadata vaultstore.NodeMetadata, changes []SecretChange, expected uint64) (vaultstore.Node, error) {
	return o.putNode(ctx, metadata, changes, expected, nil)
}

// ImportNode only creates an absent node. Import parents and referenced
// credentials/tunnels first; reserved migration choices use their own API.
func (o *Owner) ImportNode(ctx context.Context, metadata vaultstore.NodeMetadata, changes []SecretChange, times ImportTimes) (vaultstore.Node, error) {
	return o.putNode(ctx, metadata, changes, 0, &times)
}

func (o *Owner) putNode(ctx context.Context, metadata vaultstore.NodeMetadata, changes []SecretChange, expected uint64, times *ImportTimes) (vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, change := range changes {
		if !vaultstore.NodeEditableField(change.Field) {
			return vaultstore.Node{}, vault.ErrFormat
		}
	}
	return o.writeNode(ctx, metadata, changes, expected, false, times)
}

// DeleteNode removes one leaf or empty folder. A subtree operation must supply
// an atomic multi-node change; callers must never emulate it with partial deletes.
func (o *Owner) DeleteNode(ctx context.Context, id string, expected uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.writeNode(ctx, vaultstore.NodeMetadata{ID: id}, nil, expected, true, nil)
	return err
}

// ValidNodeNotes applies the stored note contract without converting plaintext
// into an immutable string. Native migration uses the same bounds as edits.
func ValidNodeNotes(value []byte) bool {
	if len(value) > 65536 || !utf8.Valid(value) {
		return false
	}
	units := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == 0 {
			return false
		}
		value = value[size:]
		units++
		if r > 0xffff {
			units++
		}
		if units > 16384 {
			return false
		}
	}
	return true
}

func (o *Owner) writeNode(ctx context.Context, metadata vaultstore.NodeMetadata, changes []SecretChange, expected uint64, deleted bool, importedTimes *ImportTimes) (vaultstore.Node, error) {
	s, err := o.nodeStore()
	if err != nil {
		return vaultstore.Node{}, err
	}
	if expected >= math.MaxInt64 || len(changes) > 3 {
		return vaultstore.Node{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vaultstore.Node{}, err
	}
	old, err := s.ReadNode(ctx, metadata.ID)
	if errors.Is(err, vaultstore.ErrMissing) {
		if expected != 0 || deleted {
			return vaultstore.Node{}, vaultstore.ErrConflict
		}
	} else if err != nil {
		return vaultstore.Node{}, err
	} else {
		if old.ID != metadata.ID {
			return vaultstore.Node{}, vault.ErrAuthentication
		}
		if err := o.verifyNode(old); err != nil {
			return vaultstore.Node{}, err
		}
		if old.RowVersion < o.nodeFloors[old.ID] {
			return vaultstore.Node{}, vault.ErrRollback
		}
		if old.RowVersion != expected || old.Deleted {
			return vaultstore.Node{}, vaultstore.ErrConflict
		}
	}
	if deleted {
		metadata = old.NodeMetadata
		for _, f := range old.Fields {
			if f.Present {
				changes = append(changes, SecretChange{Field: f.Field, Remove: true})
			}
		}
	}
	if metadata.Validate() != nil {
		return vaultstore.Node{}, vault.ErrFormat
	}
	if !deleted {
		if err := o.verifyNodeReferences(ctx, s, metadata); err != nil {
			return vaultstore.Node{}, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	root := s.Identity().Root
	value := vaultstore.Node{NodeMetadata: metadata, CreatedAt: old.CreatedAt, UpdatedAt: now, RowVersion: expected + 1, Deleted: deleted, Fields: append([]vaultstore.SecretField{}, old.Fields...), SealSuite: vaultstore.NodeSealHMACSHA256, SealSignerKeyID: root.ID, SealSignerKeyVersion: root.Version, Seal: make([]byte, 32)}
	if expected == 0 {
		value.CreatedAt = now
	}
	if importedTimes != nil {
		value.CreatedAt, value.UpdatedAt = importedTimes.CreatedAt, importedTimes.UpdatedAt
	}
	fields := make(map[string]vaultstore.SecretField, len(value.Fields))
	for _, f := range value.Fields {
		fields[f.Field] = f
	}
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		previous := fields[change.Field]
		if !vaultstore.NodeSecretField(change.Field) || seen[change.Field] || len(change.Value) > vault.MaxSecretBytes || (change.Remove && (len(change.Value) != 0 || !previous.Present)) || previous.Version >= math.MaxInt64 || (change.Field == "notes" && !ValidNodeNotes(change.Value)) {
			return vaultstore.Node{}, vault.ErrFormat
		}
		seen[change.Field] = true
		fields[change.Field] = vaultstore.SecretField{Field: change.Field, Version: previous.Version + 1, Present: !change.Remove}
	}
	value.Fields = value.Fields[:0]
	for _, f := range fields {
		value.Fields = append(value.Fields, f)
	}
	sort.Slice(value.Fields, func(i, j int) bool { return value.Fields[i].Field < value.Fields[j].Field })
	if value.Validate() != nil {
		return vaultstore.Node{}, vault.ErrFormat
	}
	secrets := make([]vaultstore.Secret, 0, len(changes))
	for _, change := range changes {
		secret, err := o.prepareSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: metadata.ID, Field: change.Field}, change.Value, fields[change.Field].Version-1)
		if err != nil {
			return vaultstore.Node{}, err
		}
		secrets = append(secrets, secret)
	}
	err = o.root.With(func(key []byte) error { var err error; value.Seal, err = nodeMAC(key, s.Identity(), value); return err })
	if err != nil {
		return vaultstore.Node{}, err
	}
	if err := s.WriteNode(ctx, value, secrets, expected); err != nil {
		return vaultstore.Node{}, err
	}
	o.nodeFloors[value.ID] = value.RowVersion
	return value, nil
}

// Authenticate dependencies before signing a new routing choice. SQLite repeats
// structural checks in the write transaction; the owner lock/exclusive connection
// prevents a different in-process writer between these reads and that transaction.
func (o *Owner) verifyNodeReferences(ctx context.Context, s vaultstore.NodeStore, n vaultstore.NodeMetadata) error {
	seen := map[string]bool{n.ID: true}
	parent := n.ParentID
	depth := 1
	for parent != nil {
		if seen[*parent] || depth >= vaultstore.MaxNodeDepth {
			return vaultstore.ErrConflict
		}
		seen[*parent] = true
		depth++
		ancestor, err := s.ReadNode(ctx, *parent)
		if err != nil {
			return err
		}
		if ancestor.ID != *parent {
			return vault.ErrAuthentication
		}
		if err := o.verifyNode(ancestor); err != nil {
			return err
		}
		if ancestor.Deleted || ancestor.Kind != 0 {
			return vaultstore.ErrConflict
		}
		parent = ancestor.ParentID
	}
	if n.TunnelConfigID != nil {
		tunnels, ok := o.store.(vaultstore.TunnelStore)
		if !ok {
			return vaultstore.ErrStorage
		}
		tunnel, err := tunnels.ReadTunnel(ctx, *n.TunnelConfigID)
		if err != nil {
			return err
		}
		if tunnel.ID != *n.TunnelConfigID {
			return vault.ErrAuthentication
		}
		if err := o.verifyTunnel(tunnel); err != nil {
			return err
		}
		if tunnel.Deleted {
			return vaultstore.ErrConflict
		}
	}
	for _, id := range []*string{n.CredentialID, n.RDPGatewayCredentialID} {
		if id == nil {
			continue
		}
		credentials, ok := o.store.(vaultstore.CredentialStore)
		if !ok {
			return vaultstore.ErrStorage
		}
		credential, err := credentials.ReadCredential(ctx, *id)
		if err != nil {
			return err
		}
		if credential.ID != *id {
			return vault.ErrAuthentication
		}
		if err := o.verifyCredential(credential); err != nil {
			return err
		}
		if credential.Deleted {
			return vaultstore.ErrConflict
		}
	}
	return nil
}

// Authorization must cover the complete resolution chain before this callback.
// Notes require View; inline passwords require the resolved connection's Use.
func (o *Owner) WithNodeField(ctx context.Context, id, field string, minimum uint64, use func([]byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return err
	}
	if !vaultstore.NodeEditableField(field) || use == nil {
		return vault.ErrFormat
	}
	n, err := s.ReadNode(ctx, id)
	if err != nil {
		return err
	}
	if n.ID != id {
		return vault.ErrAuthentication
	}
	if err := o.verifyNode(n); err != nil {
		return err
	}
	if n.RowVersion < minimum {
		return vault.ErrRollback
	}
	if n.Deleted {
		return vaultstore.ErrMissing
	}
	for _, f := range n.Fields {
		if f.Field == field && f.Present {
			return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: id, Field: field}, f.Version, true, use)
		}
	}
	return vaultstore.ErrMissing
}
