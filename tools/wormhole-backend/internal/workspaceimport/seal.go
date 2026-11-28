package workspaceimport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const maxImportCiphertextBytes = 64 * 1024 * 1024

type ImportBoundary struct {
	Manifest        vault.BoundaryManifest
	MinimumRevision uint64 // Authenticated floor from the destination owner.
}

// Authority comes from the admitted destination. The caller must hold the
// authenticated account and TLS state and supply its policy and persisted
// floors. Signatures here authenticate content and grant no PostgreSQL Write.
type Authority struct {
	Trust                     vault.UserKeyTrust
	Account                   vault.UserKeyState
	Enrollment                vault.UserEnrollmentCertificate
	MinimumEnrollmentRevision uint64
	EscrowPersonal            bool
	Personal, Shared          *ImportBoundary
}

// TunnelTransform validates the provider's settings and translates embedded
// references through resolveFallback. The returned buffer is wiped after use
// and may alias settings.
// It runs synchronously in the local owner and must never retain plaintext.
type TunnelTransform func(kind int, settings []byte, resolveFallback func(string) (string, error)) ([]byte, error)

type SealedImport struct {
	body      []byte
	signature []byte
	target    Target
	author    vault.KeyRef
}

func (SealedImport) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

// PostgresPayload returns a native write document and its detached signature.
// They include signed metadata and exclusively ciphertext for secret fields.
// Retain the same sealed document when reconciling an uncertain commit.
func (s *SealedImport) PostgresPayload() (body, signature []byte) {
	return bytes.Clone(s.body), bytes.Clone(s.signature)
}

// VerifyPostgresAuthor binds the staged document to the currently admitted
// writer before it is sent to PostgreSQL.
func (s *SealedImport) VerifyPostgresAuthor(workspace, user uuid.UUID, author vault.KeyRef, public ed25519.PublicKey) error {
	if s == nil || s.target.WorkspaceID != workspace || s.target.UserID != user || s.author != author ||
		len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, importSigningDigest(s.body), s.signature) {
		return vault.ErrAuthentication
	}
	return nil
}

type importPayload struct {
	FormatVersion uint16                 `json:"formatVersion"`
	Target        Target                 `json:"target"`
	SourceDigest  []byte                 `json:"sourceDigest"`
	Author        vault.KeyRef           `json:"author"`
	Boundaries    []boundaryReceipt      `json:"boundaries"`
	Nodes         []importNode           `json:"nodes"`
	Credentials   []importCredential     `json:"credentials"`
	Tunnels       []importTunnel         `json:"tunnels"`
	Values        []importValue          `json:"values"`
	Pins          resolver.MigrationPlan `json:"pins"`
}

type boundaryReceipt struct {
	ID       uuid.UUID `json:"id"`
	Revision uint64    `json:"revision"`
	Digest   []byte    `json:"digest"`
}

type importNode struct {
	Boundary   uuid.UUID                      `json:"boundaryId"`
	Metadata   vaultstore.NodeMetadata        `json:"metadata"`
	Seal       vault.RecordSeal               `json:"seal"`
	Fields     sharedcatalog.NodeFieldsRecord `json:"fields"`
	FieldsSeal vault.RecordSeal               `json:"fieldsSeal"`
	Imported   []byte                         `json:"imported,omitempty"`
}

type importCredential struct {
	Boundary uuid.UUID                      `json:"boundaryId"`
	Record   sharedcatalog.CredentialRecord `json:"record"`
	Seal     vault.RecordSeal               `json:"seal"`
}

type importTunnel struct {
	Boundary uuid.UUID                  `json:"boundaryId"`
	Record   sharedcatalog.TunnelRecord `json:"record"`
	Seal     vault.RecordSeal           `json:"seal"`
}

type importValue struct {
	Boundary uuid.UUID                `json:"boundaryId"`
	Binding  vault.SharedValueBinding `json:"binding"`
	Copy     vault.SignedKeyCopy      `json:"keyCopy"`
	Envelope vault.Envelope           `json:"envelope"`
}

// Seal prepares the complete import in memory. It authenticates the current
// recipient roots before reading source fields, lends plaintext only to native
// sealing, and returns nothing on failure. It does not dispatch a write.
func (p *Plan) Seal(ctx context.Context, source *localvault.Owner, authority Authority, signingSeed []byte, transform TunnelTransform) (*SealedImport, error) {
	if p == nil || ctx == nil || source == nil || len(signingSeed) != ed25519.SeedSize || (len(p.Tunnels) != 0 && transform == nil) {
		return nil, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest, err := p.preparationDigest()
	if err != nil || digest != p.digest {
		return nil, vault.ErrAuthentication
	}
	if authority.Trust.WorkspaceID != p.Target.WorkspaceID || authority.Trust.UserID != p.Target.UserID {
		return nil, vault.ErrAuthentication
	}
	if err := vault.VerifyUserEnrollmentCertificate(authority.Enrollment, authority.Account, authority.Trust, max(1, authority.MinimumEnrollmentRevision)); err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(signingSeed)
	defer vault.Wipe(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), authority.Enrollment.Rekey.Public.Signing) {
		return nil, vault.ErrAuthentication
	}
	boundaries, receipts, err := p.verifyBoundaries(authority)
	if err != nil {
		return nil, err
	}
	signer := vault.KeyRef{ID: authority.Enrollment.Rekey.SigningKeyID, Version: authority.Enrollment.Rekey.KeyVersion}
	payload := importPayload{FormatVersion: 1, Target: p.Target, SourceDigest: p.SourceFingerprint[:], Author: signer, Boundaries: receipts,
		Nodes: []importNode{}, Credentials: []importCredential{}, Tunnels: []importTunnel{}, Values: []importValue{}, Pins: p.Pins}
	if err := p.sealRecords(ctx, source, signer, private, boundaries, transform, &payload); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &SealedImport{body: body, signature: ed25519.Sign(private, importSigningDigest(body)), target: p.Target, author: signer}, nil
}

func importSigningDigest(body []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/workspace-import-write\x00"))
	hash.Write(body)
	return hash.Sum(nil)
}

func (p *Plan) verifyBoundaries(a Authority) (map[Destination]vault.BoundaryManifest, []boundaryReceipt, error) {
	needed := make(map[Destination]bool, 2)
	for _, place := range p.placements {
		needed[place.destination] = true
	}
	boundaries := make(map[Destination]vault.BoundaryManifest, len(needed))
	receipts := make([]boundaryReceipt, 0, len(needed))
	ids := make(map[uuid.UUID]bool)
	publicKeys := make(map[string]bool)
	for _, scope := range []struct {
		destination Destination
		owner       uuid.UUID
		escrow      bool
		boundary    *ImportBoundary
	}{{Personal, p.Target.UserID, a.EscrowPersonal, a.Personal}, {Shared, uuid.Nil, true, a.Shared}} {
		if !needed[scope.destination] {
			continue
		}
		if scope.boundary == nil {
			return nil, nil, vault.ErrPolicy
		}
		m := scope.boundary.Manifest
		trust := vault.BoundaryTrust{WorkspaceID: p.Target.WorkspaceID, BoundaryID: m.BoundaryID, Signer: a.Trust.Signer,
			Organisation: a.Trust.Organisation, MinimumRevision: scope.boundary.MinimumRevision}
		if err := vault.VerifyBoundaryManifest(m, trust); err != nil {
			return nil, nil, err
		}
		if !m.Active || m.OwnerUserID != scope.owner || m.OrgEscrow != scope.escrow || ids[m.BoundaryID] {
			return nil, nil, vault.ErrPolicy
		}
		ids[m.BoundaryID] = true
		// Previous roots of this boundary may share the current root's ID by
		// design. Nothing may reuse an ID or key from a different boundary.
		rootIDs := make(map[uuid.UUID]bool)
		for _, root := range []*vault.BoundaryKey{&m.View, &m.Secret, m.PreviousView, m.PreviousSecret} {
			if root == nil {
				continue
			}
			public := string(root.Public)
			if publicKeys[public] || ids[root.Key.ID] {
				return nil, nil, vault.ErrPolicy
			}
			publicKeys[public], rootIDs[root.Key.ID] = true, true
		}
		for id := range rootIDs {
			ids[id] = true
		}
		raw, err := vault.EncodeBoundaryManifest(m)
		if err != nil {
			return nil, nil, err
		}
		digest := sha256.Sum256(raw)
		receipts = append(receipts, boundaryReceipt{m.BoundaryID, m.Revision, digest[:]})
		boundaries[scope.destination] = m
	}
	return boundaries, receipts, nil
}

func (p *Plan) sealRecords(ctx context.Context, source *localvault.Owner, signer vault.KeyRef, private ed25519.PrivateKey,
	boundaries map[Destination]vault.BoundaryManifest, transform TunnelTransform, result *importPayload) error {
	byTarget := make(map[string]vault.BoundaryManifest, len(p.placements))
	for _, place := range p.placements {
		byTarget[place.id] = boundaries[place.destination]
	}
	tunnels := make(map[string]int, len(p.Tunnels))
	for _, tunnel := range p.Tunnels {
		tunnels[tunnel.ID] = tunnel.Kind
	}
	fields := make(map[string][]vaultstore.CredentialField)
	notes := make(map[string]bool)
	remaining := maxImportCiphertextBytes
	err := source.WithWorkspaceImportSecrets(ctx, p.SourceFingerprint, func(ref vaultstore.SecretRef, value []byte) error {
		place, ok := p.placements[ItemID{Kind: ref.OwnerKind, ID: ref.OwnerID}]
		if !ok {
			return vault.ErrAuthentication
		}
		boundary := byTarget[place.id]
		if ref.OwnerKind == "tunnel" {
			mapped, err := transform(tunnels[place.id], value, func(fallback string) (string, error) {
				destination, available := p.placements[ItemID{Kind: "tunnel", ID: fallback}]
				if !available || tunnels[destination.id] != 2 || (place.destination == Shared && destination.destination == Personal) {
					return "", vault.ErrPolicy
				}
				return destination.id, nil
			})
			defer vault.Wipe(mapped)
			if err != nil {
				return err
			}
			if len(mapped) == 0 {
				return vault.ErrFormat
			}
			value = mapped
		}
		if len(value)+16 > remaining {
			return vault.ErrFormat
		}
		remaining -= len(value) + 16
		binding := vault.SharedValueBinding{WorkspaceID: p.Target.WorkspaceID, OwnerKind: ref.OwnerKind,
			OwnerID: uuid.MustParse(place.id), Field: ref.Field, Version: 1, DEK: vault.KeyRef{ID: uuid.New(), Version: 1}}
		var dek [32]byte
		rand.Read(dek[:])
		defer vault.Wipe(dek[:])
		envelope, err := vault.SealSharedValue(dek[:], binding, value)
		if err != nil {
			return err
		}
		isNote := ref.OwnerKind == "node" && ref.Field == "notes"
		holder := boundary.Secret
		if isNote {
			holder = boundary.View
		}
		copy, err := vault.SealKeyCopy(dek[:], vault.KeyCopyBinding{WorkspaceID: binding.WorkspaceID, Key: binding.DEK,
			Holder: holder.Key, Issuer: signer}, holder.Public, private[:ed25519.SeedSize])
		if err != nil {
			return err
		}
		result.Values = append(result.Values, importValue{boundary.BoundaryID, binding, copy, envelope})
		// Note values never enter the inline credential release manifest.
		if ref.OwnerKind == "credential" || ref.Field == "inlinePassword" {
			fields[place.id] = append(fields[place.id], vaultstore.CredentialField{Field: ref.Field, Version: 1, Present: true})
		}
		if isNote {
			notes[place.id] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	retained := make(map[string][]resolver.EffectiveCredentialSnapshot)
	for _, pin := range p.Pins.Entries {
		if pin.Choice == "keep" {
			retained[pin.Legacy.NodeID] = append(retained[pin.Legacy.NodeID], pin.Legacy)
		}
	}
	for _, metadata := range p.Nodes {
		var imported []byte
		if pins := retained[metadata.ID]; notes[metadata.ID] || len(pins) != 0 {
			data := NodeData{FormatVersion: legacyNodeDataFormat, NodeID: metadata.ID, Pins: append([]resolver.EffectiveCredentialSnapshot{}, pins...)}
			if notes[metadata.ID] {
				data.FormatVersion, data.NoteVersion = viewKeyNoteFormat, 1
			}
			var err error
			imported, err = json.Marshal(data)
			if err != nil {
				return err
			}
			if len(imported) > MaxNodeDataBytes {
				return vault.ErrFormat
			}
			digest := sha256.Sum256(imported)
			metadata.Imported = &vaultstore.NodeImportReference{Digest: hex.EncodeToString(digest[:]), RetainedPins: len(pins) != 0, NoteVersion: data.NoteVersion}
		}
		boundary := byTarget[metadata.ID].BoundaryID
		seal, err := sharedcatalog.SignNode(p.Target.WorkspaceID, boundary, metadata, 1, signer, private)
		if err != nil {
			return err
		}
		manifest := sharedcatalog.NodeFieldsRecord{NodeID: metadata.ID, Fields: append([]vaultstore.CredentialField{}, fields[metadata.ID]...)}
		fieldSeal, err := sharedcatalog.SignSelection(p.Target.WorkspaceID, boundary, manifest, 1, signer, private)
		if err != nil {
			return err
		}
		result.Nodes = append(result.Nodes, importNode{boundary, metadata, seal, manifest, fieldSeal, imported})
	}
	for _, metadata := range p.Credentials {
		boundary := byTarget[metadata.ID].BoundaryID
		manifest := append([]vaultstore.CredentialField{}, fields[metadata.ID]...)
		sort.Slice(manifest, func(i, j int) bool { return manifest[i].Field < manifest[j].Field })
		record := sharedcatalog.CredentialRecord{Metadata: metadata, Fields: manifest}
		seal, err := sharedcatalog.SignCredential(p.Target.WorkspaceID, boundary, record, 1, signer, private)
		if err != nil {
			return err
		}
		result.Credentials = append(result.Credentials, importCredential{boundary, record, seal})
	}
	for _, metadata := range p.Tunnels {
		boundary := byTarget[metadata.ID].BoundaryID
		record := sharedcatalog.TunnelRecord{Metadata: metadata, ConfigurationVersion: 1}
		seal, err := sharedcatalog.SignSelection(p.Target.WorkspaceID, boundary, record, 1, signer, private)
		if err != nil {
			return err
		}
		result.Tunnels = append(result.Tunnels, importTunnel{boundary, record, seal})
	}
	return ctx.Err()
}
