package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

const beginNoteViewSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,expires_at::text
 FROM wormhole_api_v1.begin_note_view(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint)`

const fetchNoteSQL = `SELECT workspace_id::text,user_id::text,device_id::text,node_id::text,
 ticket_id::text,epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.fetch_note(pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid)`

const noteViewAvailableSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.begin_note_view(bytea,uuid,bigint)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.fetch_note(bytea,uuid,uuid)') IS NOT NULL)::text`

const maxNoteViewBytes = 1024 * 1024
const maxNoteEnvelopeBytes = 90_000

func (s *Session) NoteViewSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, noteViewAvailableSQL)
}

type NoteViewIntent struct {
	use      UseIntent
	revision uint64
}

// A stale selection or missing View grant is an expected denial. SQL returns
// no receipt and makes no audit or ticket mutation for those cases.
func (s *Session) BeginNoteView(ctx context.Context, node uuid.UUID, revision uint64) (*NoteViewIntent, error) {
	if ctx == nil || node == uuid.Nil || revision == 0 || revision > math.MaxInt64 {
		return nil, ErrConfiguration
	}
	var intent *NoteViewIntent
	err := s.beginUseOperation(ctx, beginNoteViewSQL, [][]byte{nil, []byte(node.String()), strconv.AppendUint(nil, revision, 10)}, func(rows [][][]byte) error {
		if len(rows) == 0 {
			return nil
		}
		use, e := parseUseIntent(rows, s.admission, node)
		if e == nil {
			intent = &NoteViewIntent{use: *use, revision: revision}
		}
		return e
	})
	return intent, err
}

// FetchNote consumes a committed note-view ticket. The response contains only
// the selected node's note ciphertext and its verification material.
func (s *Session) FetchNote(ctx context.Context, intent *NoteViewIntent) (*UnverifiedNoteView, error) {
	if ctx == nil || intent == nil || intent.use.Ticket == uuid.Nil || intent.revision == 0 {
		return nil, ErrConfiguration
	}
	var result *UnverifiedNoteView
	err := s.queryConnection(ctx, intent.use.Node, fetchNoteSQL, [][]byte{[]byte(intent.use.Ticket.String())}, maxNoteViewBytes, 8,
		func(rows [][][]byte, request AdmissionRequest) error {
			payload, err := secretReleasePayload(rows, request, intent.use)
			if err != nil {
				return err
			}
			result, err = DecodeNoteView(payload, request, intent.use.Node, intent.revision, intent.use.Epoch, intent.use.ChangeSeq)
			return err
		})
	if err != nil {
		return nil, err
	}
	return result, nil
}

type noteViewWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	Node          json.RawMessage `json:"node"`
	Attachment    *string         `json:"attachment"`
	Profile       string          `json:"profile"`
	Account       json.RawMessage `json:"account"`
	Enrollment    string          `json:"enrollment"`
	Boundary      json.RawMessage `json:"boundary"`
	Root          json.RawMessage `json:"root"`
	DEK           json.RawMessage `json:"dek"`
	Value         json.RawMessage `json:"value"`
}

type UnverifiedNoteView struct {
	nodeData   *UnverifiedImportedNodeData
	revision   uint64
	runtime    *UnverifiedRuntimeState
	enrollment vault.UserEnrollmentCertificate
	material   *noteMaterial
}

type noteMaterial struct {
	manifest vault.BoundaryManifest
	root     UnverifiedKeyCopy
	dek      UnverifiedKeyCopy
	value    UnverifiedSharedValue
}

// DecodeNoteView decodes a snapshot-bound native response. It neither grants
// View nor authenticates its contents. Only an audited owner may open a view.
func DecodeNoteView(raw []byte, request AdmissionRequest, id uuid.UUID, revision, epoch, sequence uint64) (*UnverifiedNoteView, error) {
	if len(raw) == 0 || len(raw) > maxNoteViewBytes {
		return nil, ErrAdmissionResponse
	}
	var wire noteViewWire
	if _, err := strictCatalogObject(raw, wire, "attachment", "boundary", "root", "dek", "value"); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &wire) != nil || wire.FormatVersion != 1 || len(wire.Enrollment) == 0 ||
		len(wire.Enrollment) > 2*vault.MaxUserEnrollmentCertificateBytes {
		return nil, ErrAdmissionResponse
	}
	row, err := snapshotOptionalRow(wire.Node, 24)
	if err != nil || row == nil {
		return nil, ErrAdmissionResponse
	}
	var attachment []byte
	if wire.Attachment != nil {
		attachment = []byte(*wire.Attachment)
	}
	node, err := parseImportedNodeProjection(row, attachment, request, id, epoch, sequence)
	if err != nil || node.record.Node.Seal.Revision != revision {
		return nil, ErrAdmissionResponse
	}
	runtime, err := parseRuntimeMaterial(wire.Profile, wire.Account, request)
	if err != nil {
		return nil, err
	}
	enrollmentRaw, err := hex.DecodeString(wire.Enrollment)
	if err != nil {
		return nil, ErrAdmissionResponse
	}
	enrollment, err := vault.DecodeUserEnrollmentCertificate(enrollmentRaw)
	if err != nil || enrollment.Manifest.Context.WorkspaceID != request.WorkspaceID || enrollment.Manifest.Context.UserID != request.UserID {
		return nil, ErrAdmissionResponse
	}
	scope := UseIntent{Node: id, Epoch: epoch, ChangeSeq: sequence}
	material, err := parseNoteMaterial(wire, request, scope, node.record.Node.Boundary,
		vault.KeyRef{ID: enrollment.Rekey.EncryptionKeyID, Version: enrollment.Rekey.KeyVersion})
	if err != nil {
		return nil, err
	}
	return &UnverifiedNoteView{nodeData: node, revision: revision, runtime: runtime, enrollment: enrollment, material: material}, nil
}

func parseNoteMaterial(wire noteViewWire, request AdmissionRequest, scope UseIntent, boundary uuid.UUID, holder vault.KeyRef) (*noteMaterial, error) {
	manifestRow, e1 := snapshotOptionalRow(wire.Boundary, 9)
	rootMissing := bytes.Equal(bytes.TrimSpace(wire.Root), []byte("null"))
	dekRow, e3 := snapshotOptionalRow(wire.DEK, 24)
	valueRow, e4 := snapshotOptionalRow(wire.Value, 9)
	if e1 != nil || e3 != nil || e4 != nil {
		return nil, ErrAdmissionResponse
	}
	if manifestRow == nil && rootMissing && dekRow == nil && valueRow == nil {
		return nil, nil
	}
	if manifestRow == nil || rootMissing || dekRow == nil || valueRow == nil || len(valueRow[8]) > 2*maxNoteEnvelopeBytes {
		return nil, ErrAdmissionResponse
	}
	manifest, err := parseBoundaryProjection([][][]byte{manifestRow}, request, boundary, scope.Epoch, scope.ChangeSeq)
	if err != nil {
		return nil, err
	}
	values, err := parseManifestValues([][][]byte{valueRow}, request, "node", scope.Node,
		[]vaultstore.CredentialField{{Field: "notes", Version: 1, Present: true}}, scope.Epoch, scope.ChangeSeq)
	if err != nil {
		return nil, err
	}
	key, err := releaseKeyRef(dekRow, 5)
	if err != nil || key.ID == values[0].Binding.DEK.ID || key.ID == holder.ID {
		return nil, ErrAdmissionResponse
	}
	root, err := parseBoundaryRootCopy(wire.Root, request, key, holder, scope.Epoch, scope.ChangeSeq, 24)
	if err != nil {
		return nil, err
	}
	dek, err := parseKeyCopyProjection([][][]byte{dekRow}, request, values[0].Binding.DEK, key, scope.Epoch, scope.ChangeSeq)
	if err != nil {
		return nil, err
	}
	return &noteMaterial{manifest: *manifest, root: *root, dek: *dek, value: values[0]}, nil
}

type VerifiedNoteView struct {
	material *noteMaterial
	purpose  vault.BoundaryPurpose
	trust    TrustState
	used     atomic.Bool
}

// VerifyNoteView authenticates the workspace policy, current enrollment,
// node seal, note reference and key-copy issuers before any key is opened.
// Publish nonzero observations durably even when verification reports an error.
func (s TrustState) VerifyNoteView(ctx context.Context, node uuid.UUID, revision uint64, v *UnverifiedNoteView) (observed TrustState, verified *VerifiedNoteView, err error) {
	if ctx == nil || v == nil || v.nodeData == nil || node == uuid.Nil || revision == 0 || v.revision != revision || s.Enrollment == nil {
		return TrustState{}, nil, ErrConfiguration
	}
	observed = s
	changed := false
	advance := func(next TrustState, e error) error {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
		if changed && s.Revision == math.MaxUint64 {
			return ErrTrustState
		}
		return e
	}
	defer func() {
		if changed && s.Revision != math.MaxUint64 {
			observed.Revision++
		}
		if verified != nil {
			verified.trust = cloneTrustState(observed)
		}
	}()
	if err = advance(s.VerifyRuntimeState(ctx, v.runtime)); err != nil {
		return observed, nil, err
	}
	if err = advance(observed.AdvanceEnrollment(v.enrollment, observed.WrappingRevision)); err != nil {
		return observed, nil, err
	}
	if err = advance(observed.verifyImportedNodeProjection(node, v.nodeData)); err != nil {
		return observed, nil, err
	}
	purpose, noteVersion, err := noteBinding(v.nodeData)
	if err != nil {
		return observed, nil, err
	}
	m := v.material
	if (purpose == "") != (m == nil) {
		return observed, nil, ErrAdmissionResponse
	}
	if m != nil {
		if err = advance(observed.AdvanceBoundary(v.nodeData.record.Node.Boundary, m.manifest)); err != nil {
			return observed, nil, err
		}
		current, previous := m.manifest.View, m.manifest.PreviousView
		if purpose == vault.BoundarySecret {
			current, previous = m.manifest.Secret, m.manifest.PreviousSecret
		}
		if m.root.Binding.Key != current.Key && (previous == nil || m.root.Binding.Key != previous.Key) ||
			m.root.boundaryRecipient() != observed.Enrollment.Encryption || m.value.Binding.Version != noteVersion {
			return observed, nil, vault.ErrAuthentication
		}
		if err = advance(observed.advanceBoundaryRootCopy(m.root)); err != nil {
			return observed, nil, err
		}
		if err = advance(observed.AdvanceKeyCopy(m.dek.Binding, m.dek.Copy, m.dek.Author)); err != nil {
			return observed, nil, err
		}
	}
	authors := map[uuid.UUID]uint64{s.UserID: v.runtime.account.Sequence}
	records := []*UnverifiedNodeAuthor{&v.nodeData.record.Author}
	if m != nil {
		records = append(records, m.root.Author, m.dek.Author)
	}
	for _, author := range records {
		if author != nil {
			a := author.State
			if seq, ok := authors[a.UserID]; ok && seq != a.Sequence {
				return observed, nil, ErrTreeSnapshotChanged
			}
			authors[a.UserID] = a.Sequence
		}
	}
	if err = ctx.Err(); err != nil {
		return observed, nil, err
	}
	if !observed.Account.Active || observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		return observed, nil, vault.ErrAuthentication
	}
	return observed, &VerifiedNoteView{material: m, purpose: purpose}, nil
}

func noteBinding(node *UnverifiedImportedNodeData) (vault.BoundaryPurpose, uint64, error) {
	meta := node.record.Node.Metadata
	if meta.Imported != nil && meta.Imported.NoteVersion != 0 {
		if node.body != nil {
			return "", 0, ErrAdmissionResponse
		}
		return vault.BoundaryView, meta.Imported.NoteVersion, nil
	}
	data, err := workspaceimport.DecodeNodeData(meta, node.body)
	if err != nil || data == nil {
		return "", 0, err
	}
	return data.NotePurpose(), data.NoteVersion, nil
}

// WithValue borrows the note once, after the owner commits the authenticated
// state. Plaintext and the temporary root key are wiped when the callback returns.
func (v *VerifiedNoteView) WithValue(ctx context.Context, committed TrustState, private []byte, use func([]byte) error) error {
	if ctx == nil || v == nil || len(private) != 32 || use == nil {
		return ErrConfiguration
	}
	if !committed.valid() || !reflect.DeepEqual(committed, v.trust) || !committed.Account.Active {
		return ErrTrustState
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !v.used.CompareAndSwap(false, true) {
		return ErrUseTicket
	}
	m := v.material
	if m == nil {
		return use(nil)
	}
	pin, err := committed.accountTrust()
	if err != nil {
		return err
	}
	trust := vault.BoundaryTrust{WorkspaceID: committed.WorkspaceID, BoundaryID: m.manifest.BoundaryID,
		Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: committed.Catalog["boundary/"+m.manifest.BoundaryID.String()].Revision}
	issuer := func(copy UnverifiedKeyCopy) vault.KeyCopyTrust {
		public := pin.Organisation
		if copy.Author != nil {
			public = copy.Author.signingPublic()
		}
		return vault.KeyCopyTrust{Issuer: copy.Binding.Issuer, Public: public}
	}
	root, err := openBoundaryReleaseRoot(private, m.root, issuer(m.root), m.manifest, trust, v.purpose, committed)
	if err != nil {
		return err
	}
	defer vault.Wipe(root)
	open := vault.OpenSharedNote
	if v.purpose == vault.BoundarySecret {
		open = vault.OpenSharedValue
	}
	note, err := open(root, m.root.Binding.Key, m.value.Binding, m.dek.Copy, issuer(m.dek), m.value.Envelope, m.manifest, trust)
	if err != nil {
		return err
	}
	defer vault.Wipe(note)
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(note)
}
