package sharedcatalog

import (
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestNodeFieldsManifestSignatureScopeAndTombstones(t *testing.T) {
	_, _, cert, state, pin, key := credentialFixture(t)
	r := NodeFieldsRecord{NodeID: uuid.NewString(), Fields: []vaultstore.CredentialField{{Field: "inlinePassword", Version: 9, Present: true}}}
	scope, _, err := SelectionIdentity(r)
	if err != nil || scope.Kind != "node-fields" || scope.User != uuid.Nil {
		t.Fatal(scope, err)
	}
	trust := SelectionTrust{Workspace: pin.Workspace, Boundary: pin.Boundary, Author: pin.Author, Scope: scope, OrganisationKey: pin.OrganisationKey, Organisation: pin.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 3, MinimumSelectionRevision: 7}
	seal, err := SignSelection(pin.Workspace, pin.Boundary, r, 7, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	if observed, err := VerifyCurrentSelection(r, pin.Boundary, seal, cert, state, trust); err != nil || observed.SelectionRevision != 7 {
		t.Fatal(observed, err)
	}
	for _, mode := range []string{"owner", "version", "present", "deleted", "field", "kind", "boundary", "revision"} {
		changed := r
		changed.Fields = append([]vaultstore.CredentialField{}, r.Fields...)
		p := trust
		s := seal
		b := pin.Boundary
		switch mode {
		case "owner":
			changed.NodeID = uuid.NewString()
		case "version":
			changed.Fields[0].Version++
		case "present":
			changed.Fields[0].Present = false
		case "deleted":
			changed.Deleted = true
			changed.Fields[0].Present = false
		case "field":
			changed.Fields[0].Field = "notes"
		case "kind":
			p.Scope.Kind = "slot"
		case "boundary":
			b = uuid.New()
		case "revision":
			s.Revision++
		}
		if observed, err := VerifyCurrentSelection(changed, b, s, cert, state, p); err == nil || observed.SelectionRevision != 0 {
			t.Fatal("unauthenticated manifest", mode, err)
		}
	}
	r.Deleted = true
	r.Fields[0].Present = false
	seal, err = SignSelection(pin.Workspace, pin.Boundary, r, 8, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	if observed, err := VerifyCurrentSelection(r, pin.Boundary, seal, cert, state, trust); err != vaultstore.ErrMissing || observed.SelectionRevision != 8 {
		t.Fatal("lost tombstone floor", observed, err)
	}
	for _, fields := range [][]vaultstore.CredentialField{{}, {{Field: "inlinePassword", Version: 9, Present: false}}} {
		r.Deleted = false
		r.Fields = fields
		if _, err := SignSelection(pin.Workspace, pin.Boundary, r, 9, state.Signing, key); err != nil {
			t.Fatal("absent field", err)
		}
	}
}

func TestNodeFieldsManifestRejectsMalformedContent(t *testing.T) {
	good := NodeFieldsRecord{NodeID: uuid.NewString(), Fields: []vaultstore.CredentialField{{Field: "inlinePassword", Version: 1, Present: true}}}
	for _, mode := range []string{"id", "nil", "many", "field", "zero", "large", "deleted", "pointer"} {
		bad := good
		bad.Fields = append([]vaultstore.CredentialField{}, good.Fields...)
		var record SelectionRecord
		switch mode {
		case "id":
			bad.NodeID = "bad"
		case "nil":
			bad.Fields = nil
		case "many":
			bad.Fields = append(bad.Fields, bad.Fields[0])
		case "field":
			bad.Fields[0].Field = "password"
		case "zero":
			bad.Fields[0].Version = 0
		case "large":
			bad.Fields[0].Version = math.MaxInt64 + 1
		case "deleted":
			bad.Deleted = true
		case "pointer":
			record = &bad
		}
		if record == nil {
			record = bad
		}
		if _, _, err := SelectionIdentity(record); err != vault.ErrFormat {
			t.Fatal(mode, err)
		}
	}
}
