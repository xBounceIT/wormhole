package sharedcatalog

import (
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestTunnelSelectionSignatureAndValidation(t *testing.T) {
	_, _, cert, state, pin, key := credentialFixture(t)
	record := TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 1}, ConfigurationVersion: 6}
	scope, _, err := SelectionIdentity(record)
	if err != nil || scope.Kind != "tunnel" || scope.User != uuid.Nil {
		t.Fatal(scope, err)
	}
	trust := SelectionTrust{Workspace: pin.Workspace, Boundary: pin.Boundary, Author: pin.Author, Scope: scope, OrganisationKey: pin.OrganisationKey, Organisation: pin.Organisation, MinimumSelectionRevision: 7}
	seal, err := SignSelection(pin.Workspace, pin.Boundary, record, 7, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	if o, err := VerifyCurrentSelection(record, pin.Boundary, seal, cert, state, trust); err != nil || o.SelectionRevision != 7 {
		t.Fatal(o, err)
	}
	for _, mode := range []string{"id", "name", "kind", "configuration", "deleted", "boundary", "scope", "revision", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			r, s, b, tr := record, seal, pin.Boundary, trust
			switch mode {
			case "id":
				r.Metadata.ID = uuid.NewString()
			case "name":
				r.Metadata.Name += " changed"
			case "kind":
				r.Metadata.Kind++
			case "configuration":
				r.ConfigurationVersion++
			case "deleted":
				r.Deleted = true
			case "boundary":
				b = uuid.New()
			case "scope":
				tr.Scope.Kind = "slot"
			case "revision":
				s.Revision++
			case "rollback":
				tr.MinimumSelectionRevision++
			}
			if o, err := VerifyCurrentSelection(r, b, s, cert, state, tr); err == nil || o.SelectionRevision != 0 {
				t.Fatal("untrusted tunnel accepted", o, err)
			}
		})
	}
	record.Deleted = true
	seal, err = SignSelection(pin.Workspace, pin.Boundary, record, 8, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	if o, err := VerifyCurrentSelection(record, pin.Boundary, seal, cert, state, trust); err != vaultstore.ErrMissing || o.SelectionRevision != 8 {
		t.Fatal("tombstone", o, err)
	}
	for _, mode := range []string{"zero", "large", "ahead", "bad-id", "bad-name", "bad-kind", "pointer"} {
		r := record
		var input SelectionRecord
		switch mode {
		case "zero":
			r.ConfigurationVersion = 0
		case "large":
			r.ConfigurationVersion = math.MaxInt64 + 1
		case "ahead":
			r.ConfigurationVersion = 10
		case "bad-id":
			r.Metadata.ID = "bad"
		case "bad-name":
			r.Metadata.Name = ""
		case "bad-kind":
			r.Metadata.Kind = 10
		case "pointer":
			input = &r
		}
		if input == nil {
			input = r
		}
		if _, err := SignSelection(pin.Workspace, pin.Boundary, input, 9, state.Signing, key); err != vault.ErrFormat {
			t.Fatal(mode, err)
		}
	}
	// Provider changes and configuration updates are valid only under a fresh seal.
	record.Deleted = false
	for kind := 0; kind <= 9; kind++ {
		record.Metadata.Kind = kind
		record.ConfigurationVersion = 9
		if _, err := SignSelection(pin.Workspace, pin.Boundary, record, 9, state.Signing, key); err != nil {
			t.Fatal(kind, err)
		}
	}
}
