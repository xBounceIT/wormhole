package sharedcatalog

import (
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func selectionRecords() []SelectionRecord {
	return []SelectionRecord{
		SlotRecord{ID: uuid.NewString(), Name: "Shared account", Protocol: "ssh", DefaultCredentialID: uuid.NewString()},
		SlotValueRecord{ID: uuid.NewString(), SlotID: uuid.NewString(), UserID: uuid.NewString(), CredentialID: uuid.NewString()},
		OverrideRecord{NodeID: uuid.NewString(), UserID: uuid.NewString(), CredentialID: uuid.NewString()},
	}
}

func TestSelectionSignaturesAndScope(t *testing.T) {
	_, _, cert, state, pin, key := credentialFixture(t)
	for _, r := range selectionRecords() {
		scope, _, err := SelectionIdentity(r)
		if err != nil {
			t.Fatal(err)
		}
		trust := SelectionTrust{Workspace: pin.Workspace, Boundary: pin.Boundary, Author: pin.Author, Scope: scope, OrganisationKey: pin.OrganisationKey, Organisation: pin.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 3, MinimumSelectionRevision: 7}
		sign := func(r SelectionRecord) vault.RecordSeal {
			t.Helper()
			s, e := SignSelection(pin.Workspace, pin.Boundary, r, 7, state.Signing, key)
			if e != nil {
				t.Fatal(e)
			}
			return s
		}
		seal := sign(r)
		verify := func(r SelectionRecord, s vault.RecordSeal, p SelectionTrust) (SelectionObservation, error) {
			return VerifyCurrentSelection(r, pin.Boundary, s, cert, state, p)
		}
		if got, e := verify(r, seal, trust); e != nil || got != (SelectionObservation{9, 3, 7}) {
			t.Fatal(got, e)
		}
		// Mutate every field, including the assignment row ID (not its floor key).
		v := reflect.ValueOf(r)
		for i := 0; i < v.NumField(); i++ {
			changed := reflect.New(v.Type()).Elem()
			changed.Set(v)
			f := changed.Field(i)
			if f.Kind() == reflect.Bool {
				f.SetBool(!f.Bool())
			} else {
				value := "changed"
				if strings.HasSuffix(v.Type().Field(i).Name, "ID") {
					value = uuid.NewString()
				}
				if v.Type().Field(i).Name == "Protocol" {
					value = "rdp"
				}
				f.SetString(value)
			}
			if got, e := verify(changed.Interface().(SelectionRecord), seal, trust); e == nil || got.SelectionRevision != 0 {
				t.Fatal("unsigned field", v.Type().Field(i).Name, got, e)
			}
		}
		for _, change := range []func(*SelectionTrust){
			func(p *SelectionTrust) { p.Scope.Subject = uuid.New() }, func(p *SelectionTrust) { p.Scope.User = uuid.New() }, func(p *SelectionTrust) { p.Scope.Kind = "other" }, func(p *SelectionTrust) { p.Workspace = uuid.New() }, func(p *SelectionTrust) { p.Boundary = uuid.New() }, func(p *SelectionTrust) { p.Author = uuid.New() }, func(p *SelectionTrust) { p.MinimumStateSequence++ }, func(p *SelectionTrust) { p.MinimumCertificateRevision++ }, func(p *SelectionTrust) { p.MinimumSelectionRevision++ },
		} {
			p := trust
			change(&p)
			if got, e := verify(r, seal, p); e == nil || got.SelectionRevision != 0 {
				t.Fatal("pin", got, e)
			}
		}
		changed := reflect.New(v.Type()).Elem()
		changed.Set(v)
		changed.FieldByName("Deleted").SetBool(true)
		tomb := changed.Interface().(SelectionRecord)
		if got, e := verify(tomb, sign(tomb), trust); e != vaultstore.ErrMissing || got.SelectionRevision != 7 {
			t.Fatal("tombstone", got, e)
		}
		// The same body cannot be moved into another record domain.
		body, e := selectionSigningBytes(pin.Workspace, pin.Boundary, r, seal)
		if e != nil {
			t.Fatal(e)
		}
		body[0] ^= 1
		bad := seal
		bad.Signature = ed25519.Sign(key, body)
		if got, e := verify(r, bad, trust); e != vault.ErrAuthentication || got.SelectionRevision != 0 {
			t.Fatal("domain", got, e)
		}
		bad = seal
		bad.FormatVersion = vault.FormatVersion + 1
		if _, e := verify(r, bad, trust); e != vault.ErrNewerFormat {
			t.Fatal("new format", e)
		}
		bad = seal
		bad.SignerKeyID = uuid.NewString()
		if _, e := verify(r, bad, trust); e != vault.ErrAuthentication {
			t.Fatal("signer", e)
		}
		if _, e := verify(nil, seal, trust); e != vault.ErrFormat {
			t.Fatal("nil", e)
		}
	}
}

func TestSelectionValidation(t *testing.T) {
	records := selectionRecords()
	slot := records[0].(SlotRecord)
	value := records[1].(SlotValueRecord)
	override := records[2].(OverrideRecord)
	invalid := []SelectionRecord{nil, (*SlotRecord)(nil), &slot, SlotRecord{}, SlotValueRecord{}, OverrideRecord{}}
	for _, name := range []string{"", " \t", strings.Repeat("a", 1025), "a\x00b", string([]byte{255})} {
		r := slot
		r.Name = name
		invalid = append(invalid, r)
	}
	for _, id := range []string{"", uuid.Nil.String(), "bad", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		a := slot
		a.ID = id
		invalid = append(invalid, a)
		b := value
		b.ID = id
		invalid = append(invalid, b)
		b = value
		b.SlotID = id
		invalid = append(invalid, b)
		b = value
		b.UserID = id
		invalid = append(invalid, b)
		b = value
		b.CredentialID = id
		invalid = append(invalid, b)
		c := override
		c.NodeID = id
		invalid = append(invalid, c)
		c = override
		c.UserID = id
		invalid = append(invalid, c)
		c = override
		c.CredentialID = id
		invalid = append(invalid, c)
	}
	a := slot
	a.Protocol = "sftp"
	invalid = append(invalid, a)
	a = slot
	a.DefaultCredentialID = "bad"
	invalid = append(invalid, a)
	_, _, _, state, pin, key := credentialFixture(t)
	for _, r := range invalid {
		if _, _, e := SelectionIdentity(r); e != vault.ErrFormat {
			t.Fatalf("accepted %#v: %v", r, e)
		}
		if _, e := SignSelection(pin.Workspace, pin.Boundary, r, 1, state.Signing, key); e == nil {
			t.Fatal("signed malformed")
		}
	}
	value.Deleted = true
	value.CredentialID = ""
	override.Deleted = true
	override.CredentialID = ""
	for _, r := range []SelectionRecord{value, override} {
		if _, _, e := SelectionIdentity(r); e != nil {
			t.Fatal("empty tombstone", e)
		}
	}
	for _, protocol := range []string{"ssh", "rdp", "vnc"} {
		a = slot
		a.Protocol = protocol
		a.Name = strings.Repeat("a", 1024)
		a.DefaultCredentialID = ""
		if _, _, e := SelectionIdentity(a); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := SignSelection(pin.Workspace, pin.Boundary, slot, 1, state.Signing, nil); e != vault.ErrFormat {
		t.Fatal(e)
	}
	if _, e := SignSelection(pin.Workspace, pin.Boundary, slot, 0, state.Signing, key); e != vault.ErrFormat {
		t.Fatal(e)
	}
}
