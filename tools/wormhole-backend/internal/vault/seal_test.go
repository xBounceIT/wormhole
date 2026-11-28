package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
)

func testRecord() ResolutionRecord {
	return ResolutionRecord{WorkspaceID: "workspace", NodeID: "node", BoundaryID: "boundary", Revision: 4}
}

func TestResolutionSealsCoverEveryRoutingField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	record := testRecord()
	seal, err := SignRecord(record, "signer", 1, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	local, err := SealLocalRecord(record, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecord(record, seal, pub, 4); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLocalRecord(record, local, testKey(), 4); err != nil {
		t.Fatal(err)
	}
	// Exercise every field, including newly added routing fields. A field omitted
	// from canonicalization becomes an immediately visible regression.
	for i := 0; i < reflect.TypeOf(record).NumField(); i++ {
		t.Run(reflect.TypeOf(record).Field(i).Name, func(t *testing.T) {
			changed := record
			field := reflect.ValueOf(&changed).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				field.SetString("different")
			case reflect.Uint64:
				field.SetUint(5)
			case reflect.Pointer:
				value := reflect.New(field.Type().Elem())
				switch value.Elem().Kind() {
				case reflect.String:
					value.Elem().SetString("different")
				case reflect.Bool:
					value.Elem().SetBool(true)
				default:
					value.Elem().SetUint(1)
				}
				field.Set(value)
			}
			if VerifyRecord(changed, seal, pub, 4) == nil {
				t.Fatal("unsigned routing change accepted")
			}
			if VerifyLocalRecord(changed, local, testKey(), 4) == nil {
				t.Fatal("local routing change accepted")
			}
		})
	}
	if err := VerifyRecord(record, seal, pub, 5); err != ErrRollback {
		t.Fatal("seal rollback")
	}
	if err := VerifyLocalRecord(record, local, testKey(), 5); err != ErrRollback {
		t.Fatal("local rollback")
	}
	for _, mutate := range []func(*RecordSeal){func(s *RecordSeal) { s.FormatVersion = 2 }, func(s *RecordSeal) { s.FormatVersion = 0 }, func(s *RecordSeal) { s.SignerKeyID = "other" }, func(s *RecordSeal) { s.SignerKeyVersion++ }, func(s *RecordSeal) { v := "capability"; s.CapabilityID = &v }, func(s *RecordSeal) { s.Signature = nil }} {
		s := seal
		mutate(&s)
		if VerifyRecord(record, s, pub, 4) == nil {
			t.Fatal("seal header change accepted")
		}
	}
}

func TestSealInputValidation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := testRecord()
	if _, err := SignRecord(r, "signer", 1, nil, nil); err != ErrFormat {
		t.Fatal("bad key")
	}
	if _, err := SignRecord(ResolutionRecord{}, "signer", 1, nil, priv); err != ErrFormat {
		t.Fatal("bad record")
	}
	if _, err := SignRecord(r, "", 1, nil, priv); err != ErrFormat {
		t.Fatal("bad signer")
	}
	if _, err := SealLocalRecord(r, nil); err != ErrFormat {
		t.Fatal("bad local key")
	}
	if _, err := SealLocalRecord(ResolutionRecord{}, testKey()); err != ErrFormat {
		t.Fatal("bad local record")
	}
	seal, _ := SignRecord(r, "signer", 1, nil, priv)
	if VerifyRecord(r, seal, nil, 0) != ErrFormat {
		t.Fatal("bad verify key")
	}
	r.CredentialMode = new(uint8(4))
	if VerifyRecord(r, seal, pub, 0) != ErrFormat {
		t.Fatal("unknown resolver mode")
	}
}
