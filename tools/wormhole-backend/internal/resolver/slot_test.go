package resolver

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSlotConformance(t *testing.T) {
	raw, err := os.ReadFile("testdata/slots-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name     string               `json:"name"`
		Plan     Plan                 `json:"plan"`
		User     string               `json:"userId"`
		Slot     CredentialSlot       `json:"slot"`
		Value    *CredentialSlotValue `json:"value"`
		Expected Plan                 `json:"expected"`
		Error    string               `json:"error"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 30 {
		t.Fatal("missing fixtures")
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			before, _ := json.Marshal(f)
			got, err := ResolveSlot(f.Plan, f.User, f.Slot, f.Value)
			if f.Error != "" {
				if err != ErrCredential || got != (Plan{}) {
					t.Fatal("accepted invalid slot", err)
				}
			} else {
				if err != nil || !reflect.DeepEqual(got, f.Expected) {
					t.Fatalf("slot choice: %+v, %v", got, err)
				}
				c := vaultstore.CredentialMetadata{ID: got.Credential.ID, Protocol: CredentialProtocol(got.Protocol), Username: " personal ", Domain: " domain "}
				applied, e := ApplyCredential(got, c)
				if e != nil || applied.Username != "personal" || applied.Domain != "domain" {
					t.Fatal("mixed identities", e)
				}
			}
			after, _ := json.Marshal(f)
			if string(before) != string(after) {
				t.Fatal("mutated input")
			}
		})
	}
}
