package resolver

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestResolverRefusesAnImportedNodeWithRetainedPins(t *testing.T) {
	host, protocol := "import.example", 0
	imported := &vaultstore.NodeImportReference{Digest: "abababababababababababababababababababababababababababababababab"}
	chain := []vaultstore.NodeMetadata{{ID: uuid.NewString(), Name: "Imported node", Host: &host, Kind: 1, Protocol: &protocol, Imported: imported}}
	if _, err := Resolve(chain, ""); err != nil {
		t.Fatal("notes alone blocked normal resolution", err)
	}
	imported.RetainedPins = true
	if plan, err := Resolve(chain, ""); err != ErrImportedPins || plan != (Plan{}) {
		t.Fatal("the ordinary resolver returned an unpinned credential choice", err)
	}
}

func TestConformanceV1(t *testing.T) {
	file, err := os.Open("testdata/conformance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var fixtures []struct {
		Name       string                         `json:"name"`
		Chain      []vaultstore.NodeMetadata      `json:"chain"`
		Override   string                         `json:"overrideCredentialId"`
		Credential *vaultstore.CredentialMetadata `json:"credential"`
		Expected   Plan                           `json:"expected"`
		Error      string                         `json:"error"`
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 40 {
		t.Fatal("conformance cases missing")
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			got, err := Resolve(f.Chain, f.Override)
			if err == nil && f.Credential != nil {
				got, err = ApplyCredential(got, *f.Credential)
			}
			if f.Error != "" {
				want := map[string]error{"chain": ErrChain, "target": ErrTarget, "credential": ErrCredential, "tunnel": ErrTunnel}[f.Error]
				if want == nil || err != want || !reflect.DeepEqual(got, Plan{}) {
					t.Fatalf("unexpected rejection: %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("resolution mismatch\ngot  %+v\nwant %+v\nerror %v", got, f.Expected, err)
			}
		})
	}
}

func pointer[T any](value T) *T { return &value }
func TestChainDepthAndNoInputMutation(t *testing.T) {
	chain := make([]vaultstore.NodeMetadata, vaultstore.MaxNodeDepth)
	for i := range chain {
		chain[i] = vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "node", Kind: 0}
	}
	chain[0].Kind = 1
	chain[0].Host = pointer(" host.example ")
	chain[0].Protocol = pointer(0)
	for i := 0; i < len(chain)-1; i++ {
		chain[i].ParentID = &chain[i+1].ID
	}
	before, _ := json.Marshal(chain)
	if _, err := Resolve(chain, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(chain)
	if string(before) != string(after) {
		t.Fatal("mutated borrowed metadata")
	}
	extra := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "root", Kind: 0}
	chain[len(chain)-1].ParentID = &extra.ID
	if _, err := Resolve(append(chain, extra), ""); err != ErrChain {
		t.Fatal("accepted depth overflow", err)
	}
	if _, err := Resolve(nil, ""); err != ErrChain {
		t.Fatal(err)
	}
	if _, err := ApplyCredential(Plan{Credential: Choice{Kind: "inline"}}, vaultstore.CredentialMetadata{}); err != ErrCredential {
		t.Fatal(err)
	}
}

func TestRDPExternalClientPlatformAndAzureAD(t *testing.T) {
	for _, os := range []string{"windows", "linux", "darwin"} {
		for _, p := range []Plan{{Protocol: 1, ExternalRDPClient: true}, {Protocol: 1, Domain: " AzureAD "}, {Protocol: 1, Username: "  AzUrEaD\\alice "}} {
			if RequiresExternalRDP(os, p) != (os == "windows") {
				t.Fatal("external client platform policy", os, p)
			}
		}
		if RequiresExternalRDP(os, Plan{Protocol: 1, Username: "azuread-user"}) || RequiresExternalRDP(os, Plan{Protocol: 0, ExternalRDPClient: true}) {
			t.Fatal("unrelated identity forced external client")
		}
	}
}
