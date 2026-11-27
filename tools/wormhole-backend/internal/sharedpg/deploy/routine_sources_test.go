package deploy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutineSourceHashesBindRenderedWorkspaceIdentity(t *testing.T) {
	const first = "11111111-1111-4111-8111-111111111111"
	const second = "22222222-2222-4222-8222-222222222222"
	// Use the fully expanded migration, including the current recovery guards.
	_, body, ok := strings.Cut(workspaceRecoveryExportMigration, "AS $material$")
	body, _, closed := strings.Cut(body, "$material$")
	if !ok || !closed {
		t.Fatal("missing expanded recovery body")
	}
	raw := substituteIdentity(body, "password", first)
	body = strings.ReplaceAll(body, "\r\n", "\n")
	encoded, err := RoutineSourceHashes("password", first)
	if err != nil {
		t.Fatal(err)
	}
	var hashes map[string]string
	if err := json.Unmarshal(encoded, &hashes); err != nil {
		t.Fatal(err)
	}
	rendered := substituteIdentity(body, "password", first)
	for _, source := range []string{raw, rendered, strings.ReplaceAll(rendered, "\n", "\r\n")} {
		if hashes[bodyHash(source)] != bodyHash(body) {
			t.Fatal("legitimate deployed source not recognized")
		}
	}
	for _, source := range []string{body, substituteIdentity(body, "password", second), substituteIdentity(body, "security", first), rendered + " "} {
		if _, ok := hashes[bodyHash(source)]; ok {
			t.Fatal("foreign or modified SQL accepted")
		}
	}
	if _, err := RoutineSourceHashes("bad", first); err != ErrIdentity {
		t.Fatal("invalid identity", err)
	}
}
