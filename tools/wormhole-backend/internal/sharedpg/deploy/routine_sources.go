package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

var routineBodyStart = regexp.MustCompile(`(?i)\bAS\s+(\$(?:[a-z_][a-z0-9_]*)?\$)`)

// RoutineSourceHashes binds the server's prosrc digest to the exact migration
// body rendered for this workspace. The identity-independent digest is used
// in the released catalog fingerprint, which also binds the routine signature.
func RoutineSourceHashes(tag, workspaceID string) ([]byte, error) {
	if err := ValidateIdentity(tag, workspaceID); err != nil {
		return nil, err
	}
	hashes := make(map[string]string)
	for _, sql := range schemaMigrations {
		for {
			match := routineBodyStart.FindStringSubmatchIndex(sql)
			if match == nil {
				break
			}
			quote := sql[match[2]:match[3]]
			sql = sql[match[1]:]
			body, rest, ok := strings.Cut(sql, quote)
			if !ok {
				return nil, errMigrationBoundary
			}
			canonical := strings.ReplaceAll(body, "\r\n", "\n")
			template := bodyHash(canonical)
			rendered := substituteIdentity(canonical, tag, workspaceID)
			crlf := strings.ReplaceAll(rendered, "\n", "\r\n")
			sources := []string{rendered, crlf}
			// Standalone upgrades preserve the exact embedded SQL, including
			// LF Go fragments inside a CRLF migration on Windows.
			if body != canonical && body != strings.ReplaceAll(canonical, "\n", "\r\n") {
				sources = append(sources, substituteIdentity(body, tag, workspaceID))
			}
			for _, source := range sources {
				key := bodyHash(source)
				if previous, ok := hashes[key]; ok && previous != template {
					return nil, errMigrationBoundary
				}
				hashes[key] = template
			}
			sql = rest
		}
	}
	return json.Marshal(hashes)
}

func bodyHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
