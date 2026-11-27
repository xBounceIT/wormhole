package updateauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

func notarizedAssessment(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	authority := map[string]any{"assessment:authority:source": "Notarized Developer ID"}
	for key, value := range fields {
		authority[key] = value
	}
	data, err := plist.Marshal(map[string]any{
		"assessment:verdict":   true,
		"assessment:authority": authority,
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDarwinPublisherAssessment(t *testing.T) {
	if !isNotarizedDarwinAssessment(notarizedAssessment(t, nil)) {
		t.Fatal("notarized disk image assessment was rejected")
	}
	for _, fields := range []map[string]any{
		{"assessment:authority:source": "Developer ID"},
		{"assessment:authority:source": []string{"Notarized Developer ID"}},
		{"assessment:authority:override": "security disabled"},
		{"assessment:authority:weak": true},
	} {
		if isNotarizedDarwinAssessment(notarizedAssessment(t, fields)) {
			t.Fatalf("accepted a weak or overridden assessment: %v", fields)
		}
	}
	denied := bytes.Replace(notarizedAssessment(t, nil), []byte("<true/>"), []byte("<false/>"), 1)
	for _, raw := range [][]byte{
		nil, []byte("source=Notarized Developer ID"), bytes.Repeat([]byte{' '}, maxAssessmentBytes+1), denied,
		[]byte(`<plist version="1.0"><dict><key>assessment:verdict</key><true/></dict></plist>`),
	} {
		if isNotarizedDarwinAssessment(raw) {
			t.Fatal("malformed or negative assessment was accepted")
		}
	}
}

func TestDarwinPublisherPinsTeamAndVerifiesDiskImage(t *testing.T) {
	const team = "AB7CDEFGH9"
	path := filepath.Join(t.TempDir(), "Wormhole Setup.dmg")
	file := openDarwinTestImage(t, path)
	defer file.Close()
	approved := notarizedAssessment(t, nil)
	for _, c := range []struct {
		name      string
		team      string
		file      *os.File
		codesign  error
		gatekeep  error
		mutateAt  string
		want      error
		toolCalls int
	}{
		{"verified", team, file, nil, nil, "", nil, 2},
		{"signer refused", team, file, errors.New("not signed by pinned team"), nil, "", ErrPublisherUntrusted, 1},
		{"notarization refused", team, file, nil, errors.New("assessment denied"), "", ErrPublisherUntrusted, 2},
		{"invalid team", `A" or true`, file, nil, nil, "", ErrPublisherUnavailable, 0},
		{"changed during signature check", team, file, nil, nil, "/usr/bin/codesign", ErrArtifact, 1},
		{"changed during notarization check", team, file, nil, nil, "/usr/sbin/spctl", ErrArtifact, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			tool := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("native validation was not bounded")
				}
				if executable == c.mutateAt {
					if err := os.WriteFile(path, []byte("modified after the first check"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				switch calls {
				case 1:
					if executable != "/usr/bin/codesign" || len(args) != 5 ||
						!reflect.DeepEqual(args[:3], []string{"--verify", "--strict", "-R"}) || !strings.Contains(args[3], `certificate leaf[subject.OU] = "`+team+`"`) ||
						!strings.Contains(args[3], "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists") ||
						args[4] != path {
						t.Fatalf("unexpected signature verification: %q %q", executable, args)
					}
					return nil, c.codesign
				case 2:
					want := []string{"--assess", "--type", "open", "--context", "context:primary-signature", "--ignore-cache", "--no-cache", "--raw", path}
					if executable != "/usr/sbin/spctl" || !reflect.DeepEqual(args, want) {
						t.Fatalf("unexpected Gatekeeper invocation: %q %q", executable, args)
					}
					return approved, c.gatekeep
				default:
					t.Fatalf("unexpected tool: %q", executable)
					return nil, nil
				}
			}
			if err := verifyDarwinPublisher(c.file, c.team, tool); err != c.want || calls != c.toolCalls {
				t.Fatalf("verification returned %v after %d calls, expected %v after %d", err, calls, c.want, c.toolCalls)
			}
			if c.mutateAt != "" {
				if err := os.WriteFile(path, []byte("signed disk image fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, invalid := range []string{"", "0000000000", strings.ToLower(team), team + "\n", "éX7CDEFGH9"} {
		if err := validateDarwinTeamID(invalid); err != ErrPublisherUnavailable {
			t.Fatalf("invalid team accepted: %q", invalid)
		}
	}
	other := openDarwinTestImage(t, filepath.Join(t.TempDir(), "test.app"))
	defer other.Close()
	if err := verifyDarwinPublisher(other, team, nil); err != ErrArtifact {
		t.Fatalf("accepted non-disk image: %v", err)
	}
}

func openDarwinTestImage(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.WriteFile(path, []byte("signed disk image fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestDarwinAssessmentOutputBound(t *testing.T) {
	var output assessmentOutput
	if _, err := output.Write(make([]byte, maxAssessmentBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{0}); err != io.ErrShortBuffer || output.buffer.Len() != maxAssessmentBytes {
		t.Fatal("assessment output is not bounded")
	}
}
