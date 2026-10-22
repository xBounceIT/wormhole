package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestMRemotePasswordBytes(t *testing.T) {
	for _, test := range []struct {
		name, password string
		want           []byte
		valid          bool
	}{
		{"empty", "", []byte{}, true},
		{"ASCII", "mR3m", []byte{'m', 'R', '3', 'm'}, true},
		{"Latin-1", "Pässwörd1", []byte{0x50, 0xe4, 0x73, 0x73, 0x77, 0xf6, 0x72, 0x64, 0x31}, true},
		{"boundaries", "\x00\u007f\u0080\u00ff", []byte{0, 0x7f, 0x80, 0xff}, true},
		{"above Latin-1", "prefix\u0100", nil, false},
		{"surrogate pair", "prefix😀", nil, false},
		{"invalid UTF-8", "prefix\xff", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, valid := mremotePasswordBytes(test.password)
			if valid != test.valid || !bytes.Equal(got, test.want) {
				t.Fatalf("got %x, %v; want %x, %v", got, valid, test.want, test.valid)
			}
		})
	}
}

func TestMRemoteVerifierAcceptsOnlyAuthenticatedKnownMarkers(t *testing.T) {
	for _, marker := range []string{mremoteVerifier, mremoteUnprotectedVerifier, "unexpected", ""} {
		encoded := encryptMRemoteFixture(t, marker, mremoteDefaultPassword)
		want := marker == mremoteVerifier || marker == mremoteUnprotectedVerifier
		if mremoteVerifierAccepts(encoded, mremoteDefaultPassword, mremoteTestIterations) != want {
			t.Errorf("unexpected verifier acceptance for %q", marker)
		}
		blob, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		blob[len(blob)-1] ^= 1
		if mremoteVerifierAccepts(base64.StdEncoding.EncodeToString(blob), mremoteDefaultPassword, mremoteTestIterations) {
			t.Fatal("tampered GCM tag accepted")
		}
	}
	if mremoteVerifierAccepts("not base64", mremoteDefaultPassword, 1000) {
		t.Fatal("malformed verifier accepted")
	}
}

func TestMRemoteSilentDefaultIterationLimits(t *testing.T) {
	root, _, _, err := readMRemoteFile(filepath.Join("testdata", "mremote", "default-key.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, iterations := range []string{"", "1000", "0", "-1", "invalid", "250001", "10000001"} {
		root.KDFIterations = iterations
		want := iterations == "" || iterations == "1000"
		if mremoteUsesSilentDefault(root) != want {
			t.Errorf("unexpected silent default result for iterations %q", iterations)
		}
	}
}

func TestMRemoteImportGoldenFixturesRejectIncorrectPasswords(t *testing.T) {
	for _, test := range []struct{ name, file, password string }{
		{"default with wrong password", "default-key.xml", "wrong"},
		{"custom with missing password", "custom-ascii.xml", ""},
		{"custom with wrong password", "custom-ascii.xml", "wrong"},
		{"Latin-1 with wrong password", "custom-latin1.xml", "Password1"},
		{"unrepresentable password", "custom-latin1.xml", "Pässwörd1\u0100"},
	} {
		t.Run(test.name, func(t *testing.T) {
			databasePath := newMRemoteTestDatabase(t)
			request := mremoteImportRequest{
				Path: filepath.Join("testdata", "mremote", test.file), Password: test.password,
				PlanNonce: "11111111-1111-4111-8111-111111111111",
			}
			if _, err := analyzeMRemoteImport(databasePath, request); err == nil || err.Error() != "the mRemoteNG encryption password is incorrect" {
				t.Fatalf("unexpected error: %v", err)
			}
			assertMRemoteDatabaseEmpty(t, databasePath)
			request.StructureOnly = true
			plan, err := analyzeMRemoteImport(databasePath, request)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Credentials != 0 || plan.Folders != 1 || plan.Connections != 1 || len(plan.Warnings) != 1 {
				t.Fatalf("unexpected structure-only plan: %+v", plan)
			}
		})
	}
}

func TestMRemoteImportBouncyCastleGoldenFixtures(t *testing.T) {
	for _, test := range []struct {
		name, file, password string
		passwordRequired     bool
	}{
		{"silent default", "default-key.xml", "", false},
		{"explicit default", "default-key.xml", "mR3m", false},
		{"custom ASCII", "custom-ascii.xml", "Password1", true},
		{"custom Latin-1", "custom-latin1.xml", "Pässwörd1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			databasePath := newMRemoteTestDatabase(t)
			request := mremoteImportRequest{
				Path: filepath.Join("testdata", "mremote", test.file), Password: test.password,
				PlanNonce: "11111111-1111-4111-8111-111111111111",
			}
			inspection, err := inspectMRemoteImport(request)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.PasswordRequired != test.passwordRequired {
				t.Errorf("passwordRequired = %v, want %v", inspection.PasswordRequired, test.passwordRequired)
			}
			plan, err := analyzeMRemoteImport(databasePath, request)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Folders != 1 || plan.Connections != 1 || plan.Credentials != 1 || len(plan.Warnings) != 0 {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			response, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(response), "demo-secret") {
				t.Fatal("plaintext credential leaked into preview")
			}
			assertMRemoteJSONArrays(t, response, "warnings", "skippedUnsupportedSamples", "preview")
			assertMRemoteDatabaseEmpty(t, databasePath)

			previousStore := credentialSecretStore
			stored := 0
			credentialSecretStore = func(id, _, password string) (string, string, error) {
				stored++
				if password != "demo-secret" {
					t.Error("imported password differs from BouncyCastle golden plaintext")
				}
				return "protected-" + id, "test", nil
			}
			t.Cleanup(func() { credentialSecretStore = previousStore })
			request.PlanToken = plan.PlanToken
			result, err := commitMRemoteImport(databasePath, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.FoldersCreated != 1 || result.ConnectionsCreated != 1 || result.CredentialsCreated != 1 || stored != 1 {
				t.Fatalf("unexpected commit: %+v, protected secrets: %d", result, stored)
			}
			response, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			assertMRemoteJSONArrays(t, response, "warnings")
		})
	}
}

func TestMRemoteImportCLIEmitsArraysForEmptyAndSkippedPlans(t *testing.T) {
	for _, test := range []struct{ name, nodes string }{
		{"empty", ""},
		{"unsupported", `<Node Name="Legacy" Type="Connection" Protocol="Telnet" />`},
	} {
		t.Run(test.name, func(t *testing.T) {
			databasePath := newMRemoteTestDatabase(t)
			request := mremoteImportRequest{
				Path:      writeMRemoteFixture(t, fmt.Sprintf(`<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.6">%s</mrng:Connections>`, test.nodes)),
				PlanNonce: "11111111-1111-4111-8111-111111111111",
			}
			for _, operation := range []string{"mremote-import-analyze", "mremote-import-commit"} {
				payload, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				code := runBackendCLI([]string{"-database", databasePath, "-operation", operation}, bytes.NewReader(payload), &stdout, &stderr)
				if code != 0 {
					t.Fatalf("%s failed: %s", operation, stderr.String())
				}
				assertMRemoteJSONArrays(t, stdout.Bytes(), "warnings")
				if operation == "mremote-import-analyze" {
					assertMRemoteJSONArrays(t, stdout.Bytes(), "skippedUnsupportedSamples", "preview")
					var plan mremoteImportPlanResponse
					if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
						t.Fatal(err)
					}
					request.PlanToken = plan.PlanToken
				}
			}
			assertMRemoteDatabaseEmpty(t, databasePath)
		})
	}
}

func assertMRemoteJSONArrays(t *testing.T, payload []byte, fields ...string) {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if _, ok := response[field].([]any); !ok {
			t.Errorf("%s must be a JSON array, got %T", field, response[field])
		}
	}
}
