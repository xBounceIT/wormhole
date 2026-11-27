package deploy

import (
	"errors"
	"strings"
	"testing"
)

const schemaTestWorkspace = "c56a3ce6-6e09-48f4-b986-3ccd311fba1f"

func TestSchemaScriptContainsAllMigrationsInOneTransaction(t *testing.T) {
	script, err := SchemaScript("testscope", schemaTestWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(script, "\nBEGIN;\n") != 1 || strings.Count(script, "\nCOMMIT;\n") != 1 || !strings.HasSuffix(script, "\nCOMMIT;\n") {
		t.Fatal("expected one outer transaction")
	}
	if strings.Contains(script, "{{") || strings.Count(script, schemaTestWorkspace) < SchemaVersion || !strings.Contains(script, "SET LOCAL ROLE wh_testscope_owner;") {
		t.Fatal("workspace identity was not rendered throughout the deployment")
	}
	position := 0
	for _, version := range schemaMigrations {
		body, err := migrationBody(version)
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := renderMigration(body, "testscope", schemaTestWorkspace)
		if err != nil {
			t.Fatal(err)
		}
		index := strings.Index(script[position:], rendered+"\nSET LOCAL ROLE NONE;\n")
		if index < 0 {
			t.Fatal("migration missing, reordered, or missing role reset")
		}
		position += index + len(rendered)
	}
	for _, identity := range [][2]string{{"quoted';", schemaTestWorkspace}, {"testscope", "not-an-id"}} {
		if script, err := SchemaScript(identity[0], identity[1]); script != "" || !errors.Is(err, ErrIdentity) {
			t.Fatal("invalid deployment identity accepted")
		}
	}
}

func TestMigrationBodyRejectsInvalidTransactionBoundaries(t *testing.T) {
	for _, input := range []string{"SELECT 1;\nCOMMIT;", "BEGIN;\nSELECT 1;", "SELECT 2;\nBEGIN;\nSELECT 1;\nCOMMIT;", "BEGIN;\nSELECT 1;\nCOMMIT;\nSELECT 2;"} {
		if body, err := migrationBody(input); body != "" || !errors.Is(err, errMigrationBoundary) {
			t.Fatalf("migration transaction escaped: %q", input)
		}
	}
	if body, err := migrationBody("-- Header\r\nBEGIN;\r\nSELECT 1;\r\nCOMMIT;\r\n"); err != nil || body != "-- Header\nSELECT 1;" {
		t.Fatal("Windows migration could not be normalized", err)
	}
}

func TestServerCertificateRenewalMigrationRendersStandaloneUpgrade(t *testing.T) {
	migration, err := ServerCertificateRenewalMigration("testscope", schemaTestWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	body, err := migrationBody(migration)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := SchemaScript("testscope", schemaTestWorkspace)
	if err != nil || strings.Contains(migration, "{{") || !strings.Contains(schema, body) {
		t.Fatal("standalone renewal upgrade differed from the fresh deployment", err)
	}
}
