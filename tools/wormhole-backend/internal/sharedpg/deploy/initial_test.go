package deploy

import (
	"strings"
	"testing"
)

const testWorkspace = "12345678-1234-4234-8234-123456789abc"

func TestInitialMigrationIdentity(t *testing.T) {
	for _, generate := range []func(string, string) (string, error){InitialMigration, SessionMigration, KeyGraphMigration, SessionProofMigration, PasswordChangeMigration, AccountKeysMigration, AccountCertificatesMigration, AccountStateMigration, TLSTrustMigration, InvitationLoginMigration, InvitationCopiesMigration, AccountEnrollmentMigration, InvitationCommitMigration, DeviceConfirmationMigration, InvitationCertificationMigration, NodePermissionsMigration, TreeSnapshotMigration, NodeAuthorMigration, CatalogChangesMigration, UseIntentsMigration, UseConsumptionMigration, ResolverMigration, ResolutionChainMigration, CredentialSlotsMigration, CredentialCatalogMigration, CredentialProjectionMigration, SelectionProjectionMigration, ConnectionResolutionMigration, BoundaryPermissionsMigration, BoundaryManifestsMigration, ConnectionSnapshotMigration, CredentialValuesMigration, KeyCopyProjectionMigration, CredentialReleaseGraphMigration, FetchSecretMigration, ReleasePolicyMigration, ConnectionPlanMigration, RuntimeStateMigration, NodeSecretManifestsMigration, TunnelProfilesMigration, FortinetIPsecMigration, EnrolledCatalogAuthorsMigration, TunnelFallbackMigration} {
		for _, tag := range []string{"testscope", "abcdefghijklmnop", "abc23457"} {
			sql, err := generate(tag, testWorkspace)
			if err != nil || strings.Contains(sql, "{{") || !strings.Contains(sql, "wh_"+tag+"_owner") || !strings.Contains(sql, testWorkspace) {
				t.Fatal("identity substitution failed")
			}
		}
		for _, tag := range []string{"", "short", "abcdefghijklmnopq", "TESTSCOPE", "bad_tag_", "abcde018", "abcd;--x"} {
			if _, err := generate(tag, testWorkspace); err != ErrIdentity {
				t.Fatal("accepted invalid role tag")
			}
		}
		for _, id := range []string{"", strings.ToUpper(testWorkspace), "00000000-0000-0000-0000-000000000000", "bad", "' ; COMMIT; --"} {
			if _, err := generate("testscope", id); err != ErrIdentity {
				t.Fatal("accepted invalid workspace identity")
			}
		}
	}
}
