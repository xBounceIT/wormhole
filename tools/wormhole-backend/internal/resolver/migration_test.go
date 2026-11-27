package resolver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func migrationFixture() (string, []EffectiveCredentialSnapshot, []EffectiveCredentialSnapshot) {
	workspace, node, credential := uuid.NewString(), uuid.NewString(), uuid.NewString()
	var old, next []EffectiveCredentialSnapshot
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		before := EffectiveCredentialSnapshot{NodeID: node, ProtocolPath: path, CredentialID: credential, Username: "old-private-user", SourceKind: "saved"}
		after := before
		after.ResolverVersion = Version
		if path != "reveal" {
			after.Username = "new-private-user"
		}
		old, next = append(old, before), append(next, after)
	}
	return workspace, old, next
}

func TestMigrationPlanDefaultsOrderingIsolationAndPrivateReport(t *testing.T) {
	workspace, old, next := migrationFixture()
	before := append([]EffectiveCredentialSnapshot{}, old...)
	plan, err := BuildMigration(workspace, old, next)
	if err != nil || plan.Validate() != nil || len(plan.Entries) != 2 {
		t.Fatal(plan, err)
	}
	if !reflect.DeepEqual(before, old) {
		t.Fatal("input reordered")
	}
	for _, e := range plan.Entries {
		if e.Choice != "keep" || e.Legacy.Username != "old-private-user" {
			t.Fatal("old identity not preserved", e)
		}
	}
	reversed := []EffectiveCredentialSnapshot{next[2], next[0], next[1]}
	other, err := BuildMigration(workspace, []EffectiveCredentialSnapshot{old[1], old[2], old[0]}, reversed)
	if err != nil || !reflect.DeepEqual(other, plan) {
		t.Fatal("input order affects plan", err)
	}
	changed, err := plan.Decide(plan.Fingerprint, []MigrationDecision{{NodeID: old[0].NodeID, ProtocolPath: "ssh", Choice: "new"}})
	if err != nil || plan.Entries[1].Choice != "keep" || changed.Entries[1].Choice != "new" {
		t.Fatal("decision mutated original or wrong path", err)
	}
	if err := changed.Recheck(workspace, old, next); err != nil {
		t.Fatal(err)
	}
	report, err := changed.Report()
	if err != nil || len(report) != 2 || report[1].Choice != "new" || !report[1].UsernameChanged {
		t.Fatal(report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), "private-user") || strings.Contains(string(encoded), workspace) {
		t.Fatal("identity or workspace data in ID-only report")
	}
}

func TestMigrationFingerprintIndependentBinaryVector(t *testing.T) {
	workspace := "11111111-1111-4111-8111-111111111111"
	old := EffectiveCredentialSnapshot{NodeID: "22222222-2222-4222-8222-222222222222", ProtocolPath: "reveal", Username: "before", SourceKind: "none"}
	next := old
	next.Username, next.ResolverVersion = "after", Version
	plan, err := BuildMigration(workspace, []EffectiveCredentialSnapshot{old}, []EffectiveCredentialSnapshot{next})
	// Generated independently with Python hashlib and big-endian uint64 field
	// lengths, following the domain/field order defined by the migration format.
	if err != nil || plan.Fingerprint != "989d52f9f77d63d472307eb17ceb335f2921c019e578b78cffd36d1924612b4d" {
		t.Fatal(plan.Fingerprint, err)
	}
}

func TestMigrationRecheckBindsEveryOldAndNewIdentity(t *testing.T) {
	workspace, old, next := migrationFixture()
	plan, err := BuildMigration(workspace, old, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func([]EffectiveCredentialSnapshot, []EffectiveCredentialSnapshot)
	}{
		{"changed path still differs", func(_, n []EffectiveCredentialSnapshot) { n[0].Username = "third-private-user" }},
		{"previously unchanged path", func(o, n []EffectiveCredentialSnapshot) {
			o[2].Username = "changed-both"
			n[2].Username = "changed-both"
		}},
		{"legacy identity", func(o, _ []EffectiveCredentialSnapshot) { o[0].Username = "new-legacy" }},
		{"domain", func(o, n []EffectiveCredentialSnapshot) { o[2].Domain = "DOMAIN"; n[2].Domain = "DOMAIN" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := append([]EffectiveCredentialSnapshot{}, old...), append([]EffectiveCredentialSnapshot{}, next...)
			test.change(a, b)
			if err := plan.Recheck(workspace, a, b); err != ErrMigrationStale {
				t.Fatal("stale source accepted", err)
			}
		})
	}
	if err := plan.Recheck(workspace, nil, nil); err != ErrMigrationStale {
		t.Fatal("removed connections accepted", err)
	}
	if err := plan.Recheck(uuid.NewString(), old, next); err != ErrMigration {
		t.Fatal("different workspace accepted", err)
	}
	forged := plan
	forged.Entries = append([]MigrationEntry{}, plan.Entries...)
	forged.Entries[0].Legacy.Username = "forged"
	if forged.Validate() != nil {
		t.Fatal("fixture must remain structurally valid")
	}
	if err := forged.Recheck(workspace, old, next); err != ErrMigrationStale {
		t.Fatal("forged pin identity accepted", err)
	}
	partial, err := BuildMigration(workspace, old[2:], next[2:])
	if err != nil {
		t.Fatal(err)
	}
	if err := partial.Recheck(workspace, old, next); err != ErrMigrationStale {
		t.Fatal("omitted companion paths accepted", err)
	}
}

func TestMigrationInvalidSourcesGroupsAndPlans(t *testing.T) {
	workspace, old, next := migrationFixture()
	for _, test := range []struct{ old, next []EffectiveCredentialSnapshot }{
		{old, next[:2]}, {old[:2], next[:2]}, {old[:1], next[:1]},
		{append(old, old[0]), append(next, next[0])},
		{old, []EffectiveCredentialSnapshot{next[0], next[1], next[1]}},
		{next, old},
	} {
		if _, err := BuildMigration(workspace, test.old, test.next); err != ErrMigration {
			t.Fatal("invalid groups accepted", err)
		}
	}
	if _, err := BuildMigration("bad", old, next); err != ErrMigration {
		t.Fatal(err)
	}
	for _, path := range []string{"ssh", "vnc", "reveal"} {
		s := EffectiveCredentialSnapshot{NodeID: uuid.NewString(), ProtocolPath: path, SourceKind: "system"}
		n := s
		n.ResolverVersion = Version
		if _, err := BuildMigration(workspace, []EffectiveCredentialSnapshot{s}, []EffectiveCredentialSnapshot{n}); err != ErrMigration {
			t.Fatal("invalid system source accepted", path, err)
		}
	}
	plan, err := BuildMigration(workspace, old, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*MigrationPlan){
		func(p *MigrationPlan) { p.Version = 9 }, func(p *MigrationPlan) { p.WorkspaceID = "bad" }, func(p *MigrationPlan) { p.Fingerprint = "bad" }, func(p *MigrationPlan) { p.Fingerprint = strings.ToUpper(p.Fingerprint) },
		func(p *MigrationPlan) { p.Entries[0].Choice = "unknown" }, func(p *MigrationPlan) {
			p.Entries[0].Candidate = p.Entries[0].Legacy
			p.Entries[0].Candidate.ResolverVersion = Version
		},
		func(p *MigrationPlan) { p.Entries = append(p.Entries, p.Entries[0]) }, func(p *MigrationPlan) { p.Entries[0].Legacy.Domain = "invalid-ssh-domain" },
	} {
		bad := plan
		bad.Entries = append([]MigrationEntry{}, plan.Entries...)
		mutate(&bad)
		if bad.Validate() != ErrMigration {
			t.Fatal("invalid plan accepted")
		}
		if _, err := bad.Report(); err != ErrMigration {
			t.Fatal(err)
		}
		if _, err := bad.Decide(bad.Fingerprint, nil); err != ErrMigration {
			t.Fatal(err)
		}
	}
}

func TestMigrationDecisionsAreAtomicAndBoundToPreview(t *testing.T) {
	workspace, old, next := migrationFixture()
	plan, err := BuildMigration(workspace, old, next)
	if err != nil {
		t.Fatal(err)
	}
	valid := MigrationDecision{NodeID: old[0].NodeID, ProtocolPath: "ssh", Choice: "new"}
	for _, decisions := range [][]MigrationDecision{{valid, valid}, {valid, {NodeID: uuid.NewString(), ProtocolPath: "ssh", Choice: "keep"}}, {{NodeID: valid.NodeID, ProtocolPath: "ssh", Choice: "invalid"}}, {valid, valid, valid}} {
		if got, err := plan.Decide(plan.Fingerprint, decisions); err != ErrMigration || !reflect.DeepEqual(got, MigrationPlan{}) {
			t.Fatal("invalid decision batch accepted", err)
		}
		for _, entry := range plan.Entries {
			if entry.Choice != "keep" {
				t.Fatal("partial decision mutated preview")
			}
		}
	}
	if _, err := plan.Decide(strings.Repeat("0", 64), []MigrationDecision{valid}); err != ErrMigrationStale {
		t.Fatal(err)
	}
	empty, err := BuildMigration(workspace, nil, nil)
	if err != nil || empty.Entries == nil || empty.Validate() != nil {
		t.Fatal(err)
	}
	if changed, err := empty.Decide(empty.Fingerprint, nil); err != nil || changed.Entries == nil {
		t.Fatal(err)
	}
	if report, err := empty.Report(); err != nil || report == nil || len(report) != 0 {
		t.Fatal(err)
	}
	for _, paths := range [][]string{{"reveal", "vnc"}, {"reveal", "rdp", "rdp-gateway"}} {
		var a, b []EffectiveCredentialSnapshot
		node := uuid.NewString()
		for _, path := range paths {
			s := EffectiveCredentialSnapshot{NodeID: node, ProtocolPath: path, SourceKind: "none"}
			a = append(a, s)
			s.ResolverVersion = Version
			b = append(b, s)
		}
		if _, err := BuildMigration(workspace, a, b); err != nil {
			t.Fatal("valid protocol group rejected", err)
		}
	}
}
