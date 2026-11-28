package resolver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSnapshotDifferenceContainsOnlyIDsAndFlags(t *testing.T) {
	old := EffectiveCredentialSnapshot{NodeID: uuid.NewString(), ProtocolPath: "rdp", CredentialID: uuid.NewString(), Username: "private-user", Domain: "PRIVATE-DOMAIN", SourceKind: "saved"}
	next := old
	next.ResolverVersion = Version
	if diff, err := CompareSnapshots(old, next); err != nil || diff != nil {
		t.Fatal(diff, err)
	}
	next.CredentialID = uuid.NewString()
	next.Username = "new-private-user"
	next.Domain = "OTHER-DOMAIN"
	diff, err := CompareSnapshots(old, next)
	if err != nil || diff == nil || !diff.CredentialChanged || !diff.UsernameChanged || !diff.DomainChanged || diff.SourceChanged {
		t.Fatal(diff, err)
	}
	raw, err := json.Marshal(diff)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{old.Username, next.Username, old.Domain, next.Domain} {
		if strings.Contains(string(raw), value) {
			t.Fatal("identity value in diagnostics")
		}
	}
	next.SourceKind = "inline"
	next.CredentialID = next.NodeID
	if diff, err := CompareSnapshots(old, next); err != nil || !diff.SourceChanged {
		t.Fatal(diff, err)
	}
}

func TestSnapshotValidationAndComparisonBoundaries(t *testing.T) {
	base := EffectiveCredentialSnapshot{NodeID: uuid.NewString(), ProtocolPath: "ssh", SourceKind: "none"}
	for _, path := range []string{"ssh", "sftp", "vnc", "rdp", "rdp-gateway", "reveal"} {
		s := base
		s.ProtocolPath = path
		if s.Validate() != nil {
			t.Fatal(path)
		}
	}
	for _, kind := range []string{"none", "system", "inline", "saved"} {
		s := base
		s.SourceKind = kind
		if kind == "inline" {
			s.CredentialID = s.NodeID
		}
		if kind == "saved" {
			s.CredentialID = uuid.NewString()
		}
		if s.Validate() != nil {
			t.Fatal(kind)
		}
	}
	for _, mutate := range []func(*EffectiveCredentialSnapshot){
		func(s *EffectiveCredentialSnapshot) { s.NodeID = "bad" }, func(s *EffectiveCredentialSnapshot) { s.ProtocolPath = "http" },
		func(s *EffectiveCredentialSnapshot) { s.SourceKind = "unknown" }, func(s *EffectiveCredentialSnapshot) { s.CredentialID = uuid.NewString() },
		func(s *EffectiveCredentialSnapshot) { s.SourceKind = "inline" }, func(s *EffectiveCredentialSnapshot) { s.SourceKind = "saved" },
		func(s *EffectiveCredentialSnapshot) { s.Username = string([]byte{0xff}) }, func(s *EffectiveCredentialSnapshot) { s.Domain = "domain\x00" },
		func(s *EffectiveCredentialSnapshot) { s.Username = strings.Repeat("x", 2049) }, func(s *EffectiveCredentialSnapshot) { s.ResolverVersion = -1 },
		func(s *EffectiveCredentialSnapshot) { s.ResolverVersion = Version + 1 },
	} {
		s := base
		mutate(&s)
		if s.Validate() != ErrCredential {
			t.Fatal("invalid snapshot accepted")
		}
		next := base
		next.ResolverVersion = Version
		if _, err := CompareSnapshots(s, next); err != ErrCredential {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*EffectiveCredentialSnapshot){func(s *EffectiveCredentialSnapshot) { s.NodeID = uuid.NewString() }, func(s *EffectiveCredentialSnapshot) { s.ProtocolPath = "sftp" }, func(s *EffectiveCredentialSnapshot) { s.ResolverVersion = 0 }} {
		next := base
		next.ResolverVersion = Version
		mutate(&next)
		if _, err := CompareSnapshots(base, next); err != ErrCredential {
			t.Fatal(err)
		}
	}
	base.ResolverVersion = Version
	if _, err := CompareSnapshots(base, base); err != ErrCredential {
		t.Fatal("unversioned comparison", err)
	}
}
