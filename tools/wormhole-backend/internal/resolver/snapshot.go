package resolver

import (
	"strings"
	"unicode/utf8"
)

// EffectiveCredentialSnapshot contains identity metadata only. Version 0 is an
// observation of a legacy walk, version 1 is the new resolver's result. Runtime
// observations are not a complete/coherent migration baseline by themselves.
type EffectiveCredentialSnapshot struct {
	NodeID          string `json:"nodeId"`
	ProtocolPath    string `json:"protocolPath"`
	CredentialID    string `json:"credentialId"`
	Username        string `json:"username"`
	Domain          string `json:"domain"`
	SourceKind      string `json:"sourceKind"`
	ResolverVersion int    `json:"resolverVersion"`
}

func (s EffectiveCredentialSnapshot) Validate() error {
	if !canonicalID(s.NodeID) || s.ResolverVersion < 0 || s.ResolverVersion > Version {
		return ErrCredential
	}
	if !KnownAccountPath(s.ProtocolPath) {
		return ErrCredential
	}
	switch s.SourceKind {
	case "none", "system":
		if s.CredentialID != "" {
			return ErrCredential
		}
	case "inline":
		if s.CredentialID != s.NodeID {
			return ErrCredential
		}
	case "saved":
		if !canonicalID(s.CredentialID) {
			return ErrCredential
		}
	default:
		return ErrCredential
	}
	for _, value := range []string{s.Username, s.Domain} {
		if len(value) > 2048 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return ErrCredential
		}
	}
	return nil
}

// SnapshotDifference is safe for ID-only diagnostics. It never includes either
// username/domain, display names, endpoints, error text or secret material.
type SnapshotDifference struct {
	NodeID            string `json:"nodeId"`
	ProtocolPath      string `json:"protocolPath"`
	OldCredentialID   string `json:"oldCredentialId"`
	NewCredentialID   string `json:"newCredentialId"`
	CredentialChanged bool   `json:"credentialChanged"`
	UsernameChanged   bool   `json:"usernameChanged"`
	DomainChanged     bool   `json:"domainChanged"`
	SourceChanged     bool   `json:"sourceChanged"`
}

func CompareSnapshots(old, next EffectiveCredentialSnapshot) (*SnapshotDifference, error) {
	if old.Validate() != nil || next.Validate() != nil || old.ResolverVersion != 0 || next.ResolverVersion != Version || old.NodeID != next.NodeID || old.ProtocolPath != next.ProtocolPath {
		return nil, ErrCredential
	}
	d := SnapshotDifference{NodeID: old.NodeID, ProtocolPath: old.ProtocolPath, OldCredentialID: old.CredentialID, NewCredentialID: next.CredentialID, CredentialChanged: old.CredentialID != next.CredentialID, UsernameChanged: old.Username != next.Username, DomainChanged: old.Domain != next.Domain, SourceChanged: old.SourceKind != next.SourceKind}
	if !d.CredentialChanged && !d.UsernameChanged && !d.DomainChanged && !d.SourceChanged {
		return nil, nil
	}
	return &d, nil
}
