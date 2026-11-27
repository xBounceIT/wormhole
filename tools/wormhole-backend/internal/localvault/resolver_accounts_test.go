package localvault

import (
	"bytes"
	"context"
	"runtime"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func installAccountMigration(t *testing.T, o *Owner, n vaultstore.Node, oldChoices map[string]resolver.EffectiveCredentialSnapshot) (vaultstore.Node, resolver.MigrationPlan) {
	t.Helper()
	paths := []string{"reveal"}
	switch *n.Protocol {
	case 0, 7:
		paths = append(paths, "ssh", "sftp")
	case 1:
		paths = append(paths, "rdp", "rdp-gateway")
	case 6:
		paths = append(paths, "vnc")
	}
	var old, next []resolver.EffectiveCredentialSnapshot
	for _, path := range paths {
		r, err := o.ResolveConnectionPath(context.Background(), n.ID, "", path)
		if err != nil {
			t.Fatal(err)
		}
		before := r.Account
		if choice, ok := oldChoices[path]; ok {
			before = choice
		}
		before.NodeID, before.ProtocolPath, before.ResolverVersion = n.ID, path, 0
		old, next = append(old, before), append(next, r.Account)
	}
	plan, err := resolver.BuildMigration(o.store.Identity().WorkspaceID, old, next)
	if err != nil {
		t.Fatal(err)
	}
	written, err := o.ImportResolverMigration(context.Background(), n.ID, plan, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	return written, plan
}

func TestPinnedAccountsAreIndependentAndUseCurrentSecretRevision(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	plan, err := plan.Decide(plan.Fingerprint, []resolver.MigrationDecision{{NodeID: n.ID, ProtocolPath: "sftp", Choice: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != nil {
		t.Fatal(err)
	}
	assertAccount := func(path, user, password string, version int) {
		t.Helper()
		var borrowed []byte
		err := o.WithConnectionSecret(ctx, n.ID, "", path, "password", func(r Resolution, value []byte) error {
			borrowed = value
			if r.Plan.Username != user || string(value) != password || r.Account.ResolverVersion != version || r.Account.ProtocolPath != path {
				t.Fatal("path identity or secret mismatch", path)
			}
			return nil
		})
		if err != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("failed release or retained secret", err)
		}
	}
	assertAccount("ssh", "old-identity-never-write-clear", "pinned-secret", 0)
	assertAccount("reveal", "old-identity-never-write-clear", "pinned-secret", 0)
	assertAccount("sftp", "", "candidate-secret", 1)
	metadata := c.CredentialMetadata
	metadata.Username = "renamed-profile-user"
	if _, err := o.PutCredential(ctx, metadata, []SecretChange{{Field: "password", Value: []byte("rotated-secret")}}, 1); err != nil {
		t.Fatal(err)
	}
	assertAccount("ssh", "old-identity-never-write-clear", "rotated-secret", 0)
	if _, err := o.ResolveConnectionPath(ctx, n.ID, "", ""); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "rdp", "password", func(Resolution, []byte) error { t.Fatal("wrong path released"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "", "password", func(Resolution, []byte) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}

func TestAccountProjectionPreservesInheritedChoiceOwner(t *testing.T) {
	o, _, _, _ := owner(t)
	n, parent, c, _ := resolutionFixture(t, o)
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		r, err := o.ResolveConnectionPath(context.Background(), n.ID, "", path)
		if err != nil || r.Plan.Credential.NodeID != parent.ID {
			t.Fatal("inherited choice owner changed", path, err)
		}
		r, err = o.ResolveConnectionPath(context.Background(), n.ID, c.ID, path)
		if err != nil || r.Plan.Credential.NodeID != n.ID || r.Plan.Credential.Kind != "override" {
			t.Fatal("override did not stay at leaf", path, err)
		}
	}
	n.Protocol = nodePtr(0)
	updated, err := o.PutNode(context.Background(), n.NodeMetadata, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	updated, plan := installAccountMigration(t, o, updated, map[string]resolver.EffectiveCredentialSnapshot{"ssh": {SourceKind: "saved", CredentialID: c.ID, Username: "legacy-user"}})
	if r, err := o.ResolveConnection(context.Background(), n.ID, ""); err != nil || r.Plan.Credential.NodeID != n.ID {
		t.Fatal("pin was not an explicit leaf choice", err)
	}
	if _, err := o.DecideResolverMigration(context.Background(), n.ID, updated.RowVersion, plan.Fingerprint, []resolver.MigrationDecision{{NodeID: n.ID, ProtocolPath: "ssh", Choice: "new"}}); err != nil {
		t.Fatal(err)
	}
	if r, err := o.ResolveConnection(context.Background(), n.ID, ""); err != nil || r.Plan.Credential.NodeID != parent.ID {
		t.Fatal("new choice did not restore inheritance", err)
	}
}

func TestPinnedGatewayAndOverrideStaySeparate(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate", true: "same"}[same], func(t *testing.T) {
			ctx := context.Background()
			o, _, _, _ := owner(t)
			makeCredential := func(user string) vaultstore.Credential {
				m := draft()
				m.Protocol = "rdp"
				m.Username = user
				c, err := o.PutCredential(ctx, m, []SecretChange{{Field: "password", Value: []byte(user + "-password")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			candidate, oldMain, oldGateway, override := makeCredential("candidate"), makeCredential("old-main"), makeCredential("old-gateway"), makeCredential("override")
			m := nodeDraft()
			m.Protocol = nodePtr(1)
			m.CredentialID = &candidate.ID
			m.RDPGatewayUsageMethod = nodePtr(1)
			m.RDPGatewayHostname = nodePtr("gateway.example")
			m.RDPGatewayUseSameCreds = &same
			m.RDPGatewayCredentialID = &candidate.ID
			n, err := o.PutNode(ctx, m, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{
				"rdp":         {SourceKind: "saved", CredentialID: oldMain.ID, Username: "pinned-main", Domain: "OLD"},
				"rdp-gateway": {SourceKind: "saved", CredentialID: oldGateway.ID, Username: `EDGE\pinned-gateway`},
			})
			for _, over := range []string{"", override.ID} {
				for _, path := range []string{"rdp", "rdp-gateway"} {
					wantID, wantUser, wantPassword := oldMain.ID, "pinned-main", "old-main-password"
					if path == "rdp-gateway" {
						wantID, wantUser, wantPassword = oldGateway.ID, `EDGE\pinned-gateway`, "old-gateway-password"
					}
					if over != "" && (path != "rdp-gateway" || same) {
						wantID, wantUser, wantPassword = override.ID, "override", "override-password"
					}
					err := o.WithConnectionSecret(ctx, n.ID, over, path, "password", func(r Resolution, value []byte) error {
						if r.Plan.Credential.ID != wantID || r.Plan.Username != wantUser || string(value) != wantPassword {
							t.Fatal("wrong gateway/override account", path, over)
						}
						if over == "" && (r.Plan.GatewaySameCredentials || r.GatewayAccount.CredentialID != oldGateway.ID) {
							t.Fatal("distinct gateway pin collapsed")
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestPinnedRevealCanPreserveHistoricalCrossProtocolAccount(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	candidate := draft()
	candidate.Protocol = "rdp"
	c, err := o.PutCredential(ctx, candidate, []SecretChange{{Field: "password", Value: []byte("rdp-reveal-password")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.CredentialMode = nodePtr(1)
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"reveal": {SourceKind: "saved", CredentialID: c.ID, Username: "historical", Domain: "CORP"}})
	if err := o.WithConnectionSecret(ctx, n.ID, "", "reveal", "password", func(r Resolution, value []byte) error {
		if r.Plan.Username != "historical" || r.Plan.Domain != "CORP" || string(value) != "rdp-reveal-password" {
			t.Fatal("historical Reveal lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(Resolution, []byte) error { t.Fatal("Reveal choice leaked to SSH"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestPinnedNoneInlineAndSystemSources(t *testing.T) {
	ctx := context.Background()
	t.Run("vnc-none", func(t *testing.T) {
		o, _, _, _ := owner(t)
		m := draft()
		m.Protocol = "vnc"
		c, err := o.PutCredential(ctx, m, []SecretChange{{Field: "password", Value: []byte("vnc-password")}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		nm := nodeDraft()
		nm.Protocol = nodePtr(6)
		nm.CredentialID = &c.ID
		n, err := o.PutNode(ctx, nm, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, plan := installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"vnc": {SourceKind: "none"}})
		if err := o.WithConnectionSecret(ctx, n.ID, "", "vnc", "password", func(Resolution, []byte) error { t.Fatal("none fell back to candidate"); return nil }); err != vaultstore.ErrMissing {
			t.Fatal(err)
		}
		if _, err := o.DecideResolverMigration(ctx, n.ID, n.RowVersion, plan.Fingerprint, []resolver.MigrationDecision{{NodeID: n.ID, ProtocolPath: "vnc", Choice: "new"}}); err != nil {
			t.Fatal(err)
		}
		if err := o.WithConnectionSecret(ctx, n.ID, "", "vnc", "password", func(r Resolution, value []byte) error {
			if string(value) != "vnc-password" || r.Plan.Username != "" {
				t.Fatal("new VNC choice")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("inline", func(t *testing.T) {
		o, _, _, _ := owner(t)
		m := nodeDraft()
		m.UseInlinePassword = nodePtr(true)
		m.Username = nodePtr("new-user")
		n, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("inline-password")}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"ssh": {SourceKind: "inline", CredentialID: n.ID, Username: "old-inherited-user"}})
		if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(r Resolution, value []byte) error {
			if r.Plan.Username != "old-inherited-user" || string(value) != "inline-password" {
				t.Fatal("inline pin ignored")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	for _, source := range []string{"system", "azuread"} {
		t.Run(source, func(t *testing.T) {
			o, _, _, _ := owner(t)
			m := draft()
			m.Protocol = "rdp"
			c, err := o.PutCredential(ctx, m, []SecretChange{{Field: "password", Value: []byte("rdp-password")}}, 0)
			if err != nil {
				t.Fatal(err)
			}
			nm := nodeDraft()
			nm.Protocol = nodePtr(1)
			nm.CredentialID = &c.ID
			n, err := o.PutNode(ctx, nm, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			old := resolver.EffectiveCredentialSnapshot{SourceKind: "system"}
			if source == "azuread" {
				old = resolver.EffectiveCredentialSnapshot{SourceKind: "saved", CredentialID: c.ID, Username: "azure-user", Domain: "AzureAD"}
			}
			n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"rdp": old})
			want := error(nil)
			if source == "system" || runtime.GOOS == "windows" {
				want = vault.ErrPolicy
			}
			if err := o.WithConnectionSecret(ctx, n.ID, "", "rdp", "password", func(Resolution, []byte) error {
				if want != nil {
					t.Fatal("system-client secret released")
				}
				return nil
			}); err != want {
				t.Fatal(err)
			}
		})
	}
}

func TestPinnedResolutionRejectsTamperingAndIncompatibleProtocol(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, _, plan := nodeMigrationFixture(t, o)
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != nil {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	for _, filter := range []nodeFilter{
		{completeNodeStore: store, secret: func(s vaultstore.Secret) (vaultstore.Secret, error) { return s, vaultstore.ErrMissing }},
		{completeNodeStore: store, credential: func(c vaultstore.Credential) (vaultstore.Credential, error) { c.Username = "tampered"; return c, nil }},
	} {
		o.store = filter
		if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(Resolution, []byte) error { t.Fatal("tampered pin fell back"); return nil }); err == nil {
			t.Fatal("tampered pin accepted")
		}
	}
	o.store = store
	m := n.NodeMetadata
	m.Protocol = nodePtr(6)
	m.UseInlinePassword = nodePtr(false)
	if _, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Remove: true}}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ResolveConnection(ctx, n.ID, ""); err != vault.ErrPolicy {
		t.Fatal("old SSH pins applied to VNC", err)
	}
	var choices []resolver.MigrationDecision
	for _, entry := range plan.Entries {
		choices = append(choices, resolver.MigrationDecision{NodeID: n.ID, ProtocolPath: entry.Legacy.ProtocolPath, Choice: "new"})
	}
	if _, err := o.DecideResolverMigration(ctx, n.ID, 3, plan.Fingerprint, choices); err != nil {
		t.Fatal(err)
	}
	if resolved, err := o.ResolveConnection(ctx, n.ID, ""); err != nil || resolved.Account.ProtocolPath != "vnc" || resolved.Account.SourceKind != "none" {
		t.Fatal("retired pins still affected new protocol", err)
	}
}
