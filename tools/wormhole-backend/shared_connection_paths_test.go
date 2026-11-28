package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type sharedPathProbe struct {
	*credentialReleaseProbe
	capability func() (bool, error)
	planPath   func(context.Context, uuid.UUID, string) (*sharedpg.UnverifiedConnectionPlan, error)
	beginPath  func(context.Context, uuid.UUID, string, string) (*sharedpg.UseIntent, error)
}

func (p *sharedPathProbe) ConnectionPathsSupported(context.Context) (bool, error) {
	return p.capability()
}
func (p *sharedPathProbe) ConnectionPlanPath(ctx context.Context, id uuid.UUID, path string) (*sharedpg.UnverifiedConnectionPlan, error) {
	return p.planPath(ctx, id, path)
}
func (p *sharedPathProbe) BeginUsePath(ctx context.Context, id uuid.UUID, source, path string) (*sharedpg.UseIntent, error) {
	return p.beginPath(ctx, id, source, path)
}

func addSharedPathProjection(wire map[string]any, path string, attachment any) {
	metadata := wire["metadata"].(map[string]any)
	chain := metadata["chain"].([]any)
	if len(chain[0].([]any)) == 23 {
		for i, row := range chain {
			chain[i] = append(row.([]any), nil)
		}
		metadata["credential"] = append(metadata["credential"].([]any), nil)
		roots := wire["roots"].([]any)
		roots[0] = append(roots[0].([]any), nil)
		copies := wire["accounts"].([]any)[0].(map[string]any)["copies"].([]any)
		copies[0] = append(copies[0].([]any), nil)
		wire["formatVersion"], wire["nodeFields"], wire["enrollment"] = 5, nil, nil
	}
	metadata["formatVersion"], metadata["tunnel"], metadata["importedData"], metadata["path"] = 4, nil, attachment, path
}

func signSharedPathFixture(t *testing.T, workspace uuid.UUID, signer vault.KeyRef, wire map[string]any, pins []resolver.EffectiveCredentialSnapshot) string {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	row := metadata["chain"].([]any)[0].([]any)
	var leaf vaultstore.NodeMetadata
	if err := json.Unmarshal([]byte(row[4].(string)), &leaf); err != nil {
		t.Fatal(err)
	}
	imported, err := json.Marshal(workspaceimport.NodeData{FormatVersion: 1, NodeID: leaf.ID, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(imported)
	leaf.Imported = &vaultstore.NodeImportReference{Digest: hex.EncodeToString(digest[:]), RetainedPins: true}
	leafRaw, _ := json.Marshal(leaf)
	key := sharedFixtureSigningKey()
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignNode(workspace, uuid.MustParse(row[5].(string)), leaf, 3, signer, key)
	if err != nil {
		t.Fatal(err)
	}
	row[4], row[6], row[11] = string(leafRaw), "3", hex.EncodeToString(seal.Signature)
	return hex.EncodeToString(imported)
}

func TestSharedImportedSSHNativeHandlerUsesTheRequestedAccountPath(t *testing.T) {
	for _, tc := range []struct {
		name, request, actual string
		protocol              int
		sftpOnly              bool
		wantError             bool
	}{
		{"terminal", sharedpg.DefaultConnectionPath, "ssh", 0, false, false},
		{"files-from-ssh-node", sharedpg.DefaultConnectionPath, "ssh", 0, true, false},
		{"sftp-node", sharedpg.DefaultConnectionPath, "sftp", 7, false, false},
		{"wrong-default", sharedpg.DefaultConnectionPath, "sftp", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			fingerprint := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.Binding.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
				n.Protocol, n.SshKnownHostFingerprint = &tc.protocol, &fingerprint
			})
			metadata := wire["metadata"].(map[string]any)
			base := metadata["plan"].(resolver.Plan)
			pins := []resolver.EffectiveCredentialSnapshot{
				{NodeID: node.String(), ProtocolPath: "sftp", SourceKind: "saved", CredentialID: base.Credential.ID, Username: "kept-files-account"},
				{NodeID: node.String(), ProtocolPath: "ssh", SourceKind: "saved", CredentialID: base.Credential.ID, Username: "kept-terminal-account"},
			}
			addSharedPathProjection(wire, resolver.DefaultPath(tc.protocol),
				signSharedPathFixture(t, o.Binding.WorkspaceID, account.Binding.Signing, wire, pins))
			setPath := func(path string) {
				pin, err := resolver.RetainedAccount(base, path, pins)
				if err != nil || pin == nil {
					t.Fatalf("missing fixture pin for %s: %v", path, err)
				}
				metadata["path"], metadata["plan"] = path, resolver.ApplyRetainedAccount(base, *pin)
			}
			oldPlan, oldBegin := p.plan, p.begin
			// The pre-existing endpoint cannot return a plan which ignores a pin.
			p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
				return nil, sharedpg.ErrImportedConnectionPins
			}
			p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("path-aware workspace attempted a path-less release")
				return nil, nil
			}
			plans, releases, probes := 0, 0, 0
			c.session = &sharedPathProbe{credentialReleaseProbe: p,
				capability: func() (bool, error) { probes++; return true, nil },
				planPath: func(ctx context.Context, id uuid.UUID, path string) (*sharedpg.UnverifiedConnectionPlan, error) {
					if path != sharedpg.DefaultConnectionPath || id != node {
						t.Fatal("metadata planning lost the native target")
					}
					plans++
					setPath(resolver.DefaultPath(tc.protocol))
					return oldPlan(ctx, id)
				},
				beginPath: func(ctx context.Context, id uuid.UUID, source, path string) (*sharedpg.UseIntent, error) {
					if path != tc.request || id != node {
						t.Fatal("native SSH handler chose the wrong account path")
					}
					releases++
					setPath(tc.actual)
					intent, err := oldBegin(ctx, id, source)
					intent.Path = tc.actual
					return intent, err
				},
			}
			q, private := sharedSSHRequest(node)
			q.SFTPOnly = tc.sftpOnly
			defer vault.Wipe(private)
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
			ctx := context.Background()
			route, err := h.Handle(ctx, "connection-route", vaultInput(t, sharedPlanPayload(q)))
			if err != nil || string(route) != "null" {
				t.Fatal("imported route could not be planned", err)
			}
			hostRequest := sharedPlanPayload(q)
			hostRequest["route"] = nil
			hostRaw, err := h.Handle(ctx, "ssh-host-plan", vaultInput(t, hostRequest))
			var host localvault.SSHHostPlan
			if err != nil || json.Unmarshal(hostRaw, &host) != nil || host.Fingerprint != fingerprint || releases != 0 {
				t.Fatal("imported host planning opened credentials or lost the host pin", err)
			}
			bundleRequest := sharedPlanPayload(q)
			bundleRequest["sftpOnly"], bundleRequest["publicKey"] = q.SFTPOnly, q.PublicKey
			response, err := h.Handle(ctx, "ssh-bundle", vaultInput(t, bundleRequest))
			if tc.wantError {
				if len(response) != 0 || !errors.Is(err, sharedpg.ErrAdmissionResponse) || c.Unlocked() {
					t.Fatal("a valid signed SFTP graph was used in place of the SSH default", err)
				}
				return
			}
			var result localvault.SSHConnectionBundle
			if err != nil || bytes.Contains(response, []byte("native-connection-secret")) ||
				json.Unmarshal(response, &result) != nil || result.Binding != host.Binding || plans != 2 || releases != 1 || probes != 1 {
				t.Fatal("imported connection did not produce the bound audited bundle", err)
			}
			raw, err := vault.OpenBundle(private, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(raw)
			bundle, err := vault.DecodeSSHBundle(raw)
			want, _ := resolver.RetainedAccount(base, tc.actual, pins)
			if err != nil || bundle.Username != want.Username || bundle.SFTPOnly != q.SFTPOnly {
				t.Fatal("child bundle contained another path's account", err)
			}
		})
	}
}

func TestSharedCredentialPathCapabilityAndReceiptFailures(t *testing.T) {
	for _, tc := range []struct {
		mode                   string
		err                    error
		legacy, began, fetched int
	}{
		{"legacy", nil, 1, 0, 1},
		{"probe-failed", sharedpg.ErrQuery, 0, 0, 0},
		{"issue-failed", sharedpg.ErrAuditUnavailable, 0, 1, 0},
		{"wrong-receipt", sharedpg.ErrAdmissionResponse, 0, 1, 0},
		{"wrong-graph", sharedpg.ErrAdmissionResponse, 0, 1, 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			c, p, _, _, _, _, node, _ := credentialControllerFixture(t, vault.Default)
			legacy, began, fetched := 0, 0, 0
			oldBegin, oldFetch := p.begin, p.fetch
			p.begin = func(ctx context.Context, n uuid.UUID, source string) (*sharedpg.UseIntent, error) {
				legacy++
				return oldBegin(ctx, n, source)
			}
			p.fetch = func(ctx context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				fetched++
				return oldFetch(ctx, intent)
			}
			c.session = &sharedPathProbe{credentialReleaseProbe: p,
				capability: func() (bool, error) {
					if tc.mode == "probe-failed" {
						return false, sharedpg.ErrQuery
					}
					return tc.mode != "legacy", nil
				},
				beginPath: func(ctx context.Context, n uuid.UUID, source, path string) (*sharedpg.UseIntent, error) {
					began++
					if tc.mode == "issue-failed" {
						return nil, sharedpg.ErrAuditUnavailable
					}
					intent, err := oldBegin(ctx, n, source)
					intent.Path = path
					if tc.mode == "wrong-receipt" {
						intent.Path = "ssh"
					}
					return intent, err
				},
			}
			opened := false
			err := c.withConnectionRelease(context.Background(), node, "ui", "sftp", nil,
				func(context.Context, sharedpg.TrustState, *sharedpg.VerifiedCredentialRelease) error {
					opened = true
					return nil
				})
			if !errors.Is(err, tc.err) || opened != (tc.err == nil) || legacy != tc.legacy ||
				began != tc.began || fetched != tc.fetched {
				t.Fatal("connection recovered using an unauthorised path or retried an audit", err)
			}
		})
	}
}
