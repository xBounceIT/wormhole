package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestTreeMetadataVerification(t *testing.T) {
	rows := treeRows()
	metadata, err := parseTreeMetadata(rows[0][6])
	if err != nil {
		t.Fatal(err)
	}
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	defer vault.Wipe(org)
	author := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	defer vault.Wipe(author)
	trust := sharedcatalog.NodeTrust{Workspace: uuid.MustParse(testHintID), Node: uuid.MustParse(treeFirstID), Boundary: uuid.MustParse(testHintID), Author: uuid.New(), AuthorKey: vault.KeyRef{ID: uuid.MustParse(testHintID), Version: 1}, OrganisationKey: vault.KeyRef{ID: uuid.New(), Version: 1}, Organisation: org.Public().(ed25519.PublicKey), MinimumCertificateRevision: 1, MinimumNodeRevision: 3}
	cert, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: vault.FormatVersion, WorkspaceID: trust.Workspace, UserID: trust.Author, Key: trust.AuthorKey, Kind: "user-sign", Suite: 1, PublicKey: author.Public().(ed25519.PublicKey), Revision: 1, Signer: trust.OrganisationKey}, org)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := sharedcatalog.SignNode(trust.Workspace, trust.Boundary, metadata, 3, trust.AuthorKey, author)
	if err != nil {
		t.Fatal(err)
	}
	rows[0][14] = hex.AppendEncode(nil, seal.Signature)
	page, err := parseTreePage(rows, admissionRequest(), TreeCursor{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	wipeQueryRows(rows)
	if err := page.Nodes[0].VerifyMetadata(cert, trust); err != nil {
		t.Fatal(err)
	}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: vault.FormatVersion, WorkspaceID: trust.Workspace, UserID: trust.Author, Sequence: 2, Active: true, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: trust.AuthorKey, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: trust.OrganisationKey}, org)
	if err != nil {
		t.Fatal(err)
	}
	current := sharedcatalog.CurrentNodeTrust{Workspace: trust.Workspace, Node: trust.Node, Boundary: trust.Boundary, Author: trust.Author, OrganisationKey: trust.OrganisationKey, Organisation: trust.Organisation, MinimumStateSequence: 2, MinimumCertificateRevision: 1, MinimumNodeRevision: 3}
	if observed, err := page.Nodes[0].VerifyCurrentMetadata(cert, state, current); err != nil || observed != (sharedcatalog.Observation{StateSequence: 2, CertificateRevision: 1, NodeRevision: 3}) {
		t.Fatal(observed, err)
	}
	page.Nodes[0].Metadata.Name = "redirected label"
	if err := page.Nodes[0].VerifyMetadata(cert, trust); err != vault.ErrAuthentication {
		t.Fatal("tamper accepted", err)
	}
}
