package sharedcatalog

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func fixture(t *testing.T) (vaultstore.NodeMetadata, vault.RecordSeal, vault.UserKeyCertificate, NodeTrust, ed25519.PrivateKey) {
	t.Helper()
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	trust := NodeTrust{Workspace: uuid.New(), Node: uuid.New(), Boundary: uuid.New(), Author: uuid.New(), AuthorKey: vault.KeyRef{ID: uuid.New(), Version: 1}, OrganisationKey: vault.KeyRef{ID: uuid.New(), Version: 1}, Organisation: org.Public().(ed25519.PublicKey), MinimumCertificateRevision: 3, MinimumNodeRevision: 7}
	certificate, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: vault.FormatVersion, WorkspaceID: trust.Workspace, UserID: trust.Author, Key: trust.AuthorKey, Kind: "user-sign", Suite: 1, PublicKey: key.Public().(ed25519.PublicKey), Revision: 3, Signer: trust.OrganisationKey}, org)
	if err != nil {
		t.Fatal(err)
	}
	node := vaultstore.NodeMetadata{ID: trust.Node.String(), Name: "Server", Kind: 1}
	seal, err := SignNode(trust.Workspace, trust.Boundary, node, 7, trust.AuthorKey, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(org); vault.Wipe(key) })
	return node, seal, certificate, trust, key
}

func TestEveryMetadataFieldSigned(t *testing.T) {
	node, seal, cert, trust, _ := fixture(t)
	if err := VerifyNode(node, trust.Boundary, seal, cert, trust); err != nil {
		t.Fatal(err)
	}
	typeOf := reflect.TypeOf(node)
	for i := 0; i < typeOf.NumField(); i++ {
		t.Run(typeOf.Field(i).Name, func(t *testing.T) {
			changed := node
			field := reflect.ValueOf(&changed).Elem().Field(i)
			name := typeOf.Field(i).Name
			if field.Kind() == reflect.Pointer {
				field.Set(reflect.New(field.Type().Elem()))
				field = field.Elem()
			}
			switch field.Kind() {
			case reflect.String:
				text := "changed"
				if strings.HasSuffix(name, "ID") {
					text = uuid.NewString()
				}
				if name == "SshKnownHostFingerprint" {
					text = ""
				}
				field.SetString(text)
			case reflect.Bool:
				field.SetBool(false)
			case reflect.Int, reflect.Int64:
				value := int64(1)
				switch name {
				case "Kind":
					value = 0
				case "SerialDataBits":
					value = 8
				case "RDPColorDepth":
					value = 16
				}
				field.SetInt(value)
			case reflect.Struct:
				if name != "Imported" {
					t.Fatal("untested field type", name)
				}
				field.Set(reflect.ValueOf(vaultstore.NodeImportReference{Digest: strings.Repeat("ab", 32), RetainedPins: true}))
			default:
				t.Fatal("untested field type", name)
			}
			if name == "CredentialSlotID" {
				mode := 3
				changed.CredentialMode = &mode
			}
			if err := changed.Validate(); err != nil {
				t.Fatal("tamper fixture must remain valid", err)
			}
			if err := VerifyNode(changed, trust.Boundary, seal, cert, trust); err != vault.ErrAuthentication {
				t.Fatal("unsigned field", err)
			}
		})
	}
}

func TestImportedNodeSealRequiresExactPinsReference(t *testing.T) {
	node, _, cert, trust, key := fixture(t)
	node.Imported = &vaultstore.NodeImportReference{Digest: strings.Repeat("ab", 32), RetainedPins: true}
	seal, err := SignNode(trust.Workspace, trust.Boundary, node, 7, trust.AuthorKey, key)
	if err != nil || VerifyNode(node, trust.Boundary, seal, cert, trust) != nil {
		t.Fatal("could not authenticate the imported-node reference", err)
	}
	for _, reference := range []*vaultstore.NodeImportReference{
		nil, {Digest: node.Imported.Digest}, {Digest: strings.Repeat("cd", 32), RetainedPins: true},
	} {
		modified := node
		modified.Imported = reference
		if err := VerifyNode(modified, trust.Boundary, seal, cert, trust); err != vault.ErrAuthentication {
			t.Fatal("the signed node allowed its imported data reference to change", err)
		}
	}
}

func TestNodeSealBindingsAndRollback(t *testing.T) {
	node, seal, cert, trust, key := fixture(t)
	for _, mutate := range []func(*NodeTrust){
		func(v *NodeTrust) { v.Workspace = uuid.New() }, func(v *NodeTrust) { v.Node = uuid.New() }, func(v *NodeTrust) { v.Boundary = uuid.New() }, func(v *NodeTrust) { v.Author = uuid.New() }, func(v *NodeTrust) { v.AuthorKey.Version++ }, func(v *NodeTrust) { v.OrganisationKey.Version++ }, func(v *NodeTrust) { v.Organisation = nil },
	} {
		changed := trust
		mutate(&changed)
		if VerifyNode(node, trust.Boundary, seal, cert, changed) == nil {
			t.Fatal("trust substitution")
		}
	}
	for _, mutate := range []func(*vault.RecordSeal){
		func(v *vault.RecordSeal) { v.FormatVersion++ }, func(v *vault.RecordSeal) { v.FormatVersion = 0 }, func(v *vault.RecordSeal) { v.Revision++ }, func(v *vault.RecordSeal) { v.Revision = 0 }, func(v *vault.RecordSeal) { v.Revision = 1 << 63 }, func(v *vault.RecordSeal) { v.Signature = nil }, func(v *vault.RecordSeal) { s := uuid.NewString(); v.CapabilityID = &s },
	} {
		changed := seal
		mutate(&changed)
		if VerifyNode(node, trust.Boundary, changed, cert, trust) == nil {
			t.Fatal("seal substitution")
		}
	}
	newer := trust
	newer.MinimumNodeRevision++
	if VerifyNode(node, trust.Boundary, seal, cert, newer) != vault.ErrRollback {
		t.Fatal("node replay")
	}
	newer = trust
	newer.MinimumCertificateRevision++
	if VerifyNode(node, trust.Boundary, seal, cert, newer) != vault.ErrRollback {
		t.Fatal("certificate replay")
	}
	for _, bad := range []vault.KeyRef{{}, {ID: uuid.New(), Version: 1 << 31}} {
		if _, err := SignNode(trust.Workspace, trust.Boundary, node, 7, bad, key); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := SignNode(trust.Workspace, trust.Boundary, node, 7, trust.AuthorKey, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := SignNode(uuid.Nil, trust.Boundary, node, 7, trust.AuthorKey, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := SignNode(trust.Workspace, uuid.Nil, node, 7, trust.AuthorKey, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := SignNode(trust.Workspace, trust.Boundary, node, 0, trust.AuthorKey, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	// Resolution-only signatures cannot authenticate a full catalog projection.
	old, err := vault.SignRecord(vault.ResolutionRecord{WorkspaceID: trust.Workspace.String(), NodeID: node.ID, BoundaryID: trust.Boundary.String(), Revision: 7}, trust.AuthorKey.ID.String(), 1, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyNode(node, trust.Boundary, old, cert, trust) != vault.ErrAuthentication {
		t.Fatal("cross-domain signature")
	}
}
