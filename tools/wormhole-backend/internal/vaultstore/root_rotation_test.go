package vaultstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Storage-only fixtures deliberately use opaque ciphertext, like the other
// vaultstore tests. Native owner integration must separately prove cryptography.
func rotationStorageFixture(t *testing.T) (*SQLite, string, RootRotationCounts) {
	t.Helper()
	ctx := context.Background()
	s, path := database(t)
	if err := s.SeedProfile(ctx, []byte("opaque-source-profile")); err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []bool{false, true} {
		c := credential()
		cv := credentialSecret(s, &c, "password")
		if err := s.WriteCredential(ctx, c, []Secret{cv}, 0); err != nil {
			t.Fatal(err)
		}
		v, secret := tunnel(s)
		if err := s.WriteTunnel(ctx, v, &secret, 0); err != nil {
			t.Fatal(err)
		}
		n := node(s)
		nv := nodeSecret(s, &n, "notes")
		if err := s.WriteNode(ctx, n, []Secret{nv}, 0); err != nil {
			t.Fatal(err)
		}
		l, lv := localStateRecord(s)
		if err := s.WriteLocalState(ctx, l, lv, 0); err != nil {
			t.Fatal(err)
		}
		if deleted {
			c.Deleted, c.RowVersion = true, 2
			c.Fields[0].Version, c.Fields[0].Present = 2, false
			cv = next(cv)
			cv.Envelope.Ciphertext = make([]byte, 16)
			if err := s.WriteCredential(ctx, c, []Secret{cv}, 1); err != nil {
				t.Fatal(err)
			}
			v.Deleted, v.RowVersion, v.ConfigurationVersion = true, 2, 2
			secret = next(secret)
			secret.Envelope.Ciphertext = make([]byte, 16)
			if err := s.WriteTunnel(ctx, v, &secret, 1); err != nil {
				t.Fatal(err)
			}
			n.Deleted, n.RowVersion = true, 2
			n.Fields[0].Version, n.Fields[0].Present = 2, false
			nv = next(nv)
			nv.Envelope.Ciphertext = make([]byte, 16)
			if err := s.WriteNode(ctx, n, []Secret{nv}, 1); err != nil {
				t.Fatal(err)
			}
			l.Deleted, l.RowVersion, l.Size = true, 2, 0
			l.Fields[0].Version, l.Fields[0].Present = 2, false
			lv[0] = next(lv[0])
			lv[0].Envelope.Ciphertext = make([]byte, 16)
			if err := s.WriteLocalState(ctx, l, lv, 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	standalone := record(s)
	standalone.Ref.OwnerKind = "slot-value"
	if err := s.WriteSecret(ctx, standalone, 0); err != nil {
		t.Fatal(err)
	}
	return s, path, RootRotationCounts{Credentials: 2, Tunnels: 2, Nodes: 2, LocalStates: 2, Secrets: 9}
}

func storageRotationTransforms(next Identity, rotate bool) RootRotationTransforms {
	seal := func(old []byte) ([]byte, error) {
		if !rotate {
			return old, nil
		}
		return bytes.Repeat([]byte{0x61}, 32), nil
	}
	return RootRotationTransforms{
		Secret: func(value Secret) (Secret, error) {
			if rotate {
				value.DEK.Version++
				value.Envelope.KeyVersion = value.DEK.Version
				value.Envelope.Ciphertext = bytes.Repeat([]byte{0x62}, len(value.Envelope.Ciphertext))
				value.Copy.Key, value.Copy.Holder, value.Copy.Issuer = value.DEK, next.Root, next.Root
				value.Copy.Envelope.KeyID, value.Copy.Envelope.KeyVersion = next.Root.ID, next.Root.Version
				value.Copy.Envelope.Ciphertext = bytes.Repeat([]byte{0x63}, 48)
				value.Copy.Signature = bytes.Repeat([]byte{0x64}, 32)
			}
			return value, nil
		},
		Credential: func(v Credential) ([]byte, error) { return seal(v.Seal) },
		Tunnel:     func(v Tunnel) ([]byte, error) { return seal(v.Seal) },
		Node:       func(v Node) ([]byte, error) { return seal(v.Seal) },
		LocalState: func(v LocalState) ([]byte, error) { return seal(v.Seal) },
		Profile: func(raw []byte) ([]byte, error) {
			if rotate {
				return []byte("opaque-target-profile"), nil
			}
			return raw, nil
		},
	}
}

func TestRootRotationStoragePreservesAllDomainsTombstonesAndSource(t *testing.T) {
	ctx := context.Background()
	s, path, expected := rotationStorageFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	nextIdentity := s.identity
	nextIdentity.Root.Version++
	stagePath := filepath.Join(filepath.Dir(path), "rotation space #.db")
	target, err := s.BeginRootRotation(ctx, stagePath)
	if err != nil {
		t.Fatal("ciphertext snapshot", err)
	}
	defer target.Close()
	if got, err := target.Audit(ctx, storageRotationTransforms(s.identity, false)); err != nil || got != expected {
		t.Fatal("complete source inventory", got, err)
	}
	if got, err := target.Rotate(ctx, nextIdentity, storageRotationTransforms(nextIdentity, true)); err != nil || got != expected {
		t.Fatal("root epoch transformation", got, err)
	}
	if got, err := target.Audit(ctx, storageRotationTransforms(nextIdentity, false)); err != nil || got != expected {
		t.Fatal("complete target inventory", got, err)
	}
	if _, err := target.Rotate(ctx, nextIdentity, storageRotationTransforms(nextIdentity, true)); err != ErrFormat {
		t.Fatal("root transformation replay accepted", err)
	}
	count(t, target.store, `SELECT count(*) FROM Keys`, 10)
	count(t, target.store, `SELECT count(*) FROM KeyCopies`, 9)
	count(t, target.store, `SELECT count(*) FROM Keys WHERE Status<>'active'`, 0)
	count(t, target.store, `SELECT count(*) FROM Nodes WHERE Deleted=1`, 1)
	count(t, target.store, `SELECT count(*) FROM LocalState WHERE Deleted=1`, 1)
	count(t, target.store, `SELECT count(*) FROM CredentialProfiles WHERE Deleted=1`, 1)
	count(t, target.store, `SELECT count(*) FROM TunnelConfigs WHERE Deleted=1`, 1)
	count(t, target.store, `SELECT count(*) FROM SecretValues WHERE RowVersion=2`, 4)
	count(t, target.store, `SELECT count(*) FROM Nodes WHERE SealSignerKeyVersion=2`, 2)
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) || s.identity.Root.Version != 1 {
		t.Fatal("rotation changed original workspace", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(ctx, stagePath, nextIdentity, false)
	if err != nil {
		t.Fatal("completed target cannot reopen", err)
	}
	defer reopened.Close()
	if _, err := OpenSQLite(ctx, stagePath, s.identity, false); !errors.Is(err, ErrBusy) && !errors.Is(err, ErrIdentity) {
		t.Fatal("old identity reopened target", err)
	}
}

func TestRootRotationStorageFailureRollsBackMetadataKeysAndIdentity(t *testing.T) {
	ctx := context.Background()
	s, path, expected := rotationStorageFixture(t)
	target, err := s.BeginRootRotation(ctx, filepath.Join(filepath.Dir(path), "stage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	next := s.identity
	next.Root.Version++
	transforms := storageRotationTransforms(next, true)
	calls := 0
	transform := transforms.Secret
	want := errors.New("native transformation failed")
	transforms.Secret = func(value Secret) (Secret, error) {
		calls++
		if calls == 3 {
			return Secret{}, want
		}
		return transform(value)
	}
	if _, err := target.Rotate(ctx, next, transforms); err != want {
		t.Fatal("partial transformation accepted", err)
	}
	if target.rotated || target.store.identity != s.identity {
		t.Fatal("failed transaction advanced in-memory identity")
	}
	count(t, target.store, `SELECT count(*) FROM Nodes WHERE SealSignerKeyVersion=1`, 2)
	if got, err := target.Audit(ctx, storageRotationTransforms(s.identity, false)); err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatal("rolled-back graph lost data", got, err)
	}
	if got, err := target.Rotate(ctx, next, storageRotationTransforms(next, true)); err != nil || got != expected {
		t.Fatal("explicit retry after rollback", got, err)
	}
}

func TestRootRotationStorageRefusesUnknownSourceStateAndUnsafePaths(t *testing.T) {
	for _, mode := range []string{"table", "column", "view", "trigger", "key-owner", "resolver", "root-header"} {
		t.Run(mode, func(t *testing.T) {
			s, path, _ := rotationStorageFixture(t)
			switch mode {
			case "table":
				exec(t, s, `CREATE TABLE UnknownSecrets(Value BLOB);`)
			case "column":
				exec(t, s, `ALTER TABLE Nodes ADD COLUMN UnknownSecret BLOB;`)
			case "view":
				exec(t, s, `CREATE VIEW UnknownView AS SELECT Id FROM Nodes;`)
			case "trigger":
				exec(t, s, `CREATE TRIGGER Unexpected AFTER UPDATE ON Nodes BEGIN SELECT 1; END;`)
			case "key-owner":
				exec(t, s, `UPDATE Keys SET OwnerId=NULL WHERE KeyId=(SELECT KeyId FROM Keys WHERE Kind='dek' AND Status='active' LIMIT 1);`)
			case "resolver":
				exec(t, s, `UPDATE WorkspaceMeta SET ResolverVersion=2;`)
			case "root-header":
				exec(t, s, `UPDATE WorkspaceMeta SET RootKeyVersion=2;`)
			}
			target := filepath.Join(filepath.Dir(path), "refused.db")
			if stage, err := s.BeginRootRotation(context.Background(), target); err == nil || stage != nil {
				t.Fatal("unsupported state copied", mode, err)
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created a target", err)
			}
		})
	}
	s, path, _ := rotationStorageFixture(t)
	for _, target := range []string{"", "relative.db", path, filepath.Join(filepath.Dir(path), "missing", "target.db")} {
		if stage, err := s.BeginRootRotation(context.Background(), target); err == nil || stage != nil {
			t.Fatal("unsafe target accepted", target, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginRootRotation(ctx, path+".cancel"); err != context.Canceled {
		t.Fatal("cancelled copy", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginRootRotation(context.Background(), path+".closed"); err != ErrClosed {
		t.Fatal("closed source copied", err)
	}
}

func TestRootRotationStorageRejectsInvalidTransformsAtomically(t *testing.T) {
	for _, mode := range []string{"credential", "tunnel", "node", "state", "profile", "seal-size", "profile-size", "secret-context", "secret-revision", "secret-key", "noncanonical", "missing-field", "commit-limit"} {
		t.Run(mode, func(t *testing.T) {
			s, path, expected := rotationStorageFixture(t)
			if mode == "noncanonical" {
				exec(t, s, `UPDATE SecretValues SET Envelope=CAST(Envelope AS TEXT)||' ';`)
			}
			if mode == "missing-field" {
				exec(t, s, `DELETE FROM SecretValues WHERE OwnerKind='node'; DELETE FROM KeyCopies WHERE KeyId NOT IN(SELECT DekId FROM SecretValues); DELETE FROM Keys WHERE Kind='dek' AND KeyId NOT IN(SELECT DekId FROM SecretValues);`)
			}
			if mode == "commit-limit" {
				exec(t, s, `UPDATE WorkspaceMeta SET ChangeSeq=9223372036854775807;`)
			}
			target, err := s.BeginRootRotation(context.Background(), filepath.Join(filepath.Dir(path), "stage.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			next := s.identity
			next.Root.Version++
			transforms := storageRotationTransforms(next, true)
			denied := errors.New("native source denied")
			switch mode {
			case "credential":
				transforms.Credential = func(Credential) ([]byte, error) { return nil, denied }
			case "tunnel":
				transforms.Tunnel = func(Tunnel) ([]byte, error) { return nil, denied }
			case "node":
				transforms.Node = func(Node) ([]byte, error) { return nil, denied }
			case "state":
				transforms.LocalState = func(LocalState) ([]byte, error) { return nil, denied }
			case "profile":
				transforms.Profile = func([]byte) ([]byte, error) { return nil, denied }
			case "seal-size":
				transforms.Credential = func(Credential) ([]byte, error) { return []byte{1}, nil }
			case "profile-size":
				transforms.Profile = func([]byte) ([]byte, error) { return nil, nil }
			case "secret-context", "secret-revision", "secret-key":
				base := transforms.Secret
				transforms.Secret = func(v Secret) (Secret, error) {
					value, err := base(v)
					if mode == "secret-context" {
						value.Ref.Field += "-foreign"
					} else if mode == "secret-revision" {
						value.RowVersion++
					} else {
						value.Copy.Holder = s.identity.Root
					}
					return value, err
				}
			}
			if _, err := target.Rotate(context.Background(), next, transforms); err == nil || target.rotated || target.store.identity != s.identity {
				t.Fatal("invalid transform committed", mode, err)
			}
			if mode != "noncanonical" && mode != "missing-field" {
				if got, err := target.Audit(context.Background(), storageRotationTransforms(s.identity, false)); err != nil || got != expected {
					t.Fatal("failure damaged copied graph", got, err)
				}
			}
		})
	}
}

func TestRootRotationStorageEpochBoundsAndClosedTargets(t *testing.T) {
	s, path, _ := rotationStorageFixture(t)
	target, err := s.BeginRootRotation(context.Background(), path+".stage")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	next := s.identity
	next.Root.Version++
	for _, change := range []func(*Identity){
		func(i *Identity) { i.WorkspaceID = identity().WorkspaceID },
		func(i *Identity) { i.FileID = identity().FileID },
		func(i *Identity) { i.Root.ID = identity().Root.ID },
		func(i *Identity) { i.Root.Version = 0 },
	} {
		bad := next
		change(&bad)
		if _, err := target.Rotate(context.Background(), bad, storageRotationTransforms(next, true)); err != ErrFormat {
			t.Fatal("foreign epoch accepted", err)
		}
	}
	if _, err := target.Rotate(context.Background(), next, RootRotationTransforms{}); err != ErrFormat {
		t.Fatal("missing native transforms accepted", err)
	}
	if _, err := target.Audit(context.Background(), RootRotationTransforms{}); err != ErrFormat {
		t.Fatal("missing native checks accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := target.Rotate(ctx, next, storageRotationTransforms(next, true)); err != context.Canceled {
		t.Fatal("cancelled target mutated", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []*RootRotationTarget{nil, {}, target} {
		if _, err := stage.Rotate(context.Background(), next, storageRotationTransforms(next, true)); err != ErrClosed {
			t.Fatal("closed target mutated", err)
		}
		if _, err := stage.Audit(context.Background(), storageRotationTransforms(next, false)); err != ErrClosed {
			t.Fatal("closed target checked", err)
		}
		if err := stage.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
