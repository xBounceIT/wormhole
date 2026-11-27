package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceRecoveryKitRefreshKeepsOriginalRecoveryCode(t *testing.T) {
	current, previous, organisation, keys := workspaceRotationFixture(t, serverCertNow)
	recovery := vault.NewRecoveryKey()
	defer vault.Wipe(recovery)
	code, err := vault.FormatRecoveryKey(recovery)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	capsule, err := vault.SealOrganisationRecovery(recovery, organisation, keys)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := encodeWorkspaceBootstrapRecovery(capsule, &previous)
	if err != nil {
		t.Fatal(err)
	}
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	old := workspaceRecoveryKit{Version: 2, Workspace: organisation.WorkspaceID, Encryption: organisation.Encryption,
		Signing: organisation.Signing, Public: public, Capsule: capsule,
		CA: &workspaceRecoveryCA{Certificate: current.bundle.workspaceIssuer(), Key: previous}}
	_, serverKey := serverIssuer(t, nil)
	rotation, err := prepareWorkspaceCARotation(current, previous, organisation, keys, serverRequest(t, serverKey, nil), serverCertNow)
	if err != nil {
		t.Fatal(err)
	}
	stable := rotation.overlap.bundle
	stable.Sequence++
	stable.CAs = [][]byte{stable.workspaceIssuer()}
	stable.WorkspaceCA = &WorkspaceTLSCA{Key: rotation.key.Key, IssuingCA: stable.WorkspaceCA.IssuingCA}
	final, err := rotation.overlap.signCAUpdate(stable, keys.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	material := &serverCertificateRenewalMaterial{organisation: organisation.Encryption, ca: rotation.key}
	updated, err := refreshWorkspaceRecoveryKit(old, final, material, bootstrap, keys.EncryptionPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenWorkspaceRecoveryKit(organisation.WorkspaceID, updated, code)
	if err != nil {
		t.Fatal("the original recovery code cannot open the new authority", err)
	}
	defer recovered.Wipe()
	if !bytes.Equal(recovered.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(recovered.SigningSeed, keys.SigningSeed) {
		t.Fatal("organisation keys changed")
	}
	actual, err := decodeWorkspaceRecoveryKit(organisation.WorkspaceID, updated)
	if err != nil || !reflect.DeepEqual(actual.Capsule, capsule) || actual.CA.Key.Key != rotation.key.Key ||
		!bytes.Equal(actual.CA.Certificate, stable.CAs[0]) || bytes.Equal(actual.CA.Certificate, old.CA.Certificate) {
		t.Fatal("refresh failed to preserve the capsule and replace the CA", err)
	}
	again, err := refreshWorkspaceRecoveryKit(actual, final, material, bootstrap, keys.EncryptionPrivate)
	if err != nil || !bytes.Equal(updated, again) {
		t.Fatal("refresh of the current recovery kit was not idempotent", err)
	}
	for name, mutate := range map[string]func(*workspaceRecoveryKit){
		"foreign encryption key": func(k *workspaceRecoveryKit) { k.Encryption.ID = uuid.New() },
		"substituted encryption": func(k *workspaceRecoveryKit) { k.Public.Encryption = make([]byte, 32) },
		"substituted capsule": func(k *workspaceRecoveryKit) {
			k.Capsule.Ciphertext = bytes.Clone(k.Capsule.Ciphertext)
			k.Capsule.Ciphertext[0] ^= 1
		},
		"old certificate replaced": func(k *workspaceRecoveryKit) {
			k.CA = &workspaceRecoveryCA{Certificate: stable.CAs[0], Key: previous}
		},
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := old
			mutate(&corrupt)
			if _, err := refreshWorkspaceRecoveryKit(corrupt, final, material, bootstrap, keys.EncryptionPrivate); !errors.Is(err, ErrWorkspaceRecoveryKit) {
				t.Fatal("an invalid input recovery kit was accepted", err)
			}
		})
	}
	if _, err := refreshWorkspaceRecoveryKit(old, final, material, []byte("{}"), keys.EncryptionPrivate); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("malformed server capsule accepted", err)
	}
	for _, ca := range []workspaceCAKeyCopy{
		previous, {Key: rotation.key.Key, Copy: previous.Copy},
	} {
		invalid := *material
		invalid.ca = ca
		if _, err := refreshWorkspaceRecoveryKit(old, final, &invalid, bootstrap, keys.EncryptionPrivate); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("a wrong CA copy was exported", err)
		}
	}
}

func TestWorkspaceRecoveryKitRefreshRejectsMalformedProjectionAndUntrustedContext(t *testing.T) {
	_, ca, organisation, _ := workspaceRotationFixture(t, serverCertNow)
	caWire, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	encoded := func(n int) []byte { return hex.AppendEncode(nil, bytes.Repeat([]byte{4}, n)) }
	row := [][]byte{[]byte(organisation.Encryption.ID.String()), []byte("1"), encoded(32), encoded(48), encoded(64), caWire, []byte("a1")}
	got, bootstrap, err := parseWorkspaceRecoveryKitRefresh([][][]byte{row})
	if err != nil || got.ca.Key != ca.Key || !bytes.Equal(bootstrap, []byte{0xa1}) {
		t.Fatal("recovery projection changed", err)
	}
	for _, wire := range [][][][]byte{
		nil, {row, row}, {row[:6]},
		{append(row[:6:6], nil)}, {append(row[:6:6], []byte("xx"))}, {append(row[:6:6], encoded(maxBootstrapRecoveryBytes+1))},
		{append(row[:5:5], []byte("{}"), row[6])},
	} {
		if _, _, err := parseWorkspaceRecoveryKitRefresh(wire); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("invalid recovery projection accepted", err)
		}
	}
	var s Session
	private := make([]byte, 32)
	if _, err := s.RefreshWorkspaceRecoveryKit(context.Background(), TrustState{}, nil, nil, private, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing resident signing seed accepted", err)
	}
	if _, err := s.RefreshWorkspaceRecoveryKit(context.Background(), TrustState{}, nil, nil, private, private); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("unauthenticated workspace accepted", err)
	}
}
