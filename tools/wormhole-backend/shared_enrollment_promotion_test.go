package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type confirmedEnrollmentProbe struct {
	binding sharedpg.TrustBinding
	pending sharedpg.PendingEnrollment
	target  sharedpg.TrustState
}

func (p confirmedEnrollmentProbe) ConfirmedActivation(b sharedpg.TrustBinding, record sharedpg.PendingEnrollment) (sharedpg.TrustState, error) {
	if p.binding != b || !reflect.DeepEqual(p.pending, record) {
		return sharedpg.TrustState{}, sharedpg.ErrTrustState
	}
	return p.target, nil
}
func enrollmentPublicationProof(t *testing.T, b sharedpg.TrustBinding, p sharedpg.PendingEnrollment) confirmedEnrollmentProbe {
	t.Helper()
	target, err := p.ObservedTrust().AdvanceEnrollment(p.Certificate, 1)
	if err != nil {
		t.Fatal(err)
	}
	return confirmedEnrollmentProbe{b, p, target}
}

func TestSharedEnrollmentPromotion(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	proof := enrollmentPublicationProof(t, b, p)
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedTrustConflict {
		t.Fatal("missing pending created trust", err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if err := promoteSharedEnrollment(path, root, b, p, proof); err != nil {
			t.Fatal(err)
		}
		actual, err := readActiveSharedTrustFile(path, root, b, proof.target.Revision)
		if err != nil || !reflect.DeepEqual(actual, proof.target) {
			t.Fatal("wrong activation", err)
		}
		if _, err := os.Lstat(sharedPendingEnrollmentPath(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("journal retained")
		}
	}
}

func TestSharedEnrollmentPromotionDurability(t *testing.T) {
	for _, phase := range []string{"publish", "cleanup", "new-observation"} {
		t.Run(phase, func(t *testing.T) {
			path, root, b, p := sharedPendingFixture(t)
			proof := enrollmentPublicationProof(t, b, p)
			if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
				t.Fatal(err)
			}
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			calls := 0
			failAt := 1
			if phase == "cleanup" {
				failAt = 2
			}
			privateFileDirectorySync = func(string) error {
				calls++
				if calls == failAt {
					return os.ErrPermission
				}
				return nil
			}
			expected := errSharedTrustCommitUncertain
			if phase == "cleanup" {
				expected = errSharedEnrollmentCleanup
			}
			if err := promoteSharedEnrollment(path, root, b, p, proof); err != expected {
				t.Fatal("durability result", err)
			}
			privateFileDirectorySync = syncDirectory
			if phase != "cleanup" {
				if _, err := readActiveSharedTrustFile(path, root, b, 1); err != errSharedEnrollmentPending {
					t.Fatal("partially published trust admitted", err)
				}
			}
			if phase == "new-observation" {
				org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
				defer vault.Wipe(org)
				state := *p.Trust.Account
				state.Sequence++
				state, err := vault.SignUserKeyState(state, org)
				if err != nil {
					t.Fatal(err)
				}
				next, err := p.ObserveAccount(b, state, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeSharedPendingObservation(path, root, b, p, next); err != nil {
					t.Fatal(err)
				}
				if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedTrustConflict {
					t.Fatal("stale proof ignored observation", err)
				}
				p = next
				proof = enrollmentPublicationProof(t, b, p)
			}
			if err := promoteSharedEnrollment(path, root, b, p, proof); err != nil {
				t.Fatal("reconcile publication", err)
			}
			current, err := readActiveSharedTrustFile(path, root, b, proof.target.Revision)
			if err != nil || !reflect.DeepEqual(current, proof.target) {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedEnrollmentPromotionBoundaries(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	proof := enrollmentPublicationProof(t, b, p)
	if err := promoteSharedEnrollment("relative", root, b, p, proof); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, nil); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, (*sharedpg.ConfirmedEnrollment)(nil)); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if _, err := readActiveSharedTrustFile("relative", root, b, 1); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedTrustConflict {
		release()
		t.Fatal(err)
	}
	if _, err := readActiveSharedTrustFile(path, root, b, 1); err != errSharedTrustConflict {
		release()
		t.Fatal(err)
	}
	release()
	if err := os.WriteFile(sharedTrustTransitionPath(path), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedTrustTransitionPending {
		t.Fatal(err)
	}
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, make([]byte, 32), b, p, proof); err != sharedpg.ErrTrustState {
		t.Fatal(err)
	}
	for _, mode := range []string{"corrupt", "no-pin", "foreign-pin", "future", "foreign-policy"} {
		current := proof.target
		switch mode {
		case "corrupt":
			if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
				t.Fatal(err)
			}
		case "no-pin":
			current.Enrollment = nil
			current.FormatVersion = 3
		case "foreign-pin":
			pin := *current.Enrollment
			pin.Encryption.ID = uuid.New()
			current.Enrollment = &pin
		case "future":
			current.Revision++
		case "foreign-policy":
			current.Revision = 1
			current.PolicySequence++ // validly signed newer policy conflicts with the target floor
			org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
			signed, e := vault.DecodeSignedPolicy(current.SignedProfile)
			if e != nil {
				t.Fatal(e)
			}
			signed.Policy.Sequence++
			signed, e = vault.SignPolicy(signed.Policy, current.SignerKeyID, current.SignerKeyVersion, org)
			vault.Wipe(org)
			if e != nil {
				t.Fatal(e)
			}
			current.SignedProfile, e = vault.EncodeSignedPolicy(signed)
			if e != nil {
				t.Fatal(e)
			}
			d := sha256.Sum256(current.SignedProfile)
			current.PolicyDigest = d[:]
		}
		if mode != "corrupt" {
			if err := persistSharedTrustFile(path, root, b, current); err != nil {
				t.Fatal(err)
			}
		}
		if err := promoteSharedEnrollment(path, root, b, p, proof); err == nil {
			t.Fatal("unexpected destination replaced", mode)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedPendingEnrollmentPath(path), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != sharedpg.ErrTrustState {
		t.Fatal(err)
	}
	if err := os.Remove(sharedPendingEnrollmentPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := persistSharedTrustFile(path, root, b, p.Trust); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedTrustConflict {
		t.Fatal("missing journal adopted foreign destination", err)
	}
}

func TestSharedAdmissionBlocksPendingBeforeNetwork(t *testing.T) {
	c, probe, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	if err := os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("pending enrollment marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Open(context.Background(), o, root, probe.expectedMaterial()); err != errSharedEnrollmentPending {
		t.Fatal(err)
	}
	if probe.opens.Load() != 0 || probe.starts.Load() != 0 || c.Admitted() {
		t.Fatal("pending enrollment contacted database")
	}
	// An invalid parent cannot become a trusted state through the active reader.
	if _, err := readActiveSharedTrustFile(filepath.Join(t.TempDir(), "absent", "trust"), root, o.Binding, 1); err != errSharedTrustConflict {
		t.Fatal(err)
	}
}
