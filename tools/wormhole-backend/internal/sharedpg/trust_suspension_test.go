package sharedpg

import (
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSuspensionRotationIntentSurvivesRestart(t *testing.T) {
	root, binding, initial, account, _, _, _ := accountTrustFixture(t)
	current, err := initial.AdvanceAccount(account, 1)
	if err != nil {
		t.Fatal(err)
	}
	target := uuid.NewString()
	next, err := current.TrackSuspension(target, 2, false)
	if err != nil || current.SuspensionRotations != nil || current.ValidateAdvance(next) != nil {
		t.Fatal("could not durably authorize rotation", err)
	}
	raw, err := SealTrustState(root, binding, next)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenTrustState(root, binding, raw, next.Revision)
	if err != nil || reopened.SuspensionRotations[target] != 2 {
		t.Fatal("lost rotation on reopen", err)
	}
	retry, err := reopened.TrackSuspension(target, 2, false)
	if err != nil || retry.Revision != reopened.Revision {
		t.Fatal("retry changed the trust floor", err)
	}
	newer, err := reopened.TrackSuspension(target, 4, false)
	if err != nil || reopened.SuspensionRotations[target] != 2 || newer.SuspensionRotations[target] != 4 {
		t.Fatal("changed previous confirmation", err)
	}
	for _, finished := range []bool{true, false} {
		stale, err := newer.TrackSuspension(target, 2, finished)
		if err != nil || stale.Revision != newer.Revision || stale.SuspensionRotations[target] != 4 {
			t.Fatal("stale worker altered a new suspension", err)
		}
	}
	done, err := newer.TrackSuspension(target, 4, true)
	if err != nil || done.SuspensionRotations != nil || newer.ValidateAdvance(done) != nil {
		t.Fatal("could not retire matching suspension", err)
	}
	raw, err = SealTrustState(root, binding, done)
	if err != nil {
		t.Fatal(err)
	}
	if reopened, err = OpenTrustState(root, binding, raw, done.Revision); err != nil || reopened.SuspensionRotations != nil {
		t.Fatal("completed rotation resumed", err)
	}
	standard := newer
	standard.UserMinimum = vault.Standard
	if err := standard.ValidateAdvance(done); err != ErrTrustRollback {
		t.Fatal("cleared Standard together with a rotation", err)
	}
	old := newer
	old.FormatVersion = 6
	if old.valid() {
		t.Fatal("legacy document accepted rotation authority")
	}
	for _, invalid := range []struct {
		id       string
		revision uint64
	}{{target, 1}, {target, math.MaxUint64}, {"", 2}, {binding.UserID.String(), 2}} {
		if _, err := current.TrackSuspension(invalid.id, invalid.revision, false); err == nil {
			t.Fatal("accepted invalid scope")
		}
		old = newer
		old.SuspensionRotations = map[string]uint64{invalid.id: invalid.revision}
		if old.valid() {
			t.Fatal("accepted malformed persisted scope")
		}
	}
	full := current
	full.Revision = math.MaxUint64
	if _, err := full.TrackSuspension(target, 2, false); err == nil {
		t.Fatal("trust revision wrapped")
	}
}
