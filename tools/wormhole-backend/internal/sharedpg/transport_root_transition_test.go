package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func transportTransitionFixture(t *testing.T) ([]byte, []byte, TrustBinding, TrustState, []byte, []byte) {
	t.Helper()
	t.Setenv("PGSERVICE", "")
	old, b, base, account, _, _, _ := accountTrustFixture(t)
	current, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := SealTrustState(old, b, current)
	if err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = TLSVerified
	s.CAPEM = testCA(t)
	setup, err := SealTransportSetup(old, b, s, current, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	return old, bytes.Repeat([]byte{91}, 32), b, current, previous, setup
}

func TestTransportRootTransitionRoundtrip(t *testing.T) {
	old, next, b, current, previous, setup := transportTransitionFixture(t)
	// Rewrapping authenticated metadata must not consult pgx or ambient services.
	t.Setenv("PGSERVICE", "unavailable")
	record, raw, err := PrepareTrustRootTransitionWithSetup(old, next, b, previous, setup, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustRootTransition(next, b, raw)
	if err != nil || !reflect.DeepEqual(record, restored) || record.FormatVersion != 2 {
		t.Fatal("roundtrip", err)
	}
	digest := sha256.Sum256(setup)
	if !bytes.Equal(record.Transport.PreviousDigest, digest[:]) {
		t.Fatal("source commitment")
	}
	target, err := restored.TransportCiphertext(next, b)
	if err != nil {
		t.Fatal(err)
	}
	oldPlain, err := openTransportSetupPayload(old, b, setup)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(oldPlain)
	newPlain, err := openTransportSetupPayload(next, b, target)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(newPlain)
	if !bytes.Equal(oldPlain, newPlain) {
		t.Fatal("metadata changed during rewrap")
	}
	if _, err := openTransportSetupPayload(old, b, target); err == nil {
		t.Fatal("old root opened target")
	}
	if _, err := restored.TransportCiphertext(old, b); err == nil {
		t.Fatal("wrong target root accepted")
	}
	target[0] ^= 1
	if bytes.Equal(target, record.Transport.Next) {
		t.Fatal("returned target aliases journal")
	}
	updated, err := record.ObserveAccount(b, *current.Account, current.WrappingRevision)
	if err != nil || record.ValidateObservationAdvance(b, updated) != nil || !reflect.DeepEqual(updated.Transport, record.Transport) {
		t.Fatal("observation lost setup", err)
	}
	altered := record
	copyTransport := *record.Transport
	altered.Transport = &copyTransport
	altered.Transport.PreviousDigest = bytes.Repeat([]byte{0}, 32)
	if record.ValidateObservationAdvance(b, altered) == nil {
		t.Fatal("observation rewrote setup commitment")
	}
	legacy, _, err := PrepareTrustRootTransition(old, next, b, previous, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := legacy.TransportCiphertext(next, b); err != nil || raw != nil {
		t.Fatal("legacy invented setup", err)
	}
}

func TestTransportRootTransitionBoundaries(t *testing.T) {
	old, next, b, current, previous, setup := transportTransitionFixture(t)
	for _, mode := range []string{"old-root", "new-root", "previous", "source", "payload", "noncanonical", "version", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			source := setup
			oldKey := old
			newKey := next
			trust := previous
			switch mode {
			case "old-root":
				oldKey = nil
			case "new-root":
				newKey = nil
			case "previous":
				trust = []byte("invalid")
			case "source":
				source = []byte("invalid")
			default:
				plain, err := openTransportSetupPayload(old, b, setup)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(plain)
				switch mode {
				case "payload":
					plain = []byte("{")
				case "noncanonical":
					plain = append(plain, ' ')
				case "version":
					var p transportSnapshot
					if err := json.Unmarshal(plain, &p); err != nil {
						t.Fatal(err)
					}
					p.FormatVersion = 3
					plain, _ = json.Marshal(p)
				case "oversize":
					plain = make([]byte, MaxTransportSnapshotBytes+1)
				}
				source, err = sealTransportSetupPayload(old, b, plain)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := PrepareTrustRootTransitionWithSetup(oldKey, newKey, b, trust, source, current.Revision); err == nil {
				t.Fatal("accepted", mode)
			}
		})
	}
	record, _, err := PrepareTrustRootTransitionWithSetup(old, next, b, previous, setup, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "legacy-with-setup", "digest", "target", "target-oversize", "wrong-target-root"} {
		t.Run(mode, func(t *testing.T) {
			changed := record
			transport := *record.Transport
			changed.Transport = &transport
			switch mode {
			case "missing":
				changed.Transport = nil
			case "legacy-with-setup":
				changed.FormatVersion = 1
			case "digest":
				transport.PreviousDigest = nil
			case "target":
				transport.Next = []byte("bad")
			case "target-oversize":
				transport.Next = make([]byte, MaxTransportSnapshotBytes*2+1)
			case "wrong-target-root":
				transport.Next = setup
			}
			if _, err := SealTrustRootTransition(next, b, changed); err == nil {
				t.Fatal("sealed invalid target", mode)
			}
			if _, err := changed.TransportCiphertext(next, b); err == nil {
				t.Fatal("returned invalid target", mode)
			}
		})
	}
}
