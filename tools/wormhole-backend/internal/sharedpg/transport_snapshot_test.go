package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestTransportSetupRoundTrip(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pinned-ca", true: "managed"}[managed], func(t *testing.T) {
			root, b, trust, _, org, _, _ := accountTrustFixture(t)
			s := settings()
			s.TLS = TLSVerified
			s.CAPEM = testCA(t)
			if managed {
				s.CAPEM = nil
				s.TLSBundle = trustedTLSFixture(t, trust, org, 3)
				var e error
				trust, e = trust.AdvanceTLS(s.TLSBundle)
				if e != nil {
					t.Fatal(e)
				}
			}
			raw, err := SealTransportSetup(root, b, s, trust, vault.Default, vault.Standard, 1)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(s.Database)) || bytes.Contains(raw, []byte(s.Endpoints[0].Host)) {
				t.Fatal("plaintext setup")
			}
			restored, err := OpenTransportSetup(root, b, raw, trust, vault.Default, vault.Standard, 1)
			if err != nil {
				t.Fatal(err)
			}
			if restored.Profile != vault.Standard || restored.DeviceRole != s.DeviceRole || restored.Database != s.Database || !reflect.DeepEqual(restored.Endpoints, s.Endpoints) {
				t.Fatal("lost transport", restored)
			}
			if managed {
				if restored.TLSBundle == nil || !bytes.Equal(restored.TLSBundle.Encode(), s.TLSBundle.Encode()) || len(restored.CAPEM) != 0 {
					t.Fatal("lost managed TLS")
				}
			} else if !bytes.Equal(restored.CAPEM, s.CAPEM) {
				t.Fatal("lost static roots")
			}
			if _, err := OpenTransportSetup(root, b, raw, trust, vault.Default, vault.Standard, 99); err == nil {
				t.Fatal("ignored current API floor")
			}
			if _, err := OpenTrustState(root, b, raw, 1); err == nil {
				t.Fatal("setup substituted for trust")
			}
			if _, err := OpenPendingEnrollment(root, b, raw); err == nil {
				t.Fatal("setup substituted for pending")
			}
			if managed {
				newer, err := trust.AdvanceTLS(trustedTLSFixture(t, trust, org, 4))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := OpenTransportSetup(root, b, raw, newer, vault.Default, vault.Default, 1); err == nil {
					t.Fatal("stale setup ignored TLS floor")
				}
			}
		})
	}
}

func TestTransportSnapshotBoundaries(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	_, _, trust, _, org, _, _ := accountTrustFixture(t)
	s := settings()
	s.TLS = TLSVerified
	s.CAPEM = nil
	s.TLSBundle = trustedTLSFixture(t, trust, org, 3)
	if _, err := EncodeTransportSnapshot(s, trust, vault.Default, vault.Default, 1); err != ErrTrustState {
		t.Fatal("unpersisted bundle", err)
	}
	var err error
	trust, err = trust.AdvanceTLS(s.TLSBundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeTransportSnapshot(s, trust, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"empty", "oversize", "malformed", "version", "unknown", "duplicate", "whitespace", "ca-with-bundle", "tls-off", "no-bundle", "forged", "bad-host", "bad-policy", "bad-api"} {
		t.Run(mode, func(t *testing.T) {
			input := bytes.Clone(raw)
			current := trust
			api := int32(1)
			var record transportSnapshot
			if err := json.Unmarshal(input, &record); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "empty":
				input = nil
			case "oversize":
				input = make([]byte, MaxTransportSnapshotBytes+1)
			case "malformed":
				input = []byte("{")
			case "unknown":
				input = append([]byte(`{"unknown":0,`), raw[1:]...)
			case "duplicate":
				input = append([]byte(`{"formatVersion":1,`), raw[1:]...)
			case "whitespace":
				input = append(input, ' ')
			case "bad-policy":
				current.SignedProfile = nil
			case "bad-api":
				api = 0
			default:
				switch mode {
				case "version":
					record.FormatVersion = 3
				case "ca-with-bundle":
					record.CAPEM = testCA(t)
				case "tls-off":
					record.TLS = TLSOff
				case "no-bundle":
					record.Bundle = nil
				case "forged":
					record.Bundle[len(record.Bundle)-3] ^= 1
				case "bad-host":
					record.Endpoints[0].Host = "attacker.example.test"
				}
				input, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := DecodeTransportSnapshot(input, current, vault.Default, vault.Default, api); err == nil {
				t.Fatal("accepted", mode)
			}
		})
	}
	if _, err := EncodeTransportSnapshot(Settings{}, trust, vault.Default, vault.Default, 1); err == nil {
		t.Fatal("encoded invalid settings")
	}
}

func TestTransportSetupAuthentication(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	root, b, trust, _, _, _ := trustFixture(t)
	s := settings()
	s.TLS = TLSVerified
	s.CAPEM = testCA(t)
	raw, err := SealTransportSetup(root, b, s, trust, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"root", "invalid-root", "device", "key", "workspace", "nil-binding", "missing", "oversize", "malformed", "unknown", "ciphertext", "trust-domain"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Clone(root)
			binding := b
			input := bytes.Clone(raw)
			switch mode {
			case "root":
				key[0] ^= 1
			case "invalid-root":
				key = nil
			case "device":
				binding.DeviceID = uuid.New()
			case "key":
				binding.KeyID = uuid.New()
			case "workspace":
				binding.WorkspaceID = uuid.New()
			case "nil-binding":
				binding.KeyID = uuid.Nil
			case "missing":
				input = nil
			case "oversize":
				input = make([]byte, MaxTransportSnapshotBytes*2+1)
			case "malformed":
				input = []byte("{")
			case "unknown":
				input = append([]byte(`{"extra":1,`), input[1:]...)
			case "ciphertext":
				var e vault.Envelope
				if err := json.Unmarshal(input, &e); err != nil {
					t.Fatal(err)
				}
				e.Ciphertext[0] ^= 1
				input, _ = json.Marshal(e)
			case "trust-domain":
				input, err = SealTrustState(root, b, trust)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenTransportSetup(key, binding, input, trust, vault.Default, vault.Default, 1); err == nil {
				t.Fatal("accepted", mode)
			}
		})
	}
	for _, mode := range []string{"binding", "root", "settings"} {
		binding := b
		key := root
		transport := s
		switch mode {
		case "binding":
			binding.DeviceID = uuid.New()
		case "root":
			key = nil
		case "settings":
			transport.Endpoints = nil
		}
		if _, err := SealTransportSetup(key, binding, transport, trust, vault.Default, vault.Default, 1); err == nil {
			t.Fatal("sealed invalid", mode)
		}
	}
}

func TestTransportSetupCurrentTLSCache(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	root, b, base, _, org, _, _ := accountTrustFixture(t)
	oldBundle := trustedTLSFixture(t, base, org, 3)
	oldTrust, err := base.AdvanceTLS(oldBundle)
	if err != nil {
		t.Fatal(err)
	}
	s := settings()
	s.TLS = TLSVerified
	s.CAPEM = nil
	s.TLSBundle = oldBundle
	sealed, err := SealTransportSetup(root, b, s, oldTrust, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	latest := trustedTLSFixture(t, oldTrust, org, 4)
	current, err := oldTrust.AdvanceTLS(latest)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTransportSetupWithTLS(root, b, sealed, current, vault.Default, vault.Default, 1, latest)
	if err != nil || restored.TLSBundle == nil || !bytes.Equal(restored.TLSBundle.Encode(), latest.Encode()) || !reflect.DeepEqual(restored.Endpoints, s.Endpoints) || restored.Database != s.Database || restored.DeviceRole != s.DeviceRole {
		t.Fatal("cache restoration", err)
	}
	historical, err := EncodeTransportSnapshot(s, oldTrust, vault.Default, vault.Default, 1)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := AdvanceTransportSnapshotTLS(historical, current, latest)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := EncodeTransportSnapshot(restored, current, vault.Default, vault.Default, 1)
	if err != nil || !bytes.Equal(advanced, expected) {
		t.Fatal("startup transport diverged from the enrolled transport", err)
	}
	for _, wrong := range []*VerifiedTLSBundle{nil, oldBundle, trustedTLSFixture(t, current, org, 5)} {
		if _, err := AdvanceTransportSnapshotTLS(historical, current, wrong); err == nil {
			t.Fatal("startup accepted a bundle outside its durable floor")
		}
	}
	for _, mode := range []string{"nil", "old-cache", "future-cache", "foreign-cache", "equal-source", "future-source", "bad-trust", "bad-source", "unsigned-source", "unmanaged"} {
		t.Run(mode, func(t *testing.T) {
			input := sealed
			trust := current
			bundle := latest
			switch mode {
			case "nil":
				bundle = nil
			case "old-cache":
				bundle = oldBundle
			case "future-cache":
				bundle = trustedTLSFixture(t, current, org, 5)
			case "foreign-cache":
				other, _, key := tlsTrustFixture(t)
				other, err = SignTLSTrustBundle(other, key)
				if err != nil {
					t.Fatal(err)
				}
				bundle, err = VerifyTLSTrustBundle(other, TLSTrustPin{WorkspaceID: other.WorkspaceID, Signer: other.Signer, Organisation: key.Public().(ed25519.PublicKey), MinimumSequence: 1})
				if err != nil {
					t.Fatal(err)
				}
			case "equal-source":
				trust = oldTrust
			case "future-source":
				trust = base
			case "bad-trust":
				trust.PublicKey = nil
			case "bad-source", "unsigned-source":
				raw, e := EncodeTransportSnapshot(s, oldTrust, vault.Default, vault.Default, 1)
				if e != nil {
					t.Fatal(e)
				}
				var record transportSnapshot
				if e = json.Unmarshal(raw, &record); e != nil {
					t.Fatal(e)
				}
				if mode == "bad-source" {
					record.Bundle = []byte("{")
				} else {
					old, e := DecodeTLSTrustBundle(record.Bundle)
					if e != nil {
						t.Fatal(e)
					}
					old.Signature[0] ^= 1
					record.Bundle, e = EncodeTLSTrustBundle(old)
					if e != nil {
						t.Fatal(e)
					}
				}
				raw, e = json.Marshal(record)
				if e != nil {
					t.Fatal(e)
				}
				binding, e := transportSetupBinding(b)
				if e != nil {
					t.Fatal(e)
				}
				key, e := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
				if e != nil {
					t.Fatal(e)
				}
				defer vault.Wipe(key)
				envelope, e := vault.Seal(key, binding, raw)
				if e != nil {
					t.Fatal(e)
				}
				input, e = json.Marshal(envelope)
				if e != nil {
					t.Fatal(e)
				}
			case "unmanaged":
				u := s
				u.TLSBundle = nil
				u.CAPEM = testCA(t)
				input, err = SealTransportSetup(root, b, u, base, vault.Default, vault.Default, 1)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenTransportSetupWithTLS(root, b, input, trust, vault.Default, vault.Default, 1, bundle); err == nil {
				t.Fatal("unsafe cache override", mode)
			}
		})
	}
}

func TestTransportChangePolicyPersistence(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	root, binding, trust, _, _, _, _ := accountTrustFixture(t)
	for _, policy := range []ChangePolicy{{}, {ConcurrentDevices: 300}, {ConcurrentDevices: 301}, {TransactionPooler: true}, {ConcurrentDevices: ^uint32(0)}} {
		s := settings()
		s.TLS, s.CAPEM, s.Changes = TLSVerified, testCA(t), policy
		sealed, err := SealTransportSetup(root, binding, s, trust, vault.Default, vault.Standard, 1)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := OpenTransportSetup(root, binding, sealed, trust, vault.Default, vault.Standard, 1)
		if err != nil || restored.Changes != policy || restored.Changes.UseNotifications() != policy.UseNotifications() {
			t.Fatal("lost deployment policy", err)
		}
		raw, err := EncodeTransportSnapshot(s, trust, vault.Default, vault.Standard, 1)
		if err != nil {
			t.Fatal(err)
		}
		var record transportSnapshot
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		record.FormatVersion, record.Changes = 1, nil
		legacy, _ := json.Marshal(record)
		restored, err = DecodeTransportSnapshot(legacy, trust, vault.Default, vault.Standard, 1)
		if err != nil || restored.Changes.UseNotifications() {
			t.Fatal("legacy setup must poll", err)
		}
		for _, version := range []uint16{1, 2} {
			record.FormatVersion = version
			if version == 1 {
				record.Changes = &policy
			} else {
				record.Changes = nil
			}
			invalid, _ := json.Marshal(record)
			if _, err := DecodeTransportSnapshot(invalid, trust, vault.Default, vault.Standard, 1); err == nil {
				t.Fatal("accepted inconsistent policy version")
			}
		}
		ordinary, _ := json.Marshal(s)
		if bytes.Contains(ordinary, []byte("concurrentDevices")) {
			t.Fatal("policy leaked into ordinary settings JSON")
		}
	}
}
