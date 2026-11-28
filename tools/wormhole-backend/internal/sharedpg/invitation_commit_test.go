package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type commitFixture struct {
	i             Invitation
	certification *UnverifiedInvitationCertification
	organisation  ed25519.PublicKey
	manifest      vault.InviteManifest
	plan          *vault.InviteRewrapPlan
	master        *AccountMaster
	device        uuid.UUID
	name          string
	now           time.Time
}

func (f commitFixture) prepare() (*PreparedInvitationCommit, error) {
	return PrepareInvitationCommit(f.i, f.certification, f.organisation, f.manifest, f.plan, f.master, f.device, f.name, f.now)
}
func invitationCommitFixture(t *testing.T, count int) commitFixture {
	t.Helper()
	rows, trust, secret := accountEnrollmentRows(t)
	account, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	certificate := *account.EnrollmentCertificate
	keys, err := vault.OpenEnrolledUserKeys(secret, account.Binding, account.Envelope, certificate, *account.State, trust, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Wipe)
	i, _ := enrollmentInvitationFixture(t)
	i.WorkspaceID = trust.WorkspaceID
	i.Enrollment.Context = certificate.Manifest.Context
	i.LoginName = certificate.Manifest.Context.LoginName
	i.ExpiresAt = certificate.Manifest.ExpiresAt
	fingerprint := sha256.Sum256(trust.Organisation)
	i.OrganisationFingerprint = bytes.Clone(fingerprint[:])
	plan := &vault.InviteRewrapPlan{Keys: keys, Proof: certificate.Rekey, SourceManifestRevision: certificate.Manifest.Revision}
	certificate.Manifest.Copies = nil
	certificate.Manifest.Issuers = nil
	for n := 0; n < count; n++ {
		binding := vault.KeyCopyBinding{WorkspaceID: i.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: account.State.Encryption, Issuer: vault.KeyRef{ID: uuid.New(), Version: 1}}
		certificate.Manifest.Copies = append(certificate.Manifest.Copies, binding)
		certificate.Manifest.Issuers = append(certificate.Manifest.Issuers, vault.InviteIssuer{Key: binding.Issuer, Public: trust.Organisation})
		binding.Holder, binding.Issuer = account.Binding.Encryption, account.Binding.Signing
		copy, err := vault.SealKeyCopy(make([]byte, 32), binding, certificate.Rekey.Public.Encryption, keys.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		plan.Copies = append(plan.Copies, vault.RewrappedKeyCopy{Binding: binding, Copy: copy})
	}
	certificate.Manifest, err = vault.SignInviteManifest(certificate.Manifest, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeInviteManifest(certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	plan.SourceManifestDigest = digest[:]
	owner := &AccountMaster{memory: &masterMemoryProbe{data: bytes.Clone(secret)}, preset: vault.KDFV1, askUsed: true, workspaceID: i.WorkspaceID, loginName: i.LoginName}
	t.Cleanup(func() { owner.Close() })
	certification := &UnverifiedInvitationCertification{State: *account.State, Encryption: certificate.BootstrapEncryption, Signing: certificate.BootstrapSigning, SignedProfile: certificationProfile(t, i.WorkspaceID, trust.Signer)}
	return commitFixture{i, certification, trust.Organisation, certificate.Manifest, plan, owner, uuid.New(), "test device", time.Now()}
}

func TestPrepareInvitationCommit(t *testing.T) {
	f := invitationCommitFixture(t, 1)
	p, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	raw, err := json.Marshal(p)
	if err != nil || string(raw) != "{}" {
		t.Fatal("prepared verifier serialized")
	}
	encoded, err := hex.DecodeString(string(p.params[10]))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := vault.DecodeUserEnrollmentCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(string(p.params[8]))
	ciphertext, _ := hex.DecodeString(string(p.params[9]))
	binding := vault.UserKeyBinding{WorkspaceID: f.i.WorkspaceID, UserID: f.i.Enrollment.Context.UserID, Encryption: vault.KeyRef{ID: f.plan.Proof.EncryptionKeyID, Version: 1}, Signing: vault.KeyRef{ID: f.plan.Proof.SigningKeyID, Version: 1}, Revision: 1}
	err = f.master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		envelope := vault.Envelope{FormatVersion: 1, SuiteID: vault.SuiteAES256GCM, KeyID: binding.Encryption.ID.String(), KeyVersion: 1, Nonce: nonce, Ciphertext: ciphertext}
		keys, e := vault.OpenUserKeys(secret, binding, envelope, certificate.Rekey.Public)
		if e == nil {
			keys.Wipe()
		}
		return e
	})
	if err != nil {
		t.Fatal("prepared capsule", err)
	}
	before := sha256.Sum256(bytes.Join(p.params, nil))
	f.plan.Wipe()
	if err := f.master.Close(); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(bytes.Join(p.params, nil)) != before {
		t.Fatal("prepared payload retained borrowed buffers")
	}
	saved := p.params
	p.Wipe()
	p.Wipe()
	var absent *PreparedInvitationCommit
	absent.Wipe()
	for _, v := range saved {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("request not wiped")
		}
	}
	for _, mode := range []string{"nil-plan", "nil-keys", "master", "login-name", "policy-floor", "long-name", "device", "name", "utf8", "nul", "certificate", "proof", "revision", "digest", "count", "keys", "public", "binding", "copy", "preset", "ask", "short-master", "closed-master"} {
		t.Run(mode, func(t *testing.T) {
			f := invitationCommitFixture(t, 1)
			switch mode {
			case "nil-plan":
				f.plan = nil
			case "nil-keys":
				f.plan.Keys = nil
			case "login-name":
				f.master.loginName = "another-user"
			case "long-name":
				f.name = strings.Repeat("a", 4097)
			case "policy-floor":
				signed, e := vault.DecodeSignedPolicy(f.certification.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				signed.Policy.KDF = vault.KDFV2
				key := ed25519.NewKeyFromSeed(make([]byte, 32))
				defer vault.Wipe(key)
				signed, e = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, key)
				if e != nil {
					t.Fatal(e)
				}
				f.certification.SignedProfile, e = vault.EncodeSignedPolicy(signed)
				if e != nil {
					t.Fatal(e)
				}
			case "master":
				f.master = nil
			case "device":
				f.device = uuid.Nil
			case "name":
				f.name = ""
			case "utf8":
				f.name = string([]byte{255})
			case "nul":
				f.name = "a\x00b"
			case "certificate":
				f.certification.State.Signature[0] ^= 1
			case "proof":
				f.plan.Proof.Signature[0] ^= 1
			case "revision":
				f.plan.SourceManifestRevision++
			case "digest":
				f.plan.SourceManifestDigest[0] ^= 1
			case "count":
				f.plan.Copies = nil
			case "keys":
				f.plan.Keys.SigningSeed = nil
			case "public":
				f.plan.Keys.SigningSeed[0] ^= 1
			case "binding":
				f.plan.Copies[0].Binding.Key.ID = uuid.New()
			case "copy":
				f.plan.Copies[0].Copy.Signature[0] ^= 1
			case "preset":
				f.master.preset = vault.KDFLow
			case "ask":
				f.master.askUsed = false
			case "short-master":
				f.master.memory.(*masterMemoryProbe).data = nil
			case "closed-master":
				f.master.Close()
			}
			if p, e := f.prepare(); e == nil || p != nil {
				t.Fatal("invalid preparation accepted")
			}
		})
	}
}

func TestInvitationCommitBounds(t *testing.T) {
	f := invitationCommitFixture(t, 0)
	p, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	s := NewSession()
	defer s.Close(context.Background())
	if e := s.CommitInvitation(nil, p); e != ErrConfiguration {
		t.Fatal(e)
	}
	if e := s.CommitInvitation(context.Background(), nil); e != ErrConfiguration {
		t.Fatal(e)
	}
	if e := s.CommitInvitation(context.Background(), p); e != ErrSessionClosed {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.CommitInvitation(ctx, p); e != context.Canceled {
		t.Fatal(e)
	}
	fake, _ := readySession(t, false)
	if e := fake.CommitInvitation(context.Background(), p); e != ErrQuery {
		t.Fatal(e)
	}
	seedPasswordSession(t, s)
	if e := s.CommitInvitation(context.Background(), p); e != ErrAuthentication {
		t.Fatal(e)
	}
	p.params[10] = make([]byte, 4*1024*1024)
	if e := fake.CommitInvitation(context.Background(), p); e != ErrConfiguration {
		t.Fatal(e)
	}
	p.Wipe()
	if e := fake.CommitInvitation(context.Background(), p); e != ErrConfiguration {
		t.Fatal(e)
	}
}

func TestInvitationCommitWire(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, scenario := range []string{"success", "maximum", "disconnect", "unknown", "shape", "device", "role", "revision", "epoch", "transaction", "WH012", "WH010", "WH005", "55P03", "WH001", "WH007", "WH006", "WH004", "WH003"} {
		t.Run(scenario, func(t *testing.T) {
			count := 0
			if scenario == "maximum" {
				count = vault.MaxInviteKeyCopies
			}
			f := invitationCommitFixture(t, count)
			p, err := f.prepare()
			if err != nil {
				t.Fatal(err)
			}
			defer p.Wipe()
			if count > 0 {
				size := 0
				for _, v := range p.params {
					size += len(v)
				}
				if size <= maxParameterBytes {
					t.Fatal("maximum fixture did not exercise separate limit")
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			secret := []byte("test-only-commit-wire")
			done := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				b := pgproto3.NewBackend(conn, conn)
				if e = initializeWritableTestConnection(b, secret); e != nil {
					done <- e
					return
				}
				query, params, e := receiveTestQuery(b)
				if e != nil {
					done <- e
					return
				}
				if query != commitInvitationSQL || len(params) != 12 {
					done <- fmt.Errorf("wrong commit request")
					return
				}
				for n, v := range params {
					if !bytes.Equal(v, p.params[n]) {
						done <- fmt.Errorf("altered commit parameter")
						return
					}
				}
				if scenario == "disconnect" {
					_ = listener.Close()
					done <- nil
					return
				}
				b.Send(&pgproto3.ParseComplete{})
				b.Send(&pgproto3.BindComplete{})
				code := scenario
				if scenario == "unknown" {
					code = "XX000"
				}
				if strings.HasPrefix(code, "WH") || code == "55P03" || code == "XX000" {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: "private server diagnostic"})
				} else {
					values := [][]byte{[]byte(p.device.String()), []byte(p.role), []byte("1"), []byte("1")}
					switch scenario {
					case "shape":
						values = values[:3]
					case "device":
						values[0] = []byte(uuid.NewString())
					case "role":
						values[1] = []byte("other")
					case "revision":
						values[2] = []byte("2")
					case "epoch":
						values[3] = []byte("01")
					}
					fields := make([]pgproto3.FieldDescription, len(values))
					for n := range fields {
						fields[n] = pgproto3.FieldDescription{Name: []byte("value"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}
					}
					b.Send(&pgproto3.RowDescription{Fields: fields})
					b.Send(&pgproto3.DataRow{Values: values})
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				}
				status := byte('I')
				if scenario == "transaction" {
					status = 'T'
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: status})
				if e = b.Flush(); e != nil {
					done <- e
					return
				}
				msg, e := b.Receive()
				if e == nil {
					if _, ok := msg.(*pgproto3.Terminate); !ok {
						e = fmt.Errorf("commit retried")
					}
				}
				done <- e
			}()
			settings := settings()
			settings.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
			s := NewSession()
			defer s.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e := s.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); e != nil {
				t.Fatal(e)
			}
			known := map[string]error{"WH012": ErrInvitation, "WH010": ErrAccountRevision, "WH005": ErrAuditUnavailable, "55P03": ErrChangeInProgress, "WH001": ErrIdentityUnavailable, "WH007": ErrAuthentication, "WH006": ErrTransactionIsolation, "WH004": ErrAPIVersion, "WH003": ErrTLSRequired}
			expected := ErrInvitationCommitUncertain
			if scenario == "success" || scenario == "maximum" {
				expected = nil
			} else if e, ok := known[scenario]; ok {
				expected = e
			}
			if e := s.CommitInvitation(ctx, p); e != expected {
				t.Fatalf("got %v want %v", e, expected)
			}
			retired := expected == nil || expected == ErrInvitationCommitUncertain || expected == ErrIdentityUnavailable || expected == ErrAuthentication
			select {
			case <-s.Done():
				if !retired {
					t.Fatal("known rejection retired owner")
				}
			default:
				if retired {
					t.Fatal("owner retained after commit")
				}
			}
			if e := s.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil && !errors.Is(e, net.ErrClosed) {
				t.Fatal(e)
			}
		})
	}
}

func TestPreparedInvitationAccountMasterIdentity(t *testing.T) {
	f := invitationCommitFixture(t, 0)
	p, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	if err := p.ValidateAccountMaster(f.master); err != nil {
		t.Fatal(err)
	}
	expires := p.expires
	p.expires = time.Now().Unix() - 1
	if err := p.ValidateAccountMaster(f.master); err != ErrConfiguration {
		t.Fatal("expired request accepted", err)
	}
	p.expires = expires
	if err := p.ValidateAccountMaster(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	other := &AccountMaster{}
	if err := p.ValidateAccountMaster(other); err != ErrConfiguration {
		t.Fatal("different owner accepted", err)
	}
	var absent *PreparedInvitationCommit
	if err := absent.ValidateAccountMaster(f.master); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := f.master.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateAccountMaster(f.master); err == nil {
		t.Fatal("closed master accepted")
	}
	p.Wipe()
	if err := p.ValidateAccountMaster(f.master); err != ErrConfiguration {
		t.Fatal("wiped request accepted", err)
	}
}
