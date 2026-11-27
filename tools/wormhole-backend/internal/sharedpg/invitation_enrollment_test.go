package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func enrollmentInvitationFixture(t *testing.T) (Invitation, time.Time) {
	i, _, now := invitationFixture(t)
	i.FormatVersion = 2
	i.Enrollment = &InvitationEnrollment{RoleTag: "testscope", Context: vault.InviteContext{WorkspaceID: i.WorkspaceID, UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: i.LoginName}}
	return i, now
}

func TestEnrollmentInvitation(t *testing.T) {
	i, now := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{17}, vault.InviteCodeBytes)
	token, err := EncodeInvitation(i, now)
	if err != nil || !strings.HasPrefix(token, enrollmentInvitationPrefix) {
		t.Fatal(err)
	}
	decoded, err := DecodeInvitation(token, now)
	if err != nil || !reflect.DeepEqual(i, decoded) {
		t.Fatal("roundtrip", err)
	}
	s, login, err := decoded.EnrollmentLogin(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	role, verifier, err := i.EnrollmentVerifier(code, now)
	if err != nil || ValidateSCRAMVerifier(verifier) != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	if role != s.DeviceRole || role != "wh_testscope_i_"+i.Enrollment.Context.InviteID.String() {
		t.Fatal("wrong role")
	}
	material, err := vault.DeriveInviteLogin(code, i.Enrollment.Context)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(material)
	expected, _ := EncodeLoginSecret(material)
	defer vault.Wipe(expected)
	if !bytes.Equal(login, expected) || bytes.Contains([]byte(token), login) || bytes.Contains([]byte(token), verifier) {
		t.Fatal("credential separation")
	}
	s.Endpoints[0].Host = "changed"
	s.CAPEM[0] ^= 1
	if reflect.DeepEqual(s.Endpoints, i.Endpoints) || bytes.Equal(s.CAPEM, i.CAPEM) {
		t.Fatal("transport snapshot aliases invitation")
	}
	// A recomputed checksum cannot turn v2 data into a legacy token.
	raw, _ := json.Marshal(i)
	if _, err := DecodeInvitation(invitationToken(raw), now); err != ErrInvitation {
		t.Fatal("prefix/version mismatch")
	}
	legacy, _, _ := invitationFixture(t)
	raw, _ = json.Marshal(legacy)
	payload := enrollmentInvitationPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(payload))
	if _, err := DecodeInvitation(payload+"."+hex.EncodeToString(sum[:]), now); err != ErrInvitation {
		t.Fatal("legacy masquerade")
	}
	for _, n := range []int{0, 15, 17} {
		if _, value, err := i.EnrollmentLogin(make([]byte, n), now); value != nil || err != ErrInvitation {
			t.Fatal("invalid code")
		}
		if _, value, err := i.EnrollmentVerifier(make([]byte, n), now); value != nil || err != ErrInvitation {
			t.Fatal("invalid code verifier")
		}
	}
	if _, v, err := i.EnrollmentLogin(code, time.Unix(i.ExpiresAt, 0)); v != nil || err != ErrInvitation {
		t.Fatal("expired login")
	}
	if _, v, err := legacy.EnrollmentVerifier(code, now); v != nil || err != ErrInvitation {
		t.Fatal("legacy guessed enrollment")
	}
}

func TestEnrollmentInvitationCoordinates(t *testing.T) {
	i, now := enrollmentInvitationFixture(t)
	for _, mutate := range []func(*Invitation){
		func(i *Invitation) { i.FormatVersion = 1 }, func(i *Invitation) { i.Enrollment = nil },
		func(i *Invitation) { i.Enrollment.RoleTag = "short" }, func(i *Invitation) { i.Enrollment.RoleTag = strings.Repeat("a", 17) },
		func(i *Invitation) { i.Enrollment.RoleTag = "bad_tag_" }, func(i *Invitation) { i.Enrollment.RoleTag = "TESTSCOPE" },
		func(i *Invitation) { i.Enrollment.Context.WorkspaceID = uuid.New() }, func(i *Invitation) { i.Enrollment.Context.LoginName = "other" },
		func(i *Invitation) { i.Enrollment.Context.UserID = uuid.Nil }, func(i *Invitation) { i.Enrollment.Context.InviteID = uuid.Nil },
		func(i *Invitation) { i.Enrollment.Context.KeyID = uuid.Nil }, func(i *Invitation) { i.Enrollment.Context.KeyVersion = 0 },
	} {
		copy := i
		e := *i.Enrollment
		copy.Enrollment = &e
		mutate(&copy)
		if _, err := EncodeInvitation(copy, now); err != ErrInvitation {
			t.Fatal("invalid coordinates")
		}
	}
	code := bytes.Repeat([]byte{23}, 16)
	_, org, _ := invitationFixture(t)
	bootstrap, err := vault.NewInviteBootstrap(org)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	c := i.Enrollment.Context
	envelope, err := vault.SealInviteBootstrap(code, c, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := i.OpenBootstrap(code, c, envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	opened.Wipe()
	// Even another correctly encrypted envelope must match the public issuance.
	for _, mutate := range []func(*vault.InviteContext){func(c *vault.InviteContext) { c.UserID = uuid.New() }, func(c *vault.InviteContext) { c.InviteID = uuid.New() }, func(c *vault.InviteContext) { c.KeyID = uuid.New() }, func(c *vault.InviteContext) { c.KeyVersion++ }} {
		other := c
		mutate(&other)
		envelope, err := vault.SealInviteBootstrap(code, other, bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if opened, err := i.OpenBootstrap(code, other, envelope, now); opened != nil || err != ErrInvitation {
			t.Fatal("cross-issuance bootstrap")
		}
		before, _ := vault.DeriveInviteLogin(code, c)
		after, _ := vault.DeriveInviteLogin(code, other)
		if bytes.Equal(before, after) {
			t.Fatal("cross-issuance login")
		}
		vault.Wipe(before)
		vault.Wipe(after)
	}
}
