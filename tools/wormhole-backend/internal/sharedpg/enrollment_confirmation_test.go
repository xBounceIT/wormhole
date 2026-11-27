package sharedpg

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestEnrollmentConfirmationValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	digest := make([]byte, 32)
	if err := s.ConfirmEnrollment(nil, digest); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := s.ConfirmEnrollment(context.Background(), nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := s.ConfirmEnrollment(context.Background(), digest); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.ConfirmEnrollment(ctx, digest); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if err := s.ConfirmEnrollment(context.Background(), digest); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if err := fake.ConfirmEnrollment(context.Background(), digest); err != ErrQuery {
		t.Fatal(err)
	}
	id := uuid.New()
	rows := [][][]byte{{[]byte(id.String()), []byte("true")}}
	if !validEnrollmentConfirmation(rows, id) {
		t.Fatal("valid receipt")
	}
	for _, bad := range [][][][]byte{nil, {{}}, {{[]byte(id.String()), []byte("false")}}, {{[]byte(uuid.NewString()), []byte("true")}}, {{[]byte(id.String()), []byte("t")}}, {rows[0], rows[0]}} {
		if validEnrollmentConfirmation(bad, id) {
			t.Fatal("invalid receipt")
		}
	}
	if validEnrollmentConfirmation(rows, uuid.Nil) {
		t.Fatal("nil identity")
	}
	for _, err := range []error{ErrDeviceCredentials, ErrAccountRevision, ErrAuditUnavailable, ErrChangeInProgress, ErrIdentityUnavailable, ErrAuthentication, ErrTransactionIsolation} {
		if !knownEnrollmentConfirmationRejection(err) {
			t.Fatal(err)
		}
	}
	for _, err := range []error{nil, ErrQuery, context.Canceled, ErrEnrollmentConfirmationUncertain} {
		if knownEnrollmentConfirmationRejection(err) {
			t.Fatal(err)
		}
	}
}
