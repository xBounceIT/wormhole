package sharedpg

import (
	"context"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"strconv"
	"testing"
)

func TestParseNodePermissions(t *testing.T) {
	for i := 0; i <= 31; i++ {
		got, err := parseNodePermissions([][][]byte{{[]byte(strconv.Itoa(i))}})
		if err != nil || got != permissions.Mask(i) {
			t.Fatal(got, err)
		}
	}
	for _, value := range []string{"", "32", "256", "-1", "01", "+1", " 1", "1\n", "bad"} {
		if got, err := parseNodePermissions([][][]byte{{[]byte(value)}}); err != ErrAdmissionResponse || got != 0 {
			t.Fatal("bad mask", value)
		}
	}
	for _, rows := range [][][][]byte{nil, {{}}, {{nil, nil}}, {{[]byte("1")}, {[]byte("1")}}} {
		if _, err := parseNodePermissions(rows); err != ErrAdmissionResponse {
			t.Fatal(err)
		}
	}
}
func TestNodePermissionsValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	id := uuid.New()
	if _, err := s.NodePermissions(nil, id); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.NodePermissions(context.Background(), uuid.Nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.NodePermissions(context.Background(), id); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.NodePermissions(ctx, id); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.NodePermissions(context.Background(), id); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.NodePermissions(context.Background(), id); err != ErrQuery {
		t.Fatal(err)
	}
}
