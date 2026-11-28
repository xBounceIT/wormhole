package sharedpg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func admissionRequest() AdmissionRequest {
	id := uuid.MustParse(testHintID)
	return AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: id, UserID: id, DeviceID: id}
}

func admissionRows() [][][]byte {
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte(testHintID), []byte(testHintID), []byte("false"), []byte("1"), []byte("2"), []byte("1"), []byte("0"), []byte("0001ff")}}
}

func TestAdmissionParsing(t *testing.T) {
	request := admissionRequest()
	for _, admin := range []string{"false", "true"} {
		rows := admissionRows()
		rows[0][4] = []byte(admin)
		result, err := parseAdmission(rows, request)
		if err != nil || result.IsAdmin != (admin == "true") || result.SessionID != request.DeviceID || result.MinAPI != 1 || result.MaxAPI != 2 || result.Epoch != 1 || result.ChangeSeq != 0 || string(result.SignedProfile) != string([]byte{0, 1, 255}) {
			t.Fatalf("invalid admission parse: %v", err)
		}
		clear(rows[0][9])
		if result.SignedProfile[2] != 255 {
			t.Fatal("profile aliases input")
		}
	}
	for _, rows := range [][][][]byte{nil, {}, {admissionRows()[0], admissionRows()[0]}, {{}}} {
		if _, err := parseAdmission(rows, request); err != ErrAdmissionResponse {
			t.Fatal("accepted invalid row count/shape")
		}
	}
	for _, bad := range []struct {
		column int
		value  string
	}{
		{0, ""}, {0, "00000000-0000-0000-0000-000000000000"}, {0, strings.ToUpper(testHintID)},
		{1, "22345678-1234-4234-8234-123456789abc"}, {2, "22345678-1234-4234-8234-123456789abc"}, {3, "22345678-1234-4234-8234-123456789abc"},
		{4, "t"}, {4, ""}, {5, "0"}, {5, "2"}, {5, "01"}, {5, "-1"}, {6, "0"}, {6, "2147483648"}, {7, "0"}, {7, "9223372036854775808"}, {8, "-1"}, {8, "+1"},
		{9, ""}, {9, "f"}, {9, "zz"}, {9, strings.Repeat("ff", 65537)},
	} {
		rows := admissionRows()
		rows[0][bad.column] = []byte(bad.value)
		if result, err := parseAdmission(rows, request); err != ErrAdmissionResponse || result != nil {
			t.Fatalf("accepted bad column %d", bad.column)
		}
	}
	rows := admissionRows()
	rows[0][9] = []byte(strings.Repeat("ab", 65536))
	if result, err := parseAdmission(rows, request); err != nil || len(result.SignedProfile) != 65536 {
		t.Fatal("rejected maximum profile")
	}
}

func TestAdmissionRequestValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.StartSession(nil, admissionRequest()); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, change := range []func(*AdmissionRequest){
		func(r *AdmissionRequest) { r.API = 0 }, func(r *AdmissionRequest) { r.API = -1 },
		func(r *AdmissionRequest) { r.AppVersion = "" }, func(r *AdmissionRequest) { r.AppVersion = strings.Repeat("1", 65) },
		func(r *AdmissionRequest) { r.AppVersion = "1.2.3\n" }, func(r *AdmissionRequest) { r.Source = "bad" },
		func(r *AdmissionRequest) { r.WorkspaceID = uuid.Nil }, func(r *AdmissionRequest) { r.UserID = uuid.Nil }, func(r *AdmissionRequest) { r.DeviceID = uuid.Nil },
	} {
		r := admissionRequest()
		change(&r)
		if _, err := s.StartSession(context.Background(), r); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.StartSession(context.Background(), admissionRequest()); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	if _, err := fake.StartSession(context.Background(), admissionRequest()); err != ErrQuery {
		t.Fatal(err)
	}
}

func TestWorkspaceQueryErrorsAreSanitized(t *testing.T) {
	for code, want := range map[string]error{"WH001": ErrIdentityUnavailable, "WH002": ErrProvisioning, "WH003": ErrTLSRequired, "WH004": ErrAPIVersion, "WH005": ErrAuditUnavailable, "WH006": ErrTransactionIsolation, "WH007": ErrAuthentication, "WH008": ErrPasswordChangePayload, "WH009": ErrDeviceCredentials, "WH010": ErrAccountRevision, "WH011": ErrTLSMetadata, "WH012": ErrInvitation, "WH015": ErrUseTicket, "55P03": ErrChangeInProgress, "53300": ErrConnectionLimit, "XX000": ErrQuery} {
		err := workspaceQueryError(&pgconn.PgError{Code: code, Message: "secret", Detail: "secret", Hint: "secret"})
		if err != want || strings.Contains(err.Error(), "secret") {
			t.Fatal("server detail escaped")
		}
	}
	if workspaceQueryError(errors.New("secret")) != ErrQuery {
		t.Fatal("unexpected driver error")
	}
}
