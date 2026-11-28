package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
)

func TestAccountSuspensionPageChecksIdentityAndCursor(t *testing.T) {
	account, boundary, id := uuid.NewString(), uuid.NewString(), uuid.NewString()
	request := AccountSuspensionRequest{AccountID: account, Kind: "roots"}
	page := func(kind, revision string, rows [][]any) []byte {
		t.Helper()
		b, err := json.Marshal(map[string]any{"accountId": account, "kind": kind, "revision": revision, "entries": rows})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	root := []any{"1", boundary, "1", id, "3", "false", "2", "retired"}
	rows := [][]any{root}
	for i := 2; i <= 26; i++ {
		rows = append(rows, []any{strconv.Itoa(i), nil, nil, nil, nil, nil, nil, nil})
	}
	reply, err := parseAccountSuspensionReply([][]byte{[]byte("ready"), page("roots", "49", rows)}, request)
	if err != nil || reply.Page == nil || len(reply.Page.Entries) != 25 || reply.Page.After != "25" ||
		reply.Page.Entries[0].Kind != "view" || reply.Page.Entries[1] != (AccountSuspensionEntry{Position: "2"}) {
		t.Fatal("valid paged key inventory failed", reply.Status, err)
	}
	request.Revision, request.After = "49", "25"
	if next, err := parseAccountSuspensionPage(page("roots", "49", rows[25:]), request); err != nil || len(next.Entries) != 1 || next.After != "" {
		t.Fatal("could not continue a bounded revision", err)
	}
	for _, raw := range [][]byte{
		page("roots", "50", rows[25:]),
		page("passwords", "49", rows[25:]),
		page("roots", "49", rows[:1]),
		page("roots", "049", rows[25:]),
		page("roots", "49", append(rows, rows[0])),
		[]byte(`{"accountId":"` + account + `","kind":"roots","revision":"49","entries":[],"extra":true}`),
		bytes.Repeat([]byte{'x'}, accountSuspensionPageBytes+1),
		{0xff},
	} {
		if result, err := parseAccountSuspensionPage(raw, request); result != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("accepted invalid account suspension page", err)
		}
	}
	request.Revision, request.After = "", ""
	for idx, value := range map[int]any{1: nil, 2: "3", 3: "bad-id", 4: "0", 5: "no", 6: "0", 7: "replaced"} {
		invalid := append([]any(nil), root...)
		invalid[idx] = value
		if _, err := parseAccountSuspensionPage(page("roots", "49", [][]any{invalid}), request); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("accepted invalid or partially hidden root", idx, err)
		}
	}
	request.Kind = "passwords"
	password := []any{"1", boundary, "credential", id, "History"}
	if result, err := parseAccountSuspensionPage(page("passwords", "49", [][]any{password}), request); err != nil ||
		result.Entries[0].Name != "History" {
		t.Fatal("valid password reference was rejected", err)
	}
	for idx, value := range map[int]any{1: "bad-id", 2: "private-key", 4: nil} {
		invalid := append([]any(nil), password...)
		invalid[idx] = value
		if _, err := parseAccountSuspensionPage(page("passwords", "49", [][]any{invalid}), request); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("accepted invalid password reference", idx, err)
		}
	}
	request.Kind = "groups"
	for _, status := range []string{"needs-removal", "waiting", "queued", "resolved"} {
		group := []any{"1", boundary, "Operations", "90", status, nil}
		var job string
		if status == "queued" {
			job, group[5] = id, id
		}
		masked := []any{"2", nil, nil, nil, nil, nil}
		result, err := parseAccountSuspensionPage(page("groups", "49", [][]any{group, masked}), request)
		want := AccountSuspensionEntry{Position: "1", Kind: "group", ID: boundary, Name: "Operations", Revision: "90", Status: status, JobID: job}
		if err != nil || len(result.Entries) != 2 || result.Entries[0] != want || result.Entries[1] != (AccountSuspensionEntry{Position: "2"}) {
			t.Fatal("group inventory lost its status, job or redaction", status, err)
		}
	}
	group := []any{"1", boundary, "Operations", "90", "queued", id}
	for idx, value := range map[int]any{1: nil, 2: "invalid\x00name", 3: "092", 4: "resolved", 5: nil} {
		invalid := append([]any(nil), group...)
		invalid[idx] = value
		if _, err := parseAccountSuspensionPage(page("groups", "49", [][]any{invalid}), request); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("accepted an invalid group entry", idx, err)
		}
	}
	group[4] = "unknown"
	if _, err := parseAccountSuspensionPage(page("groups", "49", [][]any{group}), request); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("an unknown group status reached the application", err)
	}
	for _, status := range []string{"busy", "stale", "unavailable", "not-recorded"} {
		if out, err := parseAccountSuspensionReply([][]byte{[]byte(status), nil}, request); err != nil || out.Status != status || out.Page != nil {
			t.Fatal("valid inventory status was rejected", status, err)
		}
		if _, err := parseAccountSuspensionReply([][]byte{[]byte(status), []byte("[]")}, request); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("non-ready status included data", status, err)
		}
	}
	for _, request := range []AccountSuspensionRequest{
		{}, {AccountID: account, Kind: "devices"}, {AccountID: account, Kind: "roots", Revision: "1"}, {AccountID: account, Kind: "roots", After: "1"},
	} {
		if _, err := NewSession().AccountSuspensionInventory(context.Background(), TrustState{}, request); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid inventory request was accepted", err)
		}
	}
}
