package sharedpg

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAccountResetTargetPagesRequireBoundedOrderedMetadata(t *testing.T) {
	workspace := uuid.New()
	makeRow := func(index byte, status string) [][]byte {
		user := uuid.UUID{15: index}
		eligible := []byte("true")
		if index%2 == 0 {
			eligible = []byte("false")
		}
		row := [][]byte{[]byte(user.String()), []byte("fixture-user"), eligible, nil, []byte(status), nil}
		if status != "not-issued" {
			row[3], row[5] = []byte(uuid.NewString()), []byte("1800000000")
		}
		return row
	}
	statuses := []string{"not-issued", "awaiting-handover", "handed-over", "redeemed", "expired", "inactive"}
	rows := make([][][]byte, 0, accountResetTargetsLimit+1)
	for i := 1; i <= accountResetTargetsLimit+1; i++ {
		rows = append(rows, makeRow(byte(i), statuses[(i-1)%len(statuses)]))
	}
	result, err := parseAccountResetTargets(rows, workspace, uuid.Nil)
	if err != nil || len(result.Targets) != accountResetTargetsLimit || result.Next == nil ||
		*result.Next != (uuid.UUID{15: accountResetTargetsLimit}) || result.Targets[1].Eligible {
		t.Fatal("reset cursor did not use the last visible account", err)
	}
	for _, invalid := range []struct {
		name string
		edit func([][]byte) [][]byte
	}{
		{"columns", func(row [][]byte) [][]byte { return row[:5] }},
		{"invalid uuid", func(row [][]byte) [][]byte { row[0] = []byte("not-a-uuid"); return row }},
		{"invalid login", func(row [][]byte) [][]byte { row[1] = []byte("UPPERCASE"); return row }},
		{"unexpected eligibility", func(row [][]byte) [][]byte { row[2] = []byte("1"); return row }},
		{"unknown status", func(row [][]byte) [][]byte { row[4] = []byte("unknown"); return row }},
		{"offer with no issuance", func(row [][]byte) [][]byte { row[4] = []byte("not-issued"); return row }},
		{"missing expiry", func(row [][]byte) [][]byte { row[5] = nil; return row }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if result, err := parseAccountResetTargets([][][]byte{invalid.edit(makeRow(1, "handed-over"))}, workspace, uuid.Nil); result.Targets != nil || !errors.Is(err, ErrAdmissionResponse) {
				t.Fatal("queue accepted invalid reset metadata", err)
			}
		})
	}
	if _, err := parseAccountResetTargets(rows, workspace, uuid.UUID{15: 1}); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("queue accepted a stale page", err)
	}
	if _, err := parseAccountResetTargets(append(rows, makeRow(52, "not-issued")), workspace, uuid.Nil); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("queue accepted too many targets", err)
	}
	empty, err := parseAccountResetTargets(nil, workspace, uuid.Nil)
	if err != nil || empty.Targets == nil || len(empty.Targets) != 0 || empty.Next != nil {
		t.Fatal("empty response did not yield a valid empty queue", err)
	}
}
