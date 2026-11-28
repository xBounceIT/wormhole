package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPersonalRootRecoveryRejectsInvalidScopeBeforeAccess(t *testing.T) {
	var session Session
	trust := TrustState{UserID: uuid.New()}
	for _, request := range []PersonalRootRecoveryRequest{
		{}, {AccountID: uuid.New()}, {AccountID: trust.UserID, Suspension: 1},
		{AccountID: uuid.New(), Suspension: 1 << 63},
	} {
		if _, _, plan, err := session.PreparePersonalRootRecovery(context.Background(), trust, nil, request); plan != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("a malformed or self-directed request reached PostgreSQL", err)
		}
	}
	if _, err := session.CommitPreparedPersonalRootRecovery(context.Background(), trust, nil, nil, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("publication bypassed an authenticated review", err)
	}
}

func checkPersonalRootRecoveryDocumentFailures(t *testing.T, ctx context.Context, session *Session, trust TrustState,
	request PersonalRootRecoveryRequest) {
	t.Helper()
	var raw []byte
	err := session.queryServerCA(ctx, trust, "SELECT status,document"+personalRootRecoveryCall, request.arguments(nil),
		maxPersonalRootRecoveryDocument, 1, 2, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 2 || string(rows[0][0]) != "ready" {
				return ErrAdmissionResponse
			}
			raw = bytes.Clone(rows[0][1])
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*personalRootRecoveryDocument)
	}{
		{"scope", func(doc *personalRootRecoveryDocument) { doc.Suspension = "0" }},
		{"manifest", func(doc *personalRootRecoveryDocument) { doc.Manifest[0] = '!' }},
		{"historical certificate", func(doc *personalRootRecoveryDocument) { doc.PreviousCertificate[0] = '!' }},
		{"roster", func(doc *personalRootRecoveryDocument) { doc.Roster = []byte(`[]`) }},
		{"different signing key", func(doc *personalRootRecoveryDocument) { doc.Signing.ID = uuid.New() }},
		{"swapped roots", func(doc *personalRootRecoveryDocument) { doc.Roots[0], doc.Roots[1] = doc.Roots[1], doc.Roots[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc personalRootRecoveryDocument
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			tc.change(&doc)
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, plan, _, _, err := verifyPersonalRootRecoveryDocument(trust, pin, request, changed); err == nil || plan.holder.Key.ID != uuid.Nil {
				t.Fatal("unverified document selected the recipient", err)
			}
		})
	}
	changed := request
	changed.Review = &[32]byte{1}
	if _, _, _, _, err := verifyPersonalRootRecoveryDocument(trust, pin, changed, raw); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("native verification accepted a different review", err)
	}
}
