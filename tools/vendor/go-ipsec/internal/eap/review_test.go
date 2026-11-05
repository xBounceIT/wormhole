package eap

import (
	"testing"
)

func TestReviewNewChallengeInvalidatesOldServerProof(t *testing.T) {
	m := NewMSCHAPv2("User", []byte("password"))
	defer m.Wipe()
	data := append([]byte{opChallenge, 1, 0, 21, 16}, make([]byte, 16)...)
	challenge := Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: data}
	if _, err := m.HandleChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	success := Packet{Code: CodeRequest, Identifier: 2, Type: TypeMSCHAPv2, Data: append([]byte{opSuccess, 1, 0, 0}, m.authResponse...)}
	if _, err := m.HandleSuccess(success); err != nil || !m.Verified() {
		t.Fatal("initial proof did not verify", err)
	}
	data[1] = 2
	data[5] = 1
	if _, err := m.HandleChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	if m.Verified() {
		t.Fatal("new challenge reused the previous server proof")
	}
}

func TestReviewEAPRejectsBytesOutsideDeclaredFrame(t *testing.T) {
	for _, frame := range [][]byte{{CodeSuccess, 1, 0, 4, 6}, {CodeSuccess, 1, 0, 5, 0}, {CodeSuccess, 1, 0, 5, 6}, {CodeSuccess, 1, 0, 6, 6, 1}, {CodeFailure, 1, 0, 5, 0}} {
		if _, err := Parse(frame); err == nil {
			t.Fatal("terminal data was treated as a completed factor")
		}
	}
}

func TestReviewRejectsMalformedMSCHAPChallenges(t *testing.T) {
	for _, request := range []Packet{
		{Code: CodeRequest, Type: TypeIdentity},
		{Code: CodeRequest, Type: TypeMSCHAPv2},
		{Code: CodeRequest, Type: TypeMSCHAPv2, Data: []byte{opSuccess, 1, 0, 5, 16}},
		{Code: CodeRequest, Type: TypeMSCHAPv2, Data: []byte{opChallenge, 1, 0, 5, 16}},
		{Code: CodeRequest, Type: TypeMSCHAPv2, Data: append([]byte{opChallenge, 1, 0, 21, 15}, make([]byte, 16)...)},
	} {
		m := NewMSCHAPv2("UID", []byte("temporary-token"))
		response, err := m.HandleChallenge(request)
		if err == nil || len(response.Data) != 0 || m.Verified() {
			t.Fatal("malformed challenge produced a credential response or verified proof")
		}
		m.Wipe()
	}
}
