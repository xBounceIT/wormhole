package eap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc3079"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 2759 §9.2 worked example.
const (
	rfc2759AuthChal = "5B5D7C7D7B3F2F3E3C2C602132262628"
	rfc2759PeerChal = "21402324255E262A28295F2B3A337C7E"
	rfc2759User     = "User"
	rfc2759Pass     = "clientPass"
	rfc2759NTResp   = "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"
	rfc2759AuthResp = "S=407A5589115FD0D6209F510FE9C04566932CDA56"
	// RFC 3079 §3.5.1 password-hash-hash and §3.5.x master/send keys.
	rfc3079PHH     = "41C00C584BD2D91C4017A2A12FA59F3F"
	rfc3079Master  = "FDECE3717A8C838CB388E527AE3CDD31"
	rfc3079SendKey = "8B7CDC149B993A1BA118CB153F56DCCB"
)

// TestRFC2759 pins NT-Response and AuthenticatorResponse to RFC 2759 §9.2.
func TestRFC2759(t *testing.T) {
	authChal := unhex(t, rfc2759AuthChal)
	peerChal := unhex(t, rfc2759PeerChal)

	nt, err := rfc2759.GenerateNTResponse(authChal, peerChal, []byte(rfc2759User), []byte(rfc2759Pass))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nt, unhex(t, rfc2759NTResp)) {
		t.Fatalf("NT-Response\n got %x\nwant %s", nt, rfc2759NTResp)
	}
	ar, err := rfc2759.GenerateAuthenticatorResponse(authChal, peerChal, nt, []byte(rfc2759User), []byte(rfc2759Pass))
	if err != nil {
		t.Fatal(err)
	}
	if ar != rfc2759AuthResp {
		t.Fatalf("AuthenticatorResponse\n got %s\nwant %s", ar, rfc2759AuthResp)
	}
}

// TestRFC3079 pins the MPPE master-key derivation to RFC 3079 §3.5.
func TestRFC3079(t *testing.T) {
	phh := unhex(t, rfc3079PHH) // §3.5.1
	nt := unhex(t, rfc2759NTResp)
	mk := rfc3079.GetMasterKey(phh, nt)
	if !bytes.Equal(mk, unhex(t, rfc3079Master)) {
		t.Fatalf("MasterKey\n got %x\nwant %s", mk, rfc3079Master)
	}
	send, err := rfc3079.GetAsymmetricStartKey(mk, rfc3079.KeyLength128Bit, true) // §3.5.3 send key
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(send, unhex(t, rfc3079SendKey)) {
		t.Fatalf("MasterSendKey\n got %x\nwant %s", send, rfc3079SendKey)
	}
}

// TestDeriveMSK checks the 64-byte expansion: the send-key half is RFC 3079
// §3.5.3 authoritative; the trailing 32 bytes are zero; the total is 64.
func TestDeriveMSK(t *testing.T) {
	phh := unhex(t, rfc3079PHH)
	nt := unhex(t, rfc2759NTResp)
	msk, err := DeriveMSK(phh, nt)
	if err != nil {
		t.Fatal(err)
	}
	if len(msk) != MSKLen {
		t.Fatalf("MSK length = %d, want %d", len(msk), MSKLen)
	}
	// Bytes [16:32] are the MasterSendKey (magic3) → RFC 3079 §3.5.3.
	if !bytes.Equal(msk[16:32], unhex(t, rfc3079SendKey)) {
		t.Fatalf("MSK send-key half\n got %x\nwant %s", msk[16:32], rfc3079SendKey)
	}
	if !bytes.Equal(msk[32:64], make([]byte, 32)) {
		t.Fatal("MSK trailing 32 bytes must be zero")
	}
	// Bytes [0:16] are the MasterReceiveKey (magic2); regression-pin to lock
	// the layout (not an RFC vector, but derived from the §3.5 MasterKey).
	recv, err := rfc3079.GetAsymmetricStartKey(unhex(t, rfc3079Master), rfc3079.KeyLength128Bit, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msk[0:16], recv) {
		t.Fatal("MSK receive-key half mismatch")
	}
}

// TestPacketRoundTrip checks the EAP packet codec for request and success.
func TestPacketRoundTrip(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 7, Type: TypeMSCHAPv2, Data: []byte{opChallenge, 1, 0, 0, 16}}
	raw := req.Marshal()
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != req.Code || got.Identifier != req.Identifier || got.Type != req.Type || !bytes.Equal(got.Data, req.Data) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, req)
	}

	suc := Packet{Code: CodeSuccess, Identifier: 9}
	raw = suc.Marshal()
	if len(raw) != 4 {
		t.Fatalf("success packet len = %d, want 4", len(raw))
	}
	got, err = Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != CodeSuccess || got.Identifier != 9 || got.Type != 0 {
		t.Fatalf("success parse mismatch: %+v", got)
	}
}

// TestChallengeResponseFlow drives HandleChallenge → HandleSuccess with a
// server emulated from the same RFC primitives.
func TestChallengeResponseFlow(t *testing.T) {
	m := &MSCHAPv2{Username: "User", Password: []byte("clientPass")}
	authChal := unhex(t, rfc2759AuthChal)

	// Build a server Challenge packet.
	chalData := []byte{opChallenge, 0x42, 0, 0, authChallengeLen}
	chalData = append(chalData, authChal...)
	chalData = append(chalData, []byte("server.example")...)
	putUint16(chalData[2:4], uint16(len(chalData)))
	chal := Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: chalData}

	resp, err := m.HandleChallenge(chal)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != CodeResponse || resp.Type != TypeMSCHAPv2 {
		t.Fatalf("bad response packet: %+v", resp)
	}
	if resp.Data[0] != opResponse || resp.Data[1] != 0x42 {
		t.Fatal("response opcode/id mismatch")
	}

	// Server side: recompute AuthenticatorResponse and build a Success request.
	phh, nt := m.MSKInputs()
	if len(phh) == 0 || len(nt) == 0 {
		t.Fatal("MSK inputs not captured")
	}
	sucData := append([]byte{opSuccess, 0x42, 0, 0}, []byte(m.authResponse)...)
	putUint16(sucData[2:4], uint16(len(sucData)))
	suc := Packet{Code: CodeRequest, Identifier: 2, Type: TypeMSCHAPv2, Data: sucData}

	sucResp, err := m.HandleSuccess(suc)
	if err != nil {
		t.Fatal(err)
	}
	if sucResp.Code != CodeResponse || len(sucResp.Data) != 1 || sucResp.Data[0] != opSuccess {
		t.Fatalf("bad success response: %+v", sucResp)
	}

	// A tampered AuthenticatorResponse must be rejected.
	badData := append([]byte{opSuccess, 0x42, 0, 0}, []byte("S=DEADBEEF")...)
	putUint16(badData[2:4], uint16(len(badData)))
	if _, err := m.HandleSuccess(Packet{Code: CodeRequest, Identifier: 3, Type: TypeMSCHAPv2, Data: badData}); err == nil {
		t.Fatal("tampered AuthenticatorResponse accepted")
	}
}

// TestVerifiedGate is finding #12: Verified() is false until the server's
// MSCHAPv2 AuthenticatorResponse has been checked, so the IKE layer can refuse an
// EAP-Success that skips the MSCHAPv2-Success step (which would otherwise let a
// server complete IKE_AUTH without proving it knows the password).
func TestVerifiedGate(t *testing.T) {
	authChal := unhex(t, rfc2759AuthChal)
	challenge := func() []byte {
		d := []byte{opChallenge, 0x42, 0, 0, authChallengeLen}
		d = append(d, authChal...)
		d = append(d, []byte("server.example")...)
		putUint16(d[2:4], uint16(len(d)))
		return d
	}

	// Happy path: not verified after the challenge, verified after the Success.
	m := &MSCHAPv2{Username: "User", Password: []byte("clientPass")}
	if _, err := m.HandleChallenge(Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: challenge()}); err != nil {
		t.Fatal(err)
	}
	if m.Verified() {
		t.Fatal("Verified() true before the MSCHAPv2 Success step")
	}
	sucData := append([]byte{opSuccess, 0x42, 0, 0}, []byte(m.authResponse)...)
	putUint16(sucData[2:4], uint16(len(sucData)))
	if _, err := m.HandleSuccess(Packet{Code: CodeRequest, Identifier: 2, Type: TypeMSCHAPv2, Data: sucData}); err != nil {
		t.Fatal(err)
	}
	if !m.Verified() {
		t.Fatal("Verified() false after a successful MSCHAPv2 Success")
	}

	// A failed AuthenticatorResponse check must not flip Verified().
	bad := &MSCHAPv2{Username: "User", Password: []byte("clientPass")}
	if _, err := bad.HandleChallenge(Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: challenge()}); err != nil {
		t.Fatal(err)
	}
	badData := append([]byte{opSuccess, 0x42, 0, 0}, []byte("S=DEADBEEF")...)
	putUint16(badData[2:4], uint16(len(badData)))
	if _, err := bad.HandleSuccess(Packet{Code: CodeRequest, Identifier: 2, Type: TypeMSCHAPv2, Data: badData}); err == nil {
		t.Fatal("tampered AuthenticatorResponse accepted")
	}
	if bad.Verified() {
		t.Fatal("Verified() true after a failed AuthenticatorResponse check")
	}
}

// TestHandleSuccessBeforeChallenge: an MSCHAPv2-Success arriving before any
// Challenge has no expected AuthenticatorResponse, which made the empty-vs-empty
// constant-time compare pass vacuously. It must now be rejected and leave the
// session unverified.
func TestHandleSuccessBeforeChallenge(t *testing.T) {
	m := &MSCHAPv2{Username: "User", Password: []byte("clientPass")}
	sucData := []byte{opSuccess, 0x42, 0, 0}
	putUint16(sucData[2:4], uint16(len(sucData)))
	if _, err := m.HandleSuccess(Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: sucData}); err == nil {
		t.Fatal("unsolicited MSCHAPv2 Success before Challenge accepted")
	}
	if m.Verified() {
		t.Fatal("Verified() true after an unsolicited Success")
	}
}

// TestNewMSCHAPv2CopiesPassword: the conversation owns a private copy, so
// Wipe cannot zero a buffer the caller still uses (and vice versa — the
// caller mutating its buffer does not corrupt an in-flight conversation).
func TestNewMSCHAPv2CopiesPassword(t *testing.T) {
	orig := []byte("clientPass")
	m := NewMSCHAPv2("User", orig)
	orig[0] = 'X'
	if string(m.Password) != "clientPass" {
		t.Fatalf("conversation password aliases the caller's buffer: %q", m.Password)
	}
	m.Wipe()
	if string(orig[1:]) != "lientPass" {
		t.Fatal("Wipe zeroed the caller's buffer")
	}
}

// TestWipeZeroesDerivedMaterial: after a challenge round, Wipe zeroes the
// password copy and every password-derived buffer and nils the fields.
func TestWipeZeroesDerivedMaterial(t *testing.T) {
	m := NewMSCHAPv2("User", []byte("clientPass"))
	authChal := unhex(t, rfc2759AuthChal)
	chalData := []byte{opChallenge, 0x42, 0, 0, authChallengeLen}
	chalData = append(chalData, authChal...)
	chalData = append(chalData, []byte("server.example")...)
	putUint16(chalData[2:4], uint16(len(chalData)))
	if _, err := m.HandleChallenge(Packet{Code: CodeRequest, Identifier: 1, Type: TypeMSCHAPv2, Data: chalData}); err != nil {
		t.Fatal(err)
	}
	// Keep references to the backing arrays to observe the zeroing.
	held := [][]byte{m.Password, m.ntResponse, m.passwordHashHash, m.authResponse, m.peerChallenge, m.authChallenge}
	for i, b := range held {
		if len(b) == 0 {
			t.Fatalf("buffer %d empty before Wipe", i)
		}
	}
	m.Wipe()
	for i, b := range held {
		for _, v := range b {
			if v != 0 {
				t.Fatalf("buffer %d not zeroed by Wipe", i)
			}
		}
	}
	if m.Password != nil || m.ntResponse != nil || m.passwordHashHash != nil || m.authResponse != nil {
		t.Fatal("Wipe did not nil the fields")
	}
}
