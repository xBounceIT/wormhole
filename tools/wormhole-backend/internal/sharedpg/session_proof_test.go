package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"

	"github.com/google/uuid"
)

func TestSCRAMProofRFC7677(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	const nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	message := []byte("n=user,r=rOprNGfwEbeRWgbNEkqO,r=" + nonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=" + nonce)
	p := calculateSCRAMProof([]byte("pencil"), salt, message, 4096)
	defer p.Wipe()
	if base64.StdEncoding.EncodeToString(p.Client) != "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=" || base64.StdEncoding.EncodeToString(p.ExpectedServer) != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatal("RFC7677 vector mismatch")
	}
}

func proofFixture() (SessionProofChallenge, []byte, []byte) {
	c := SessionProofChallenge{
		Binding:     SessionProofBinding{WorkspaceID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(), Epoch: 1, BackendPID: 42, ExpiresAt: 1900000000, CapabilityHash: sha256.Sum256(NewSessionProofNonce())},
		ClientNonce: NewSessionProofNonce(), ServerNonce: NewSessionProofNonce(), Salt: bytes.Repeat([]byte{3}, 32), Iterations: SCRAMIterations,
	}
	derived := bytes.Repeat([]byte{7}, 32)
	login, _ := EncodeLoginSecret(derived)
	return c, derived, buildSCRAMVerifier(login, c.Salt)
}

func TestSessionProofRoundTripAndWipe(t *testing.T) {
	c, derived, verifier := proofFixture()
	p, err := ProveSession(derived, c.Binding, c.ClientNonce, c)
	if err != nil {
		t.Fatal(err)
	}
	server, err := VerifySessionProof(verifier, c.Binding, c, p.Client)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyServer(server); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(p)
	if err != nil || bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(p.ExpectedServer))) {
		t.Fatal("server expectation escaped into wire format")
	}
	clientAlias, serverAlias := p.Client, p.ExpectedServer
	p.Wipe()
	if p.Client != nil || p.ExpectedServer != nil || !bytes.Equal(clientAlias, make([]byte, 32)) || !bytes.Equal(serverAlias, make([]byte, 32)) {
		t.Fatal("proof not erased")
	}
	if p.VerifyServer(server) == nil {
		t.Fatal("wiped proof accepted")
	}
	p.Wipe()
	var absent *SessionProof
	absent.Wipe()
	if absent.VerifyServer(server) == nil {
		t.Fatal("nil proof accepted")
	}
}

func TestSessionProofRejectsWrongCredentialsAndReplies(t *testing.T) {
	c, derived, verifier := proofFixture()
	p, err := ProveSession(derived, c.Binding, c.ClientNonce, c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	wrong := bytes.Repeat([]byte{8}, 32)
	wp, err := ProveSession(wrong, c.Binding, c.ClientNonce, c)
	if err != nil {
		t.Fatal(err)
	}
	defer wp.Wipe()
	for _, proof := range [][]byte{nil, make([]byte, 31), make([]byte, 33), wrong, wp.Client} {
		if result, err := VerifySessionProof(verifier, c.Binding, c, proof); err == nil || result != nil {
			t.Fatal("wrong proof accepted")
		}
	}
	for _, response := range [][]byte{nil, make([]byte, 31), make([]byte, 33), wrong} {
		if p.VerifyServer(response) == nil {
			t.Fatal("wrong server response accepted")
		}
	}
	if result, err := ProveSession(nil, c.Binding, c.ClientNonce, c); err == nil || result != nil {
		t.Fatal("invalid login material accepted")
	}
	if result, err := VerifySessionProof([]byte("invalid"), c.Binding, c, p.Client); err == nil || result != nil {
		t.Fatal("invalid verifier accepted")
	}
	for _, mutate := range []func(*SessionProofChallenge){
		func(c *SessionProofChallenge) { c.Salt = bytes.Repeat([]byte{4}, 32) },
		func(c *SessionProofChallenge) { c.Iterations++ },
		func(c *SessionProofChallenge) { c.ServerNonce = NewSessionProofNonce() },
		func(c *SessionProofChallenge) { c.ClientNonce = NewSessionProofNonce() },
		func(c *SessionProofChallenge) { c.Binding.Epoch++ },
		func(c *SessionProofChallenge) { c.Binding.BackendPID++ },
		func(c *SessionProofChallenge) { c.Binding.ExpiresAt++ },
		func(c *SessionProofChallenge) { c.Binding.UserID = uuid.New() },
		func(c *SessionProofChallenge) { c.Binding.DeviceID = uuid.New() },
		func(c *SessionProofChallenge) { c.Binding.WorkspaceID = uuid.New() },
		func(c *SessionProofChallenge) { c.Binding.CapabilityHash[0] ^= 1 },
	} {
		changed := c
		mutate(&changed)
		if result, err := VerifySessionProof(verifier, changed.Binding, changed, p.Client); err == nil || result != nil {
			t.Fatal("proof replayed across challenge coordinates")
		}
	}
}

func TestSessionProofRejectsUntrustedChallenge(t *testing.T) {
	c, derived, verifier := proofFixture()
	p, err := ProveSession(derived, c.Binding, c.ClientNonce, c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wipe()
	for name, mutate := range map[string]func(*SessionProofChallenge){
		"workspace":      func(c *SessionProofChallenge) { c.Binding.WorkspaceID = uuid.Nil },
		"user":           func(c *SessionProofChallenge) { c.Binding.UserID = uuid.Nil },
		"device":         func(c *SessionProofChallenge) { c.Binding.DeviceID = uuid.Nil },
		"epoch zero":     func(c *SessionProofChallenge) { c.Binding.Epoch = 0 },
		"epoch overflow": func(c *SessionProofChallenge) { c.Binding.Epoch = math.MaxUint64 },
		"pid":            func(c *SessionProofChallenge) { c.Binding.BackendPID = 0 },
		"expiry":         func(c *SessionProofChallenge) { c.Binding.ExpiresAt = 0 },
		"capability":     func(c *SessionProofChallenge) { c.Binding.CapabilityHash = [32]byte{} },
		"client nonce":   func(c *SessionProofChallenge) { c.ClientNonce = nil },
		"server nonce":   func(c *SessionProofChallenge) { c.ServerNonce = nil },
		"salt short":     func(c *SessionProofChallenge) { c.Salt = make([]byte, 15) },
		"salt long":      func(c *SessionProofChallenge) { c.Salt = make([]byte, 65) },
		"cost low":       func(c *SessionProofChallenge) { c.Iterations = 4095 },
		"cost high":      func(c *SessionProofChallenge) { c.Iterations = 1000001 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			mutate(&changed)
			if result, err := ProveSession(derived, changed.Binding, changed.ClientNonce, changed); err == nil || result != nil {
				t.Fatal("invalid challenge accepted")
			}
			if result, err := VerifySessionProof(verifier, changed.Binding, changed, p.Client); err == nil || result != nil {
				t.Fatal("invalid server state accepted")
			}
		})
	}
	changed := c
	changed.Binding.Epoch++
	if result, err := ProveSession(derived, c.Binding, c.ClientNonce, changed); err == nil || result != nil {
		t.Fatal("unexpected identity accepted")
	}
	if result, err := ProveSession(derived, c.Binding, NewSessionProofNonce(), c); err == nil || result != nil {
		t.Fatal("unexpected client nonce accepted")
	}
	if result, err := ProveSession(derived, c.Binding, nil, c); err == nil || result != nil {
		t.Fatal("missing client nonce accepted")
	}
}
