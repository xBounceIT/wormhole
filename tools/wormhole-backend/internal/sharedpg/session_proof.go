package sharedpg

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/crypto/pbkdf2"
)

// SessionProofBinding is expected connection/account metadata, not a replacement
// for PostgreSQL's SCRAM/TLS handshake. The server must retain and consume the
// challenge on that connection and enforce epoch/expiry against current state.
type SessionProofBinding struct {
	WorkspaceID, UserID, DeviceID uuid.UUID
	Epoch                         uint64
	BackendPID                    int32
	ExpiresAt                     int64
	// CapabilityHash commits to an independent client-generated session secret.
	// Only the hash is sent during proof; the secret must stay in native memory.
	CapabilityHash [32]byte
}

type SessionProofChallenge struct {
	Binding                        SessionProofBinding
	ClientNonce, ServerNonce, Salt []byte
	Iterations                     int
}

func NewSessionProofNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

// authMessage uses the RFC5802 transcript shape. The server nonce is a hash of
// the application domain, fixed-width identities, epoch, connection and random
// nonce; changing any expected coordinate therefore changes the signed transcript.
func (c SessionProofChallenge) authMessage(expected SessionProofBinding, clientNonce []byte) ([]byte, error) {
	b := c.Binding
	if b != expected || b.WorkspaceID == uuid.Nil || b.UserID == uuid.Nil || b.DeviceID == uuid.Nil || b.Epoch == 0 || b.Epoch > math.MaxInt64 || b.BackendPID <= 0 || b.ExpiresAt <= 0 || b.CapabilityHash == [32]byte{} || len(clientNonce) != 32 || len(c.ClientNonce) != 32 || !bytes.Equal(clientNonce, c.ClientNonce) || len(c.ServerNonce) != 32 || len(c.Salt) < 16 || len(c.Salt) > 64 || c.Iterations < SCRAMIterations || c.Iterations > 1000000 {
		return nil, ErrAuthentication
	}
	context := append([]byte("wormhole/v1/session-proof"), b.WorkspaceID[:]...)
	context = append(context, b.UserID[:]...)
	context = append(context, b.DeviceID[:]...)
	context = binary.BigEndian.AppendUint64(context, b.Epoch)
	context = binary.BigEndian.AppendUint32(context, uint32(b.BackendPID))
	context = binary.BigEndian.AppendUint64(context, uint64(b.ExpiresAt))
	context = append(context, c.ServerNonce...)
	context = append(context, b.CapabilityHash[:]...)
	serverNonce := sha256.Sum256(context)
	client := base64.RawURLEncoding.EncodeToString(clientNonce)
	combined := client + base64.RawURLEncoding.EncodeToString(serverNonce[:])
	first := "n=" + b.DeviceID.String() + ",r=" + client
	server := "r=" + combined + ",s=" + base64.StdEncoding.EncodeToString(c.Salt) + ",i=" + strconv.Itoa(c.Iterations)
	return []byte(first + "," + server + ",c=biws,r=" + combined), nil
}

type SessionProof struct {
	Client         []byte `json:"client"`
	ExpectedServer []byte `json:"-"`
}

func (p *SessionProof) Wipe() {
	if p == nil {
		return
	}
	vault.Wipe(p.Client)
	vault.Wipe(p.ExpectedServer)
	p.Client, p.ExpectedServer = nil, nil
}

func scramHMAC(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(message)
	return h.Sum(nil)
}

func calculateSCRAMProof(login, salt, message []byte, iterations int) *SessionProof {
	salted := pbkdf2.Key(login, salt, iterations, 32, sha256.New)
	defer vault.Wipe(salted)
	client := scramHMAC(salted, []byte("Client Key"))
	defer vault.Wipe(client)
	stored := sha256.Sum256(client)
	defer vault.Wipe(stored[:])
	signature := scramHMAC(stored[:], message)
	defer vault.Wipe(signature)
	proof := make([]byte, 32)
	for i := range proof {
		proof[i] = client[i] ^ signature[i]
	}
	serverKey := scramHMAC(salted, []byte("Server Key"))
	defer vault.Wipe(serverKey)
	return &SessionProof{Client: proof, ExpectedServer: scramHMAC(serverKey, message)}
}

// ProveSession authenticates only a validated challenge with an independently
// expected binding and client nonce. The caller owns and must wipe the proof.
func ProveSession(derived []byte, expected SessionProofBinding, clientNonce []byte, c SessionProofChallenge) (*SessionProof, error) {
	message, err := c.authMessage(expected, clientNonce)
	if err != nil {
		return nil, err
	}
	login, err := EncodeLoginSecret(derived)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(login)
	return calculateSCRAMProof(login, c.Salt, message, c.Iterations), nil
}

func (p *SessionProof) VerifyServer(response []byte) error {
	if p == nil || len(p.ExpectedServer) != 32 || len(response) != 32 || subtle.ConstantTimeCompare(p.ExpectedServer, response) != 1 {
		return ErrAuthentication
	}
	return nil
}

// VerifySessionProof is the native reference verifier for the database exchange.
// expected and c must come from retained server state; this function alone does
// not enforce challenge expiry, one-time consumption, or connection admission.
func VerifySessionProof(verifier []byte, expected SessionProofBinding, c SessionProofChallenge, proof []byte) ([]byte, error) {
	if len(proof) != 32 {
		return nil, ErrAuthentication
	}
	if err := ValidateSCRAMVerifier(verifier); err != nil {
		return nil, err
	}
	message, err := c.authMessage(expected, c.ClientNonce)
	if err != nil {
		return nil, err
	}
	parameters, encodedKeys, _ := bytes.Cut(verifier[len("SCRAM-SHA-256$"):], []byte("$"))
	iterations, encodedSalt, _ := bytes.Cut(parameters, []byte(":"))
	cost, _ := strconv.Atoi(string(iterations)) // Public, bounded decimal metadata.
	salt := make([]byte, base64.StdEncoding.DecodedLen(len(encodedSalt)))
	n, _ := base64.StdEncoding.Decode(salt, encodedSalt)
	if cost != c.Iterations || !bytes.Equal(salt[:n], c.Salt) {
		return nil, ErrAuthentication
	}
	encodedStored, encodedServer, _ := bytes.Cut(encodedKeys, []byte(":"))
	stored := make([]byte, 32)
	defer vault.Wipe(stored)
	server := make([]byte, 32)
	defer vault.Wipe(server)
	_, _ = base64.StdEncoding.Decode(stored, encodedStored)
	_, _ = base64.StdEncoding.Decode(server, encodedServer)
	signature := scramHMAC(stored, message)
	defer vault.Wipe(signature)
	client := make([]byte, 32)
	defer vault.Wipe(client)
	for i := range client {
		client[i] = proof[i] ^ signature[i]
	}
	actual := sha256.Sum256(client)
	defer vault.Wipe(actual[:])
	if subtle.ConstantTimeCompare(actual[:], stored) != 1 {
		return nil, ErrAuthentication
	}
	return scramHMAC(server, message), nil
}
