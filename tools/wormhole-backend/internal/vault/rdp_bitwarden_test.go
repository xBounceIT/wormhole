package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRDPBitwardenAccountComposition(t *testing.T) {
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := BundleBinding{Protocol: "rdp", Host: "example", Port: 3389, Epoch: 8, WorkspaceID: uuid.NewString(),
		NodeID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString()}
	lookup := RDPBitwardenLookup{PrimaryItemID: uuid.NewString(), GatewayItemID: uuid.NewString(), Link: bytes.Repeat([]byte{1}, 32)}
	settings := DefaultRDPSettings()
	settings.GatewayUsageMethod, settings.GatewayHostname = 1, "gateway.example"
	base := RDPBundlePayload{Settings: settings, GatewayUsername: "configured-gateway"}
	accounts := RDPBitwardenAccounts{Username: "live-user", GatewayUsername: "ignored-gateway", Password: []byte("first"), GatewayPassword: []byte("second")}
	baseRaw, err := EncodeRDPBitwardenBase(base, lookup.Slots(), lookup.Link)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRDPBitwardenAccounts(target.PublicKey().Bytes(), binding, nil, "", lookup, accounts)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := OpenRDPBitwardenAccounts(target.Bytes(), binding, nil, "", baseRaw, sealed)
	defer Wipe(raw)
	if err != nil || got.Username != "live-user" || got.GatewayUsername != "configured-gateway" ||
		string(got.Password) != "first" || string(got.GatewayPassword) != "second" ||
		!got.PasswordProvided || !got.GatewayPasswordProvided {
		t.Fatal("wrong authorized account", err)
	}
	if _, _, err := OpenRDPBitwardenAccounts(worker.Bytes(), binding, nil, "", baseRaw, sealed); err == nil {
		t.Fatal("lookup process opened the RDP accounts")
	}
	changed := bytes.Clone(baseRaw)
	changed[2] ^= 255
	if _, _, err := OpenRDPBitwardenAccounts(target.Bytes(), binding, nil, "", changed, sealed); err == nil {
		t.Fatal("cross-linked base accepted")
	}
	changed = bytes.Clone(baseRaw)
	changed[1] = byte(RDPBitwardenGateway)
	if _, _, err := OpenRDPBitwardenAccounts(target.Bytes(), binding, nil, "", changed, sealed); err == nil {
		t.Fatal("changed slot mask accepted")
	}
	changedBinding := binding
	changedBinding.Host = "different.example"
	if _, _, err := OpenRDPBitwardenAccounts(target.Bytes(), changedBinding, nil, "", baseRaw, sealed); err == nil {
		t.Fatal("changed route accepted")
	}
	for _, mutate := range []func(*RDPBitwardenAccounts){
		func(p *RDPBitwardenAccounts) { p.Password = nil },
		func(p *RDPBitwardenAccounts) { p.GatewayPassword = nil },
		func(p *RDPBitwardenAccounts) { p.GatewayPassword = []byte("line\nbreak") },
		func(p *RDPBitwardenAccounts) { p.Username = strings.Repeat("x", 514) },
	} {
		bad := accounts
		mutate(&bad)
		if _, err := SealRDPBitwardenAccounts(target.PublicKey().Bytes(), binding, nil, "", lookup, bad); err == nil {
			t.Fatal("malformed account accepted")
		}
	}
	primary := lookup
	primary.GatewayItemID = ""
	if _, err := SealRDPBitwardenAccounts(target.PublicKey().Bytes(), binding, nil, "", primary, accounts); err == nil {
		t.Fatal("extra gateway account accepted")
	}
	gateway := lookup
	gateway.PrimaryItemID = ""
	if _, err := SealRDPBitwardenAccounts(target.PublicKey().Bytes(), binding, nil, "", gateway, accounts); err == nil {
		t.Fatal("extra primary account accepted")
	}
	for _, bad := range [][]byte{nil, baseRaw[:31], append([]byte{1}, baseRaw[1:]...), append([]byte{3, 0}, baseRaw[2:]...)} {
		if _, _, err := OpenRDPBitwardenAccounts(target.Bytes(), binding, nil, "", bad, sealed); err == nil {
			t.Fatal("invalid RDP base accepted")
		}
	}
	improper := base
	improper.PasswordProvided = true
	if _, err := EncodeRDPBitwardenBase(improper, lookup.Slots(), lookup.Link); err == nil {
		t.Fatal("base reserved a present primary password")
	}
	improper = base
	improper.Settings.GatewayUseSameCreds = true
	if _, err := EncodeRDPBitwardenBase(improper, lookup.Slots(), lookup.Link); err == nil {
		t.Fatal("base reserved an independent password for reused gateway credentials")
	}
	info, err := rdpBitwardenAccountsInfo(binding, nil, "", lookup.Slots(), lookup.Link)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		bytes.Repeat([]byte{255}, 17),                    // impossible field length
		append([]byte{0, 0, 0, 12}, make([]byte, 13)...), // truncated next prefix
		make([]byte, 17),                                 // trailing byte
	} {
		cipher, err := sealBundlePayload(target.PublicKey().Bytes(), info, malformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenRDPBitwardenAccounts(target.Bytes(), binding, nil, "", baseRaw, cipher); err == nil {
			t.Fatal("malformed account frame accepted")
		}
	}
	now := time.Now()
	ticket := ConnectionBitwardenTicketPayload{RDP: &lookup, TargetPublicKey: target.PublicKey().Bytes(),
		SavedSession: []byte("fixture"), ExpiresAt: now.Add(time.Minute).UnixMilli()}
	if _, err := SealConnectionBitwardenTicket(worker.PublicKey().Bytes(), binding, ticket, now); err != nil {
		t.Fatal(err)
	}
	ticket.ItemID = uuid.NewString()
	if _, err := SealConnectionBitwardenTicket(worker.PublicKey().Bytes(), binding, ticket, now); err == nil {
		t.Fatal("RDP ticket accepted a second item format")
	}
}

func TestManualRDPBitwardenRejectsUnexpectedGatewayBase(t *testing.T) {
	settings := DefaultRDPSettings()
	settings.GatewayUsageMethod, settings.GatewayHostname = 1, "gateway.example"
	base := RDPBundlePayload{Settings: settings}
	inner := SealedBundle{FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM,
		Enc: bytes.Repeat([]byte{1}, 32), Ciphertext: bytes.Repeat([]byte{2}, 31)}
	link := bytes.Repeat([]byte{3}, 32)
	withGateway := base
	withGateway.GatewayPassword, withGateway.GatewayPasswordProvided = []byte("fixture"), true
	if _, err := EncodeManualRDPBitwardenBase(withGateway, inner, link); err == nil {
		t.Fatal("a gateway already supplied by the base cannot also use a Bitwarden release")
	}
	if _, err := EncodeManualRDPBitwardenBase(base, SealedBundle{}, link); err == nil {
		t.Fatal("a malformed document envelope cannot authorize a gateway lookup")
	}
	if _, err := EncodeManualRDPBitwardenBase(base, inner, link[:31]); err == nil {
		t.Fatal("a truncated link cannot authorize gateway credentials")
	}
	nested, err := EncodeRDPManualAuthorization(withGateway, inner)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(nested)
	raw, err := encodeRDPBitwardenBase(nested, RDPBitwardenGateway, link)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(raw)
	if _, _, _, err := OpenManualRDPBitwardenAccounts(nil, BundleBinding{}, raw, SealedBundle{}); err != ErrFormat {
		t.Fatal("the recipient must reject a prepopulated gateway base before opening the release", err)
	}
}
