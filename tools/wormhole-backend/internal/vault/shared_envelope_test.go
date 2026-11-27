package vault

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestSharedEnvelopeCodec(t *testing.T) {
	f := sharedGraph(t)
	raw, e := EncodeSharedEnvelope(f.envelope)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeSharedEnvelope(raw)
	if e != nil || !reflect.DeepEqual(got, f.envelope) {
		t.Fatal("ciphertext roundtrip", e)
	}
	Wipe(raw)
	binding, e := f.binding.binding()
	if e != nil {
		t.Fatal(e)
	}
	plain, e := Open(f.dek, binding, got)
	if e != nil || !bytes.Equal(plain, []byte("native-only secret")) {
		t.Fatal("wire alias", e)
	}
	Wipe(plain)
	for _, change := range []func(*Envelope){func(e *Envelope) { e.KeyID = "bad" }, func(e *Envelope) { e.KeyID = uuid.Nil.String() }, func(e *Envelope) { e.KeyID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }, func(e *Envelope) { e.KeyVersion = 0 }, func(e *Envelope) { e.KeyVersion = math.MaxUint32 }, func(e *Envelope) { e.FormatVersion = 0 }, func(e *Envelope) { e.SuiteID = 2 }, func(e *Envelope) { e.Nonce = nil }, func(e *Envelope) { e.Ciphertext = nil }, func(e *Envelope) { e.Ciphertext = make([]byte, MaxSecretBytes+17) }} {
		c := f.envelope
		change(&c)
		if _, e := EncodeSharedEnvelope(c); e != ErrFormat {
			t.Fatal("malformed envelope", e)
		}
	}
	raw, _ = EncodeSharedEnvelope(f.envelope)
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte(" "), MaxSharedEnvelopeBytes+1), []byte("null"), []byte("{"), []byte{255}, append([]byte(" "), raw...), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"nonce":""}`)...), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unknown":1}`)...), bytes.Replace(raw, []byte(`"keyId"`), []byte(`"KeyId"`), 1)} {
		if _, e := DecodeSharedEnvelope(bad); e != ErrFormat {
			t.Fatal("noncanonical envelope", e)
		}
	}
	newer := f.envelope
	newer.FormatVersion++
	raw, _ = json.Marshal(newer)
	if _, e := DecodeSharedEnvelope(raw); e != ErrNewerFormat {
		t.Fatal(e)
	}
	big := f.envelope
	big.Ciphertext = make([]byte, MaxSecretBytes+16)
	raw, e = EncodeSharedEnvelope(big)
	if e != nil || len(raw) > MaxSharedEnvelopeBytes {
		t.Fatal("maximum envelope", e)
	}
}
