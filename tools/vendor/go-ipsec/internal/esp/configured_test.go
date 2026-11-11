package esp

import (
	"bytes"
	"errors"
	"github.com/n0madic/go-ipsec/internal/cryptosuite"
	"testing"
	"time"
)

func TestESPConfiguredMatrixAndLimits(t *testing.T) {
	for id := cryptosuite.FirstCBC; id < cryptosuite.FirstCBC+20; id++ {
		p, _ := cryptosuite.Lookup(id)
		encr, mac := bytes.Repeat([]byte{1}, p.EncryptionBytes), bytes.Repeat([]byte{2}, p.IntegrityBytes)
		out, err := NewSA(Suite(id), 2, 1, encr, mac, encr, mac, 64)
		if err != nil {
			t.Fatal(err)
		}
		in, err := NewSA(Suite(id), 1, 2, encr, mac, encr, mac, 64)
		if err != nil {
			t.Fatal(err)
		}
		plain := []byte{0x45, 1, 2, 3, 4}
		packet, err := out.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := in.Decrypt(packet)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("ESP round trip failed", id, err)
		}
		if _, err = in.Decrypt(packet); !errors.Is(err, ErrReplay) {
			t.Fatal("replay accepted")
		}
		in.ConfigurePolicy(false, 0, 0)
		if _, err = in.Decrypt(packet); err != nil {
			t.Fatal("disabled replay rejected packet", err)
		}
		zeroSequence := append([]byte(nil), packet...)
		clear(zeroSequence[4:8])
		icvStart := len(zeroSequence) - p.ICVBytes
		copy(zeroSequence[icvStart:], p.MAC(mac, zeroSequence[:icvStart])[:p.ICVBytes])
		if _, err := in.Decrypt(zeroSequence); !errors.Is(err, ErrReplay) {
			t.Fatal("zero sequence accepted with replay disabled", err)
		}
		packet[len(packet)-1] ^= 1
		if _, err = in.Decrypt(packet); err == nil {
			t.Fatal("bad ICV accepted without replay detection")
		}
		out.ConfigurePolicy(true, 0, out.Bytes())
		if !out.Expired() {
			t.Fatal("byte limit ignored")
		}
		if _, err = out.Encrypt(plain); !errors.Is(err, ErrLifetimeExpired) {
			t.Fatal("expired key encrypted", err)
		}
		out.ConfigurePolicy(true, time.Nanosecond, 0)
		time.Sleep(time.Microsecond)
		if !out.Expired() {
			t.Fatal("time limit ignored")
		}
		if _, err = out.Encrypt(plain); !errors.Is(err, ErrLifetimeExpired) {
			t.Fatal(err)
		}
		in.ConfigurePolicy(false, 0, 1)
		packet[len(packet)-1] ^= 1
		if _, err = in.Decrypt(packet); !errors.Is(err, ErrLifetimeExpired) {
			t.Fatal("inbound byte limit ignored", err)
		}
		if Suite(id).String() != p.Name {
			t.Fatal("suite name lost")
		}
	}
}
