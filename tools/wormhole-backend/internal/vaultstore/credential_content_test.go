package vaultstore

import (
	"github.com/google/uuid"
	"testing"
)

func TestCredentialContentAndLocalSeal(t *testing.T) {
	c := Credential{CredentialMetadata: CredentialMetadata{ID: uuid.NewString(), Name: "Account", Protocol: "ssh", Kind: "password", Provider: "local"}, RowVersion: 1, Fields: []CredentialField{{Field: "password", Version: 1, Present: true}}}
	for _, size := range []int{0, 31, 32, 33, 64} {
		c.Seal = make([]byte, size)
		if err := c.ValidateContent(); err != nil {
			t.Fatal("content depends on seal suite", size, err)
		}
		err := c.Validate()
		if (size == 32 && err != nil) || (size != 32 && err != ErrFormat) {
			t.Fatal("local HMAC shape changed", size, err)
		}
	}
	c.Seal = make([]byte, 32)
	c.Fields[0].Version = 0
	if c.Validate() != ErrFormat || c.ValidateContent() != ErrFormat {
		t.Fatal("invalid content accepted")
	}
}
