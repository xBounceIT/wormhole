package vaultwire

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeRequestFieldContracts(t *testing.T) {
	for _, tc := range []struct {
		name, frame string
		valid       bool
	}{
		{"reordered", `{"payload":{"id":2},"operation":"read","id":1,"version":1}`, true},
		{"escaped-name", `{"version":1,"\u0069d":1,"operation":"read"}`, true},
		{"escaped-duplicate", `{"version":1,"id":1,"\u0069d":2,"operation":"read"}`, false},
		{"null-target", `{"version":1,"id":1,"operation":"read","targetId":null}`, true},
		{"null-payload", `{"version":1,"id":1,"operation":"read","payload":null}`, true},
		{"null-heartbeat-payload", `{"version":1,"id":1,"operation":"heartbeat","payload":null}`, false},
		{"string-id", `{"version":1,"id":"1","operation":"read"}`, false},
		{"fraction-id", `{"version":1,"id":1.0,"operation":"read"}`, false},
		{"negative-id", `{"version":1,"id":-1,"operation":"read"}`, false},
		{"overflow-version", `{"version":65536,"id":1,"operation":"read"}`, false},
		{"null-operation", `{"version":1,"id":1,"operation":null}`, false},
		{"invalid-after-payload", `{"payload":{"x":1},"version":1,"id":1,"operation":2}`, false},
		{"truncated-object", `{"version":1,"id":1,"operation":"read"`, false},
		{"trailing-comma", `{"version":1,"id":1,"operation":"read",}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := []byte(tc.frame)
			request, err := decodeRequest(frame)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !bytes.Equal(frame, []byte(tc.frame)) {
				t.Fatal("decoder mutated caller frame")
			}
			if err != nil && len(request.Payload) != 0 {
				t.Fatal("rejected request retained payload")
			}
		})
	}
}

func BenchmarkDecodeRequestLargePayload(b *testing.B) {
	frame := []byte(`{"version":1,"id":1,"operation":"read","payload":"` + strings.Repeat("x", 1024*1024) + `"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		request, err := decodeRequest(frame)
		if err != nil {
			b.Fatal(err)
		}
		clear(request.Payload)
	}
}
