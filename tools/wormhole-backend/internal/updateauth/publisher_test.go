package updateauth

import (
	"strings"
	"testing"
)

func TestPublisherPin(t *testing.T) {
	value := strings.Repeat("cd", 32)
	pin, err := ParsePublisherPin(value)
	if err != nil || pin[0] != 0xcd || pin[31] != 0xcd {
		t.Fatalf("valid pin rejected: %x, %v", pin, err)
	}
	for _, bad := range []string{"", value + "\n", strings.ToUpper(value), strings.Repeat("0", 64), strings.Repeat("zz", 32)} {
		if _, err := ParsePublisherPin(bad); err != ErrPublisherUnavailable {
			t.Fatalf("invalid pin accepted: %q, %v", bad, err)
		}
	}
}
