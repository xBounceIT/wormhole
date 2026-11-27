package main

import (
	"bytes"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// The native helper accepts one versioned request and replies once. Only a
// successful enrollment or authentication may return 32 factor bytes.
const touchIDProtocolVersion = 1
const maxTouchIDReply = 2 + 32

func encodeTouchIDRequest(operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
	request := []byte{touchIDProtocolVersion, byte(operation)}
	switch operation {
	case touchIDProbe:
		if vaultID != "" || slotID != "" {
			return nil, vaultwire.ErrProtocol
		}
		return request, nil
	case touchIDEnroll, touchIDOpen, touchIDRemove:
		if !validTouchIDCoordinate(vaultID) || !validTouchIDCoordinate(slotID) {
			return nil, vaultwire.ErrProtocol
		}
		request = append(request, vaultID...)
		return append(request, slotID...), nil
	default:
		return nil, vaultwire.ErrProtocol
	}
}

func decodeTouchIDReply(operation touchIDOperation, frame []byte) ([]byte, error) {
	if len(frame) < 2 || frame[0] != touchIDProtocolVersion || operation < touchIDProbe || operation > touchIDRemove {
		return nil, vaultwire.ErrProtocol
	}
	if frame[1] == 0 && (operation == touchIDEnroll || operation == touchIDOpen) {
		if len(frame) != maxTouchIDReply {
			return nil, vaultwire.ErrProtocol
		}
		return bytes.Clone(frame[2:]), nil
	}
	if len(frame) != 2 {
		return nil, vaultwire.ErrProtocol
	}
	switch frame[1] {
	case 0:
		return nil, nil
	case 1:
		return nil, errTouchIDUnavailable
	case 2:
		return nil, errTouchIDCanceled
	default:
		return nil, vaultwire.ErrProtocol
	}
}
