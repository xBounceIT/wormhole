package ikev1

import "crypto/sha256"

// Keep completed IDs for the IKE SA's lifetime. Never evict an ID and make an
// authenticated old exchange fresh again. Exhaustion requires reauthentication.
const maxQuickExchanges = 65536

type quickReply struct {
	messageID uint32
	request   [32]byte
	response  []byte
	natt      bool
}

func (s *Session) quickCompletedID(id uint32) bool { _, ok := s.quickCompleted[id]; return ok }
func (s *Session) rememberQuickReply(packet []byte) {
	r := quickReply{messageID: s.qmMsgID, request: sha256.Sum256(packet), response: s.lastSent, natt: s.lastSentNATT}
	s.quickReplies[s.quickReplyIndex%uint8(len(s.quickReplies))] = r
	s.quickReplyIndex++
}
func (s *Session) repeatQuickReply(packet []byte, id uint32) bool {
	digest := sha256.Sum256(packet)
	for _, reply := range s.quickReplies {
		if reply.messageID == id && len(reply.response) > 0 && reply.request == digest {
			_ = s.cfg.Send(reply.response, reply.natt)
			return true
		}
	}
	return false
}

// Verify without advancing CBC IVs or mutating pending rekey state. Public IKE
// cookies and an exchange header do not authenticate a request. Required QM1/2
// payloads also prevent a captured informational HASH from being retyped as QM1.
func (s *Session) authenticateQuick(h header, first uint8, rest []byte) bool {
	if h.messageID == 0 || h.flags&flagEncryption == 0 || s.keys == nil {
		return false
	}
	iv := s.qmIV
	if s.state == stDone {
		iv = s.keys.quickModeIV(h.messageID)
	}
	plain, err := cbcDecrypt(s.keys.encKey, iv, rest)
	if err != nil {
		return false
	}
	payloads, consumed, err := parsePayloads(first, plain)
	if err != nil || len(payloads) == 0 || payloads[0].typ != payloadHash {
		return false
	}
	var data []byte
	switch s.state {
	case stDone, stWaitQM2:
		if _, ok := findPayload(payloads, payloadSA); !ok {
			return false
		}
		if _, ok := findPayload(payloads, payloadNonce); !ok {
			return false
		}
		data = concat(be32(h.messageID), afterHash(plain, payloads, consumed))
		if s.state == stWaitQM2 {
			data = concat(be32(h.messageID), s.qmNi, afterHash(plain, payloads, consumed))
		}
	case stWaitQM3:
		data = concat([]byte{0}, be32(h.messageID), s.qmNi, s.qmNr)
	default:
		return false
	}
	return constEq(payloads[0].body, s.keys.prf.Apply(s.keys.skeyidA, data))
}
