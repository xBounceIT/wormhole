package ikev1

import "fmt"

// Proposal uses the RFC 2409 encryption and hash identifiers.
type Proposal struct{ Encryption, KeyBits, Hash uint16 }

// Rekey starts a new Quick Mode under the authenticated IKE SA.
func (s *Session) Rekey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stDone {
		return fmt.Errorf("IKEv1 rekey already in progress")
	}
	return s.startQuickMode()
}

func (s *Session) ikeProposals() []ikeProposal {
	if len(s.cfg.Proposals) == 0 {
		return defaultIKEProposals(s.authMethod())
	}
	groups := s.cfg.Groups
	if len(groups) == 0 {
		groups = []uint16{14}
	}
	var out []ikeProposal
	for _, group := range groups {
		for _, p := range s.cfg.Proposals {
			bits := p.KeyBits
			if p.Encryption == 5 {
				bits = 192
			}
			out = append(out, ikeProposal{encr: p.Encryption, keyBits: bits, hash: p.Hash, group: group, auth: s.authMethod(), lifeSeconds: s.cfg.Lifetime})
		}
		if s.cfg.Mode == ModeAggressive {
			break
		}
	}
	return out
}

// Close stops retransmission and wipes session-owned credentials and derived keys.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = stFailed
	if s.timer != nil {
		s.timer.Stop()
	}
	clear(s.psk)
	clear(s.cfg.PSK)
	if s.keys != nil {
		clear(s.keys.skeyid)
		clear(s.keys.skeyidD)
		clear(s.keys.skeyidA)
		clear(s.keys.skeyidE)
		clear(s.keys.encKey)
	}
}
