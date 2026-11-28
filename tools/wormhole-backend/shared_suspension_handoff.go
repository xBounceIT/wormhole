package main

import (
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Remote authorizations stay in this admission. Each sweep verifies the
// signatures again against the current workspace epoch and organisation pin.
func (c *sharedAdmissionController) monitorCustodianSuspensions(session suspensionInventorySession, handoff sharedSuspensionReceiptSession, pin vault.UserKeyTrust) {
	supported, err := handoff.SuspensionReceiptsSupported(c.lifetime)
	if err != nil || !supported {
		return
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	var cursor uuid.UUID
	ordinals, seen := make(map[string]int), make(map[string]int)
	progressed := false
	for {
		select {
		case <-c.lifetime.Done():
			return
		case <-timer.C:
		}
		accounts, err := handoff.ReadSuspensionReceipts(c.lifetime, pin, c.rotationEpoch, cursor)
		if err != nil {
			return
		}
		for _, account := range accounts {
			key := account.ID.String()
			seen[key] = ordinals[key]
			changed, err := c.advanceSuspensionRotation(c.lifetime, session, seen, 0, &account)
			if err != nil {
				return
			}
			progressed = progressed || changed
			cursor = account.ID
		}
		delay := 250 * time.Millisecond
		if len(accounts) < sharedpg.SuspensionReceiptPageSize {
			cursor = uuid.Nil
			ordinals, seen = seen, ordinals
			clear(seen)
			if !progressed {
				delay = 30 * time.Second
			}
			progressed = false
		}
		timer.Reset(delay)
	}
}
