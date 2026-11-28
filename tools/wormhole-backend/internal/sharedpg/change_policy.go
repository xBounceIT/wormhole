package sharedpg

import "time"

// ChangePolicy is native deployment metadata, not a renderer preference. The
// application must obtain it from authenticated workspace configuration.
type ChangePolicy struct {
	ConcurrentDevices uint32 `json:"concurrentDevices"`
	TransactionPooler bool   `json:"transactionPooler"`
}

// UseNotifications selects the optional second connection. A transaction-mode
// pooler cannot preserve LISTEN state across transactions.
func (p ChangePolicy) UseNotifications() bool {
	return !p.TransactionPooler && p.ConcurrentDevices <= 300
}

// PollInterval is zero when LISTEN is selected. Regardless of this choice, the
// caller must fetch changes after unlock/reconnect; notifications are only hints.
func (p ChangePolicy) PollInterval() time.Duration {
	if p.UseNotifications() {
		return 0
	}
	return 30 * time.Second
}
