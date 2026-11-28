package resolver

import (
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// chain is ordered leaf to root. Explicit zero parity or flow control prevents
// inheritance. Unknown persisted settings use the same defaults as legacy.
func ProjectSerialSettings(chain []vaultstore.NodeMetadata) vault.SerialSettings {
	var baud, data, stop, parity, flow *int
	for _, n := range chain {
		first(&baud, n.SerialBaudRate)
		first(&data, n.SerialDataBits)
		first(&stop, n.SerialStopBits)
		first(&parity, n.SerialParity)
		first(&flow, n.SerialFlowControl)
	}
	s := vault.DefaultSerialSettings()
	for _, field := range []struct {
		source   *int
		dst      *int
		min, max int
	}{
		{baud, &s.BaudRate, 1, 10_000_000}, {data, &s.DataBits, 5, 8}, {stop, &s.StopBits, 1, 3},
		{parity, &s.Parity, 0, 4}, {flow, &s.FlowControl, 0, 3},
	} {
		if field.source != nil && *field.source >= field.min && *field.source <= field.max {
			*field.dst = *field.source
		}
	}
	return s
}
