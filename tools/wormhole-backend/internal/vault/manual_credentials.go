package vault

import (
	"github.com/google/uuid"
	"strconv"
	"strings"
	"unicode"
)

// Native and isolated documents use the same field order for purpose-bound
// manual credentials. The expected protocol and purpose are fixed by callers.
func manualCredentialInfo(b BundleBinding, route *TunnelBundleBinding, endpoint, protocol, purpose string) ([]byte, error) {
	for _, id := range []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, ErrFormat
		}
	}
	if _, err := b.info(); err != nil {
		return nil, err
	}
	if b.Protocol != protocol || b.UseExternalClient || b.Port == 0 || b.Epoch > 9007199254740991 || len(b.Host) > 1024 || strings.IndexFunc(b.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 {
		return nil, ErrFormat
	}
	fields := []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID, b.Protocol, b.Host, strconv.Itoa(int(b.Port)), b.TunnelConfigID, strconv.FormatUint(b.Epoch, 10), "", "", "", "", ""}
	if route == nil {
		if b.TunnelConfigID != "" || endpoint != "" {
			return nil, ErrFormat
		}
	} else {
		if route.BundleBinding != b || !ValidRouteEndpoint(endpoint) {
			return nil, ErrFormat
		}
		if _, err := route.info(); err != nil {
			return nil, err
		}
		fields[9], fields[10], fields[11], fields[12], fields[13] = route.FileID, strconv.Itoa(int(route.Kind)), strconv.FormatUint(route.RowVersion, 10), strconv.FormatUint(route.ConfigurationVersion, 10), endpoint
	}
	values := make([][]byte, len(fields))
	for i, field := range fields {
		values[i] = []byte(field)
	}
	return canonical(purpose, values...), nil
}
