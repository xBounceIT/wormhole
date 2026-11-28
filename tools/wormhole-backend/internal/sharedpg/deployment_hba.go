package sharedpg

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

// DeploymentHBARules returns an include file for the DBA to install before
// any broader HBA rules. PostgreSQL 16 supports anchored user-name patterns.
func DeploymentHBARules(database, roleTag, workspaceID string, networks []string) (string, error) {
	if !identifier(database) || deploy.ValidateIdentity(roleTag, workspaceID) != nil || len(networks) == 0 || len(networks) > 32 {
		return "", ErrConfiguration
	}
	var rules strings.Builder
	rules.WriteString("# Wormhole workspace TCP access. Place before broader host rules in pg_hba.conf.\n")
	// Quoting the database makes names such as "all" literal. Validated role
	// tags contain only base32 characters, and the suffix separates workspaces.
	scope := fmt.Sprintf(`"%s" /^wh_%s_`, database, roleTag)
	seen := make(map[netip.Prefix]bool)
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			ip, err := netip.ParseAddr(network)
			if err != nil || ip.Zone() != "" {
				return "", ErrConfiguration
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix != prefix.Masked() {
			return "", ErrConfiguration
		}
		if !seen[prefix] {
			fmt.Fprintf(&rules, "hostssl %s %s scram-sha-256\n", scope, prefix)
			seen[prefix] = true
		}
	}
	fmt.Fprintf(&rules, "host %s all reject\n", scope)
	return rules.String(), nil
}
