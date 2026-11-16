package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type mremoteEffectiveIdentity struct {
	username, domain, password, protocol string
	passwordOwner                        int
}

type mremoteCredentialSource struct {
	identity mremoteEffectiveIdentity
	parent   int
	protocol int64
	mapped   bool
}

func resolveMRemoteIdentity(node mremoteXMLNode, parent mremoteEffectiveIdentity, index int) mremoteEffectiveIdentity {
	result := parent
	if !attributeTrue(node.InheritUsername) {
		result.username = nullableString(nullableMRemoteText(node.Username, maxCredentialUsernameLength))
	}
	if !attributeTrue(node.InheritDomain) {
		result.domain = nullableString(nullableMRemoteText(node.Domain, maxCredentialDomainLength))
	}
	if !attributeTrue(node.InheritPassword) {
		result.password, result.passwordOwner = strings.TrimSpace(node.Password), index
	}
	if !attributeTrue(node.InheritProtocol) {
		result.protocol = node.Protocol
	}
	return result
}

// Struct keys preserve exact password bytes, including embedded separators. RDP
// spellings are normalized only for matching; nodes retain their explicit values.
type mremoteIdentityKey struct {
	protocol         int64
	username, domain string
}

type mremoteCredentialKey struct {
	mremoteIdentityKey
	password string
}

func mremoteCredentialIdentity(protocol int64, username, domain string) (mremoteIdentityKey, string, string) {
	username, domain = strings.TrimSpace(username), strings.TrimSpace(domain)
	switch protocol {
	case 0:
		domain = ""
	case 1:
		if domain == "" {
			if prefix, user, ok := strings.Cut(username, `\`); ok && prefix != "" && user != "" {
				domain, username = strings.TrimSpace(prefix), strings.TrimSpace(user)
			}
		}
	case 6:
		username, domain = "", ""
	}
	key := mremoteIdentityKey{protocol, username, domain}
	if protocol == 1 {
		key.username, key.domain = foldMRemoteAccount(username), foldMRemoteAccount(domain)
	}
	return key, username, domain
}

func foldMRemoteAccount(value string) string {
	return strings.Map(func(character rune) rune {
		canonical := character
		for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		return canonical
	}, value)
}

type mremoteCredentialGroup struct {
	credential mremotePlannedCredential
	key        mremoteCredentialKey
	nodes      []int
	usages     []int // Connections only; folder assignments do not inflate sharing.
}

func planMRemoteCredentials(ctx context.Context, database *sql.DB, plan *mremotePlan, sources []mremoteCredentialSource, request mremoteImportRequest, password string, iterations int, taken map[string]struct{}) error {
	plan.ReuseExisting = request.ReuseExisting == nil || *request.ReuseExisting
	// Propagate the protocols of descendants sharing the same password source.
	// A mixed-protocol folder cannot safely own one protocol-scoped credential.
	protocols := make([]uint, len(sources))
	for i := len(sources) - 1; i >= 0; i-- {
		source := sources[i]
		if plan.Nodes[i].Kind == workspaceNodeConnection {
			protocols[i] |= 1 << source.protocol
		}
		if source.parent >= 0 && source.identity.passwordOwner == sources[source.parent].identity.passwordOwner {
			protocols[source.parent] |= protocols[i]
		}
	}
	groups := make([]mremoteCredentialGroup, 0)
	fingerprints := make(map[mremoteCredentialKey]int)
	type decryption struct {
		plain string
		ok    bool
	}
	decrypted := make(map[string]decryption)
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		node := &plan.Nodes[i]
		if source.identity.password == "" || !source.mapped {
			continue
		}
		if node.Kind == workspaceNodeFolder && protocols[i] & ^(uint(1)<<source.protocol) != 0 {
			continue
		}
		if request.StructureOnly {
			addMRemoteWarning(plan, fmt.Sprintf("Password for '%s' was not imported in structure-only mode.", node.Name))
			continue
		}
		secret, exists := decrypted[source.identity.password]
		if !exists {
			secret.plain, secret.ok = decryptMRemote(source.identity.password, password, iterations)
			decrypted[source.identity.password] = secret
		}
		if !secret.ok {
			addMRemoteWarning(plan, fmt.Sprintf("Could not decrypt password for '%s'; credential left unset.", node.Name))
			continue
		}
		if secret.plain == "" {
			continue
		}
		if utf8.RuneCountInString(secret.plain) > maxStoredCredentialPassword || len(secret.plain) > maxStoredCredentialBytes {
			addMRemoteWarning(plan, fmt.Sprintf("Password for '%s' exceeds Wormhole's protected credential limit; credential left unset.", node.Name))
			continue
		}
		identity, username, domain := mremoteCredentialIdentity(source.protocol, source.identity.username, source.identity.domain)
		key := mremoteCredentialKey{identity, secret.plain}
		index, exists := fingerprints[key]
		if !exists {
			index = len(groups)
			fingerprints[key] = index
			groups = append(groups, mremoteCredentialGroup{key: key, credential: mremotePlannedCredential{
				ID:       deterministicMRemoteID(request.PlanNonce, "credential", strconv.Itoa(index)),
				Protocol: source.protocol, Username: username, Domain: domain, Password: secret.plain,
			}})
		}
		groups[index].nodes = append(groups[index].nodes, i)
		if node.Kind == workspaceNodeConnection {
			groups[index].usages = append(groups[index].usages, i)
		}
	}
	var candidates map[mremoteIdentityKey][]mremoteReusedCredential
	if plan.ReuseExisting && len(groups) > 0 {
		var err error
		candidates, err = loadMRemoteReuseCandidates(ctx, database)
		if err != nil {
			return err
		}
	}
	matches, err := matchMRemoteCredentials(ctx, groups, candidates, request.ElectronUserDataPath)
	if err != nil {
		return err
	}
	for index, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		credential := group.credential
		match := matches[index]
		if match != nil {
			credential.ID = match.ID
			plan.ReusedCredentials = append(plan.ReusedCredentials, *match)
		} else {
			credential.Name = nameMRemoteCredential(group, plan.Nodes, sources, taken)
			plan.Credentials = append(plan.Credentials, credential)
			if len(group.usages) > 1 {
				plan.SharedCredentials++
				plan.SharedCredentialConnections += len(group.usages)
			}
		}
		for _, index := range group.nodes {
			plan.Nodes[index].CredentialID = sql.NullString{String: credential.ID, Valid: true}
		}
	}
	return nil
}

func nameMRemoteCredential(group mremoteCredentialGroup, nodes []mremotePlannedNode, sources []mremoteCredentialSource, taken map[string]struct{}) string {
	first := group.nodes[0]
	if len(group.usages) > 0 {
		first = group.usages[0]
	}
	anchor, fallback := nullableString(nodes[first].Host), nodes[first].Name
	if len(group.usages) > 1 {
		// Intersect ancestor paths by node identity, not by potentially duplicated names.
		ancestors := make([]int, 0)
		for p := sources[first].parent; p >= 0; p = sources[p].parent {
			ancestors = append(ancestors, p)
		}
		for _, index := range group.usages[1:] {
			seen := make(map[int]bool)
			for p := sources[index].parent; p >= 0; p = sources[p].parent {
				seen[p] = true
			}
			for len(ancestors) > 0 && !seen[ancestors[0]] {
				ancestors = ancestors[1:]
			}
		}
		if len(ancestors) == 0 {
			anchor = ""
		} else {
			anchor = nodes[ancestors[0]].Name
		}
		fallback = "shared"
	}
	user := group.credential.Username
	if group.credential.Domain != "" {
		user = group.credential.Domain + "-" + user
	}
	if len(group.usages) > 1 && anchor == "" && mremoteNamePart(user) != "" {
		stem := "mremoteng-" + mremoteNamePart(user) + "-" + protocolName(sql.NullInt64{Int64: group.credential.Protocol, Valid: true}) + "-shared"
		return allocateMRemoteName(stem, taken)
	}
	return allocateMRemoteCredentialName(user, anchor, fallback, group.credential.Protocol, taken)
}

type mremoteReusedCredential struct {
	ID, Username, Domain, Encoded, Encoding, CreatedAt string
	Protocol                                           int64
}

type mremoteCredentialQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readMRemoteReuseCandidates(ctx context.Context, database mremoteCredentialQuery) ([]mremoteReusedCredential, error) {
	// Runtime lookups normalize GUIDs. Ambiguous legacy case variants cannot
	// safely identify one profile or secret, so leave them out before decrypting.
	rows, err := database.QueryContext(ctx, `WITH profiles AS (
 SELECT Id, Username, Domain, Protocol, Kind, SecretProvider, CreatedAt,
 COUNT(*) OVER (PARTITION BY Id COLLATE NOCASE) AS Copies FROM CredentialProfiles
), secrets AS (
 SELECT Id, Secret, Encoding, COUNT(*) OVER (PARTITION BY Id COLLATE NOCASE) AS Copies FROM CredentialSecrets
)
SELECT p.Id, COALESCE(p.Username, ''), COALESCE(p.Domain, ''), p.Protocol, s.Secret, s.Encoding, p.CreatedAt
FROM profiles p JOIN secrets s ON s.Id = p.Id COLLATE NOCASE
WHERE p.Copies = 1 AND s.Copies = 1 AND COALESCE(p.Kind, 0) = 0
 AND COALESCE(p.SecretProvider, 0) = 0 AND p.Protocol IN (0, 1, 6);`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	candidates := make([]mremoteReusedCredential, 0)
	for rows.Next() {
		var candidate mremoteReusedCredential
		if err := rows.Scan(&candidate.ID, &candidate.Username, &candidate.Domain, &candidate.Protocol, &candidate.Encoded, &candidate.Encoding, &candidate.CreatedAt); err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func loadMRemoteReuseCandidates(ctx context.Context, database *sql.DB) (map[mremoteIdentityKey][]mremoteReusedCredential, error) {
	candidates, err := readMRemoteReuseCandidates(ctx, database)
	if err != nil {
		return nil, err
	}
	result := make(map[mremoteIdentityKey][]mremoteReusedCredential)
	type orderedCandidate struct {
		credential mremoteReusedCredential
		created    time.Time
		validTime  bool
	}
	ordered := make([]orderedCandidate, 0)
	for _, candidate := range candidates {
		created, err := time.Parse(time.RFC3339Nano, candidate.CreatedAt)
		ordered = append(ordered, orderedCandidate{candidate, created, err == nil})
	}
	// RFC3339Nano omits trailing zeros: lexical ordering reverses .1Z/.11Z
	// and puts a whole second after its fractions. Compare timestamps as times.
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.validTime != right.validTime {
			return !left.validTime
		}
		if left.validTime {
			if !left.created.Equal(right.created) {
				return left.created.Before(right.created)
			}
		} else if left.credential.CreatedAt != right.credential.CreatedAt {
			return left.credential.CreatedAt < right.credential.CreatedAt
		}
		return left.credential.ID < right.credential.ID
	})
	for _, item := range ordered {
		candidate := item.credential
		key, _, _ := mremoteCredentialIdentity(candidate.Protocol, candidate.Username, candidate.Domain)
		result[key] = append(result[key], candidate)
	}
	return result, nil
}

var mremoteUnprotectCredentialSecret = unprotectStoredSecret

type mremotePasswordKey struct {
	mremoteIdentityKey
	digest [sha256.Size]byte
}

func matchMRemoteCredentials(ctx context.Context, groups []mremoteCredentialGroup, candidates map[mremoteIdentityKey][]mremoteReusedCredential, userDataPath string) ([]*mremoteReusedCredential, error) {
	matches := make([]*mremoteReusedCredential, len(groups))
	byPassword := make(map[mremotePasswordKey][]int)
	remaining := make(map[mremoteIdentityKey]int)
	for index, group := range groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		password := []byte(group.credential.Password)
		key := mremotePasswordKey{group.key.mremoteIdentityKey, sha256.Sum256(password)}
		clear(password)
		byPassword[key] = append(byPassword[key], index)
		remaining[group.key.mremoteIdentityKey]++
	}
	for identity, count := range remaining {
		for _, candidate := range candidates[identity] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			secret, err := mremoteUnprotectCredentialSecret(candidate.ID, candidate.Encoded, candidate.Encoding, userDataPath)
			if cancelErr := ctx.Err(); cancelErr != nil {
				clear(secret)
				return nil, cancelErr
			}
			if err != nil {
				clear(secret)
				continue
			}
			key := mremotePasswordKey{identity, sha256.Sum256(secret)}
			indexes := byPassword[key]
			unmatched := indexes[:0]
			for _, index := range indexes {
				if err := ctx.Err(); err != nil {
					clear(secret)
					return nil, err
				}
				// Confirm exact bytes even if distinct passwords share a digest.
				password := []byte(groups[index].credential.Password)
				matched := subtle.ConstantTimeCompare(secret, password) == 1
				clear(password)
				if matched {
					matches[index] = &candidate
				} else {
					unmatched = append(unmatched, index)
				}
			}
			clear(secret)
			count -= len(indexes) - len(unmatched)
			if len(unmatched) == 0 {
				delete(byPassword, key)
			} else {
				byPassword[key] = unmatched
			}
			if count == 0 {
				break
			}
		}
	}
	return matches, ctx.Err()
}

func validateMRemoteReusedCredentials(ctx context.Context, tx *sql.Tx, credentials []mremoteReusedCredential) error {
	if len(credentials) == 0 {
		return ctx.Err()
	}
	candidates, err := readMRemoteReuseCandidates(ctx, tx)
	if err != nil {
		return err
	}
	current := make(map[string]mremoteReusedCredential, len(candidates))
	for _, candidate := range candidates {
		current[candidate.ID] = candidate
	}
	for _, expected := range credentials {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, exists := current[expected.ID]
		if !exists || actual != expected {
			return errors.New("a reused mRemoteNG credential changed after analysis; analyze the file again")
		}
	}
	return nil
}
