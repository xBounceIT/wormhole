//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ifTypeFastEthernetFX  = 62
	ifTypeFastEthernetT   = 69
	ifTypeGigabitEthernet = 117
	ifTypeWWANPP          = 243
	ifTypeWWANPP2         = 244
	ipUnicastIF           = 31
	maxPhysicalAdapters   = 8
	maxPhysicalCandidates = 24
)

const physicalConnectStagger = 250 * time.Millisecond

type physicalAdapterCandidate struct {
	id        string
	active    bool
	ifType    uint32
	ipv4Index uint32
	ipv6Index uint32
	metric    uint32
	speed     uint64
}

var (
	dnsAPI                      = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsQueryEx              = dnsAPI.NewProc("DnsQueryEx")
	procDnsRecordListFree       = dnsAPI.NewProc("DnsRecordListFree")
	physicalDNSConcurrency      = make(chan struct{}, 8)
	errPhysicalInterfaceChanged = errors.New("physical network interface changed")
	physicalAdapterSource       = physicalAdapterCandidates
	physicalHostResolver        = resolvePortalHostOnInterfaces
	physicalDNSQuery            = queryWindowsDNS
	physicalCurrentAdapter      = currentPhysicalAdapter
)

const (
	dnsTypeA            = 1
	dnsTypeAAAA         = 28
	dnsQueryBypassCache = 0x00000008
	dnsFreeRecordList   = 1
)

type dnsQueryRequest struct {
	Version                 uint32
	QueryName               *uint16
	QueryType               uint16
	QueryOptions            uint64
	DNSServerList           uintptr
	InterfaceIndex          uint32
	QueryCompletionCallback uintptr
	QueryContext            uintptr
}

type dnsQueryResult struct {
	Version      uint32
	QueryStatus  int32
	QueryOptions uint64
	QueryRecords *dnsRecordHeader
	Reserved     uintptr
}

type dnsRecordHeader struct {
	Next       *dnsRecordHeader
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
	TTL        uint32
	Reserved   uint32
	Data       [16]byte
}

func physicalTransportAdapterIDs() ([]string, error) {
	candidates, err := physicalAdapterSource(true)
	if err != nil {
		return nil, err
	}
	hasActive := false
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.id)
		hasActive = hasActive || candidate.active && (candidate.ipv4Index != 0 || candidate.ipv6Index != 0)
	}
	if !hasActive {
		return nil, errors.New("Stormshield cannot find an active physical network adapter; connect Ethernet, Wi-Fi, or mobile data and try again")
	}
	return ids, nil
}

func physicalPortalDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if literal := net.ParseIP(host); literal != nil && literal.IsLoopback() {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	for attempt := 0; attempt < 2; attempt++ {
		candidates, candidateErr := physicalAdapterSource(false)
		if candidateErr != nil || len(candidates) == 0 {
			if candidateErr == nil {
				candidateErr = errors.New("no active physical network adapter")
			}
			return nil, candidateErr
		}
		resolved, resolveErr := resolvePortalCandidates(ctx, host, candidates)
		if resolveErr != nil {
			return nil, resolveErr
		}
		connection, dialErr := dialPortalCandidates(ctx, network, port, resolved)
		if attempt == 0 && errors.Is(dialErr, errPhysicalInterfaceChanged) {
			continue
		}
		return connection, dialErr
	}
	return nil, errPhysicalInterfaceChanged
}

type physicalPortalCandidate struct {
	adapter physicalAdapterCandidate
	address net.IPAddr
}

type physicalDialResult struct {
	connection net.Conn
	err        error
}

func resolvePortalCandidates(
	ctx context.Context,
	host string,
	candidates []physicalAdapterCandidate,
) ([]physicalPortalCandidate, error) {
	if literal := net.ParseIP(host); literal != nil {
		resolved := make([]physicalPortalCandidate, 0, len(candidates))
		for _, candidate := range candidates {
			if (literal.To4() != nil && candidate.ipv4Index != 0) || (literal.To4() == nil && candidate.ipv6Index != 0) {
				resolved = append(resolved, physicalPortalCandidate{adapter: candidate, address: net.IPAddr{IP: literal}})
			}
		}
		return resolved, nil
	}
	type result struct {
		index     int
		addresses []net.IPAddr
		err       error
	}
	results := make(chan result, len(candidates))
	for index, candidate := range candidates {
		go func() {
			addresses, lookupErr := physicalHostResolver(ctx, host, candidate.ipv4Index, candidate.ipv6Index)
			results <- result{index: index, addresses: addresses, err: lookupErr}
		}()
	}
	byAdapter := make([]result, len(candidates))
	for range candidates {
		select {
		case resolved := <-results:
			byAdapter[resolved.index] = resolved
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var unresolved []int
	for index := range byAdapter {
		if len(byAdapter[index].addresses) == 0 {
			unresolved = append(unresolved, index)
		}
	}
	if len(unresolved) > 0 {
		if systemAddresses, systemErr := net.DefaultResolver.LookupIPAddr(ctx, host); systemErr == nil {
			for _, index := range unresolved {
				for _, address := range distinctIPAddresses(systemAddresses) {
					if (address.IP.To4() != nil && candidates[index].ipv4Index != 0) ||
						(address.IP.To4() == nil && candidates[index].ipv6Index != 0) {
						byAdapter[index].addresses = append(byAdapter[index].addresses, address)
					}
				}
			}
		} else if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	var resolved []physicalPortalCandidate
	var lastErr error
	seen := make(map[string]bool)
	for index, result := range byAdapter {
		if result.err != nil {
			lastErr = result.err
		}
		for _, address := range result.addresses {
			key := strings.ToLower(candidates[index].id) + "\x00" + address.IP.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			resolved = append(resolved, physicalPortalCandidate{adapter: candidates[index], address: address})
		}
	}
	if len(resolved) > 0 {
		return orderPhysicalPortalCandidates(resolved), nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("Stormshield could not resolve the portal on a physical adapter: %w", lastErr)
	}
	return nil, errors.New("Stormshield could not resolve the portal on a physical adapter")
}

func orderPhysicalPortalCandidates(candidates []physicalPortalCandidate) []physicalPortalCandidate {
	ipv4 := make([]physicalPortalCandidate, 0, len(candidates))
	ipv6 := make([]physicalPortalCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.address.IP.To4() != nil {
			ipv4 = append(ipv4, candidate)
		} else {
			ipv6 = append(ipv6, candidate)
		}
	}
	interleaved := make([]physicalPortalCandidate, 0, min(len(candidates), maxPhysicalCandidates))
	for index := 0; index < len(ipv4) || index < len(ipv6); index++ {
		if index < len(ipv4) {
			interleaved = append(interleaved, ipv4[index])
			if len(interleaved) == maxPhysicalCandidates {
				break
			}
		}
		if index < len(ipv6) {
			interleaved = append(interleaved, ipv6[index])
			if len(interleaved) == maxPhysicalCandidates {
				break
			}
		}
	}
	return interleaved
}

func dialPortalCandidates(
	ctx context.Context,
	network string,
	port string,
	candidates []physicalPortalCandidate,
) (net.Conn, error) {
	if len(candidates) == 0 {
		return nil, errors.New("Stormshield cannot route the portal through an active physical adapter")
	}
	dialContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan physicalDialResult)
	for index, candidate := range candidates {
		go func() {
			if index > 0 {
				timer := time.NewTimer(time.Duration(index) * physicalConnectStagger)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-dialContext.Done():
					return
				}
			}
			ipv6 := candidate.address.IP.To4() == nil
			current, currentErr := physicalCurrentAdapter(candidate.adapter.id)
			if currentErr != nil {
				publishPhysicalDialResult(dialContext, results, physicalDialResult{err: currentErr})
				return
			}
			interfaceIndex := current.ipv4Index
			originalIndex := candidate.adapter.ipv4Index
			if ipv6 {
				interfaceIndex = current.ipv6Index
				originalIndex = candidate.adapter.ipv6Index
			}
			if interfaceIndex == 0 {
				publishPhysicalDialResult(dialContext, results, physicalDialResult{err: errors.New("physical network interface is no longer active")})
				return
			}
			if interfaceIndex != originalIndex {
				publishPhysicalDialResult(dialContext, results, physicalDialResult{err: errPhysicalInterfaceChanged})
				return
			}
			dialer := net.Dialer{Control: bindWindowsPhysicalInterface(interfaceIndex, ipv6)}
			connection, dialErr := dialer.DialContext(dialContext, network, net.JoinHostPort(candidate.address.IP.String(), port))
			publishPhysicalDialResult(dialContext, results, physicalDialResult{connection: connection, err: dialErr})
		}()
	}
	var lastErr error
	interfaceChanged := false
	for range candidates {
		select {
		case result := <-results:
			if result.err == nil {
				if ctx.Err() != nil {
					_ = result.connection.Close()
					return nil, ctx.Err()
				}
				cancel()
				return result.connection, nil
			}
			interfaceChanged = interfaceChanged || errors.Is(result.err, errPhysicalInterfaceChanged)
			lastErr = result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if interfaceChanged {
		return nil, errPhysicalInterfaceChanged
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("Stormshield cannot route the portal through an active physical adapter")
}

func publishPhysicalDialResult(ctx context.Context, results chan<- physicalDialResult, result physicalDialResult) {
	select {
	case results <- result:
	case <-ctx.Done():
		if result.connection != nil {
			_ = result.connection.Close()
		}
	}
}

func currentPhysicalAdapter(id string) (physicalAdapterCandidate, error) {
	candidates, err := physicalAdapterSource(false)
	if err != nil {
		return physicalAdapterCandidate{}, err
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate.id, id) {
			return candidate, nil
		}
	}
	return physicalAdapterCandidate{}, errors.New("physical network interface is no longer active")
}

func resolvePortalHostOnInterfaces(
	ctx context.Context,
	host string,
	ipv4Index uint32,
	ipv6Index uint32,
) ([]net.IPAddr, error) {
	select {
	case physicalDNSConcurrency <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type result struct {
		addresses []net.IPAddr
		err       error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-physicalDNSConcurrency }()
		var addresses []net.IPAddr
		var failures []error
		if ipv4Index != 0 {
			resolved, err := physicalDNSQuery(host, ipv4Index, dnsTypeA)
			addresses = append(addresses, resolved...)
			if err != nil {
				failures = append(failures, err)
			}
		}
		if ipv6Index != 0 {
			resolved, err := physicalDNSQuery(host, ipv6Index, dnsTypeAAAA)
			addresses = append(addresses, resolved...)
			if err != nil {
				failures = append(failures, err)
			}
		}
		if len(addresses) == 0 && len(failures) > 0 {
			done <- result{err: failures[len(failures)-1]}
			return
		}
		done <- result{addresses: distinctIPAddresses(addresses)}
	}()
	select {
	case resolved := <-done:
		return resolved.addresses, resolved.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func queryWindowsDNS(host string, interfaceIndex uint32, recordType uint16) ([]net.IPAddr, error) {
	queryName, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, errors.New("physical DNS query name is invalid")
	}
	request := dnsQueryRequest{
		Version: 1, QueryName: queryName, QueryType: recordType,
		QueryOptions: dnsQueryBypassCache, InterfaceIndex: interfaceIndex,
	}
	result := dnsQueryResult{Version: 1}
	status, _, _ := procDnsQueryEx.Call(
		uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&result)), 0,
	)
	runtime.KeepAlive(queryName)
	if status != 0 {
		return nil, fmt.Errorf("physical DNS query failed with status %d", status)
	}
	if result.QueryRecords != nil {
		defer procDnsRecordListFree.Call(uintptr(unsafe.Pointer(result.QueryRecords)), dnsFreeRecordList)
	}
	if result.QueryStatus != 0 {
		return nil, fmt.Errorf("physical DNS query completed with status %d", result.QueryStatus)
	}
	var addresses []net.IPAddr
	for header := result.QueryRecords; header != nil; header = header.Next {
		if header.Type == recordType {
			length := net.IPv4len
			if recordType == dnsTypeAAAA {
				length = net.IPv6len
			}
			ip := append(net.IP(nil), header.Data[:length]...)
			addresses = append(addresses, net.IPAddr{IP: ip})
		}
	}
	return addresses, nil
}

func distinctIPAddresses(values []net.IPAddr) []net.IPAddr {
	seen := make(map[string]bool, len(values))
	result := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		key := value.IP.String()
		if key == "<nil>" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

func bindWindowsPhysicalInterface(index uint32, ipv6 bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(handle uintptr) {
			level, value := windows.IPPROTO_IP, int(bits.ReverseBytes32(index))
			if ipv6 {
				level, value = windows.IPPROTO_IPV6, int(index)
			}
			bindErr = windows.SetsockoptInt(windows.Handle(handle), level, ipUnicastIF, value)
		}); err != nil {
			return err
		}
		return bindErr
	}
}

func physicalAdapterCandidates(includeInactive bool) ([]physicalAdapterCandidate, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
	if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size == 0 {
		return nil, errors.New("could not enumerate physical network adapters")
	}
	buffer := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size); err != nil {
		return nil, errors.New("could not enumerate physical network adapters")
	}
	var candidates []physicalAdapterCandidate
	for adapter := first; adapter != nil; adapter = adapter.Next {
		name := windows.UTF16PtrToString(adapter.FriendlyName)
		detail := windows.UTF16PtrToString(adapter.Description)
		active := adapter.OperStatus == windows.IfOperStatusUp
		if (!includeInactive && !active) || !isPhysicalInterfaceType(adapter.IfType) ||
			isVPNLikeAdapter(name+" "+detail) || (adapter.IfIndex == 0 && adapter.Ipv6IfIndex == 0) {
			continue
		}
		id := strings.TrimSpace(windows.BytePtrToString(adapter.AdapterName))
		if id == "" {
			continue
		}
		metric := adapter.Ipv4Metric
		if adapter.Ipv6Metric < metric || metric == 0 {
			metric = adapter.Ipv6Metric
		}
		candidates = append(candidates, physicalAdapterCandidate{
			id: id, active: active, ifType: adapter.IfType,
			ipv4Index: adapter.IfIndex, ipv6Index: adapter.Ipv6IfIndex,
			metric: metric, speed: max(adapter.TransmitLinkSpeed, adapter.ReceiveLinkSpeed),
		})
	}
	return orderPhysicalAdapterCandidates(candidates), nil
}

func orderPhysicalAdapterCandidates(candidates []physicalAdapterCandidate) []physicalAdapterCandidate {
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].active != candidates[right].active {
			return candidates[left].active
		}
		if candidates[left].metric != candidates[right].metric {
			return candidates[left].metric < candidates[right].metric
		}
		leftScore, rightScore := physicalInterfaceScore(candidates[left].ifType), physicalInterfaceScore(candidates[right].ifType)
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		return candidates[left].speed > candidates[right].speed
	})
	if len(candidates) > maxPhysicalAdapters {
		candidates = candidates[:maxPhysicalAdapters]
	}
	return candidates
}

func isPhysicalInterfaceType(value uint32) bool {
	return physicalInterfaceScore(value) > 0
}

func physicalInterfaceScore(value uint32) int {
	switch value {
	case windows.IF_TYPE_ETHERNET_CSMACD, ifTypeFastEthernetFX, ifTypeFastEthernetT, ifTypeGigabitEthernet:
		return 40
	case windows.IF_TYPE_IEEE80211:
		return 30
	case ifTypeWWANPP, ifTypeWWANPP2:
		return 20
	default:
		return 0
	}
}

func isVPNLikeAdapter(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{
		"vpn", "tunnel", "stormshield", "openvpn", "wireguard", "nordlynx", "wintun", "tap",
		"anyconnect", "fortinet", "globalprotect", "palo alto", "check point", "checkpoint",
		"sonicwall", "juniper", "tailscale", "zerotier", "hamachi", "zscaler", "pulse secure",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
