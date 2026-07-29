using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// A stable Windows adapter identity plus the current per-family interface indexes.
/// The ID survives interface-index changes caused by reconnects or network transitions.
/// </summary>
public sealed record WindowsPhysicalNetworkAdapter(
    string Id,
    string Name,
    bool IsActive,
    int? Ipv4InterfaceIndex,
    int? Ipv6InterfaceIndex);

/// <summary>
/// Physical adapters eligible for the outer VPN transport. The ordered list includes
/// currently-disconnected physical adapters so a long-lived sidecar can recover when the
/// machine switches between Ethernet, Wi-Fi, or mobile data.
/// </summary>
public sealed record WindowsPhysicalNetworkPath(
    IReadOnlyList<WindowsPhysicalNetworkAdapter> Adapters)
{
    public bool HasAnyInterface => Adapters.Any(adapter =>
        adapter.IsActive
        && !string.IsNullOrWhiteSpace(adapter.Id)
        && (adapter.Ipv4InterfaceIndex is > 0 || adapter.Ipv6InterfaceIndex is > 0));

    public IReadOnlyList<string> AdapterIds => Adapters
        .Select(adapter => adapter.Id)
        .Where(id => !string.IsNullOrWhiteSpace(id))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}

public interface IWindowsPhysicalNetworkPathService
{
    Task<WindowsPhysicalNetworkPath> GetBestPathAsync(
        IReadOnlyCollection<string> destinationHosts,
        CancellationToken cancellationToken);

    ValueTask<Stream> ConnectTcpAsync(
        DnsEndPoint endpoint,
        CancellationToken cancellationToken);
}

/// <summary>
/// Selects non-VPN Windows uplinks without changing global routes. DNS prefers those
/// uplinks and falls back to the system resolver when a native VPN blocks physical DNS;
/// TCP sockets are always constrained to a physical uplink. Adapter IDs, rather than
/// indexes, cross long-lived boundaries; the current index is resolved again immediately
/// before every socket connect.
/// </summary>
public sealed class WindowsPhysicalNetworkPathService : IWindowsPhysicalNetworkPathService
{
    private const int MaxAdapters = 8;
    private const int MaxConnectCandidates = 24;
    private static readonly TimeSpan ConnectStagger = TimeSpan.FromMilliseconds(250);

    private readonly IWindowsNetworkAdapterSource _adapterSource;
    private readonly IPhysicalSocketConnector _socketConnector;

    public WindowsPhysicalNetworkPathService()
        : this(new WindowsNetworkAdapterSource(), new PhysicalSocketConnector())
    {
    }

    internal WindowsPhysicalNetworkPathService(
        IWindowsNetworkAdapterSource adapterSource,
        IPhysicalSocketConnector? socketConnector = null)
    {
        _adapterSource = adapterSource;
        _socketConnector = socketConnector ?? new PhysicalSocketConnector();
    }

    public Task<WindowsPhysicalNetworkPath> GetBestPathAsync(
        IReadOnlyCollection<string> destinationHosts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destinationHosts);
        cancellationToken.ThrowIfCancellationRequested();

        // Destination DNS is deliberately not resolved during preflight: doing so through the
        // system resolver would reintroduce the VPN capture this service exists to avoid, while
        // resolving it here through every adapter would duplicate the real connect work.
        var adapters = OrderAdapters(_adapterSource.GetAdapters()
                .Where(adapter => !IsVpnLikeAdapter(adapter)
                    && HasUsableInterfaceIndex(adapter)))
            .Take(MaxAdapters)
            .Select(adapter => new WindowsPhysicalNetworkAdapter(
                adapter.Id,
                adapter.Name,
                adapter.Status == OperationalStatus.Up,
                adapter.Ipv4InterfaceIndex,
                adapter.Ipv6InterfaceIndex))
            .ToArray();
        return Task.FromResult(new WindowsPhysicalNetworkPath(adapters));
    }

    public async ValueTask<Stream> ConnectTcpAsync(
        DnsEndPoint endpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (endpoint.Port is <= 0 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(endpoint), "The endpoint port must be between 1 and 65535.");

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var candidates = await ResolveConnectCandidatesAsync(endpoint.Host, cancellationToken)
                .ConfigureAwait(false);
            if (candidates.Count == 0)
            {
                throw new HttpRequestException(
                    $"No address for '{endpoint.Host}' is reachable through an active physical network interface.");
            }

            try
            {
                return await RaceConnectCandidatesAsync(candidates, endpoint.Port, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (HttpRequestException ex) when (
                attempt == 0 && ContainsInterfaceChangedException(ex))
            {
                // The stable adapter survived but Windows assigned it a new family index after
                // DNS completed. Repeat DNS on the new index instead of using a split-DNS answer
                // obtained from the previous interface incarnation.
            }
        }

        throw new UnreachableException();
    }

    private async Task<IReadOnlyList<PhysicalConnectCandidate>> ResolveConnectCandidatesAsync(
        string host,
        CancellationToken cancellationToken)
    {
        var adapters = OrderAdapters(_adapterSource.GetAdapters()
                .Where(IsActiveNonVpnCandidate))
            .Take(MaxAdapters)
            .ToArray();
        if (adapters.Length == 0)
            return Array.Empty<PhysicalConnectCandidate>();

        if (IPAddress.TryParse(host, out var literal))
        {
            return OrderConnectCandidates(adapters
                .Where(adapter => adapter.GetInterfaceIndex(literal.AddressFamily) is > 0)
                .Select(adapter => NewConnectCandidate(adapter, literal)));
        }

        // Query every eligible physical interface with bounded fan-out. Different uplinks can
        // legitimately return different answers (split DNS), so retaining the adapter/address
        // pair is essential for failover on multihomed machines.
        using var gate = new SemaphoreSlim(Math.Min(4, adapters.Length));
        var resolutions = adapters.Select(async adapter =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (adapter.Ipv4InterfaceIndex is not > 0
                    && adapter.Ipv6InterfaceIndex is not > 0)
                {
                    return Array.Empty<PhysicalConnectCandidate>();
                }

                var addresses = await _adapterSource.ResolveHostAsync(
                        host,
                        adapter.Ipv4InterfaceIndex,
                        adapter.Ipv6InterfaceIndex,
                        cancellationToken)
                    .ConfigureAwait(false);
                return addresses
                    .Where(address => adapter.GetInterfaceIndex(address.AddressFamily) is > 0)
                    .Distinct()
                    .Select(address => NewConnectCandidate(adapter, address))
                    .ToArray();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (IsExpectedResolutionFailure(ex))
            {
                return Array.Empty<PhysicalConnectCandidate>();
            }
            finally
            {
                gate.Release();
            }
        });

        var resolved = await Task.WhenAll(resolutions).ConfigureAwait(false);
        var physicalCandidates = resolved.SelectMany(result => result).ToArray();
        var unresolvedAdapters = adapters
            .Where((_, index) => resolved[index].Length == 0)
            .ToArray();
        if (unresolvedAdapters.Length == 0)
            return OrderConnectCandidates(physicalCandidates);

        // Some native clients enforce DNS-only leak protection: direct traffic on the
        // physical uplink remains usable, but queries to that uplink's DNS servers are
        // blocked. Resolve through the system path in that case, then still bind every
        // resulting TCP attempt to a physical adapter. This preserves split-DNS answers
        // when physical DNS works and avoids making DNS policy a tunnel-establishment
        // dependency when it does not.
        IReadOnlyList<IPAddress> systemAddresses;
        try
        {
            systemAddresses = await _adapterSource.ResolveHostAsync(
                    host, null, null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (IsExpectedResolutionFailure(ex))
        {
            return OrderConnectCandidates(physicalCandidates);
        }

        return OrderConnectCandidates(
            physicalCandidates.Concat(
                from adapter in unresolvedAdapters
                from address in systemAddresses.Distinct()
                where adapter.GetInterfaceIndex(address.AddressFamily) is > 0
                select NewConnectCandidate(adapter, address)));
    }

    private PhysicalConnectCandidate NewConnectCandidate(
        WindowsNetworkAdapter adapter,
        IPAddress address)
    {
        var interfaceIndex = adapter.GetInterfaceIndex(address.AddressFamily)
            ?? throw new InvalidOperationException("The adapter has no index for the resolved address family.");
        return new PhysicalConnectCandidate(
            adapter.Id,
            address,
            interfaceIndex,
            _adapterSource.GetBestRouteInterfaceIndex(address) == interfaceIndex,
            adapter.GetMetric(address.AddressFamily),
            PhysicalAdapterScore(adapter.InterfaceType),
            adapter.Speed);
    }

    private static List<PhysicalConnectCandidate> OrderConnectCandidates(
        IEnumerable<PhysicalConnectCandidate> candidates)
    {
        var ordered = candidates
            .DistinctBy(candidate => (candidate.AdapterId, candidate.Address))
            .OrderByDescending(candidate => candidate.IsSystemBestRoute)
            .ThenBy(candidate => candidate.Metric)
            .ThenByDescending(candidate => candidate.AdapterScore)
            .ThenByDescending(candidate => candidate.Speed)
            .Take(MaxConnectCandidates)
            .ToArray();

        // Prefer IPv4 for Stormshield compatibility, but alternate families so the 250 ms
        // stagger provides RFC 8305-style fallback instead of waiting for a blackholed family.
        var ipv4 = new Queue<PhysicalConnectCandidate>(
            ordered.Where(candidate => candidate.Address.AddressFamily == AddressFamily.InterNetwork));
        var ipv6 = new Queue<PhysicalConnectCandidate>(
            ordered.Where(candidate => candidate.Address.AddressFamily == AddressFamily.InterNetworkV6));
        var interleaved = new List<PhysicalConnectCandidate>(ordered.Length);
        while (ipv4.Count > 0 || ipv6.Count > 0)
        {
            if (ipv4.Count > 0) interleaved.Add(ipv4.Dequeue());
            if (ipv6.Count > 0) interleaved.Add(ipv6.Dequeue());
        }
        return interleaved;
    }

    private async Task<Stream> RaceConnectCandidatesAsync(
        IReadOnlyList<PhysicalConnectCandidate> candidates,
        int port,
        CancellationToken cancellationToken)
    {
        using var winnerCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var attempts = candidates
            .Select((candidate, index) => ConnectCandidateAfterDelayAsync(
                candidate, port, ConnectStagger * index, winnerCancellation.Token))
            .ToList();
        var failures = new List<Exception>();

        while (attempts.Count > 0)
        {
            var completed = await Task.WhenAny(attempts).ConfigureAwait(false);
            attempts.Remove(completed);
            try
            {
                var stream = await completed.ConfigureAwait(false);
                winnerCancellation.Cancel();
                await ObserveCancelledAttemptsAsync(attempts).ConfigureAwait(false);
                return stream;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                winnerCancellation.Cancel();
                await ObserveCancelledAttemptsAsync(attempts).ConfigureAwait(false);
                throw;
            }
            catch (Exception ex)
            {
                failures.Add(ex);
            }
        }

        throw new HttpRequestException(
            "Could not connect through any active physical network interface.",
            failures.Count == 1 ? failures[0] : new AggregateException(failures));
    }

    private async Task<Stream> ConnectCandidateAfterDelayAsync(
        PhysicalConnectCandidate candidate,
        int port,
        TimeSpan delay,
        CancellationToken cancellationToken)
    {
        if (delay > TimeSpan.Zero)
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);

        // Interface indexes are not stable. Resolve the adapter ID again at the last
        // possible moment so disable/enable and network transitions do not leave stale state.
        var currentAdapter = _adapterSource.GetAdapters().FirstOrDefault(adapter =>
            adapter.Status == OperationalStatus.Up
            && adapter.Id.Equals(candidate.AdapterId, StringComparison.OrdinalIgnoreCase)
            && !IsVpnLikeAdapter(adapter));
        var currentIndex = currentAdapter?.GetInterfaceIndex(candidate.Address.AddressFamily);
        if (currentIndex is not > 0)
            throw new NetworkInformationException();
        if (currentIndex.Value != candidate.InterfaceIndex)
            throw new PhysicalInterfaceChangedException();

        return await _socketConnector.ConnectAsync(
                candidate.Address, port, currentIndex.Value, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task ObserveCancelledAttemptsAsync(
        IEnumerable<Task<Stream>> attempts)
    {
        foreach (var attempt in attempts)
        {
            try
            {
                var stream = await attempt.ConfigureAwait(false);
                await stream.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Losing attempts are expected to be cancelled or to have already failed.
            }
        }
    }

    private static bool ContainsInterfaceChangedException(Exception exception) =>
        exception is PhysicalInterfaceChangedException
        || (exception is AggregateException aggregate
            && aggregate.Flatten().InnerExceptions.Any(ContainsInterfaceChangedException))
        || (exception.InnerException is { } inner
            && ContainsInterfaceChangedException(inner));

    private static bool IsExpectedResolutionFailure(Exception exception) =>
        exception is InvalidOperationException
            or NetworkInformationException
            or SocketException
        || (exception is AggregateException aggregate
            && aggregate.Flatten().InnerExceptions.All(IsExpectedResolutionFailure));

    private static IEnumerable<WindowsNetworkAdapter> OrderAdapters(
        IEnumerable<WindowsNetworkAdapter> adapters) =>
        adapters
            .Select(adapter => (Adapter: adapter, Score: PhysicalAdapterScore(adapter.InterfaceType)))
            .Where(item => item.Score > 0)
            .OrderByDescending(item => item.Adapter.Status == OperationalStatus.Up)
            .ThenBy(item => Math.Min(item.Adapter.Ipv4Metric, item.Adapter.Ipv6Metric))
            .ThenByDescending(item => item.Score)
            .ThenByDescending(item => item.Adapter.Speed)
            .Select(item => item.Adapter);

    private static bool IsActiveNonVpnCandidate(WindowsNetworkAdapter adapter) =>
        adapter.Status == OperationalStatus.Up
        && HasUsableInterfaceIndex(adapter)
        && !IsVpnLikeAdapter(adapter);

    private static bool HasUsableInterfaceIndex(WindowsNetworkAdapter adapter) =>
        adapter.Ipv4InterfaceIndex is > 0 || adapter.Ipv6InterfaceIndex is > 0;

    internal static bool IsVpnLikeAdapter(WindowsNetworkAdapter adapter)
    {
        if (adapter.InterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel)
            return true;

        var text = (adapter.Name + " " + adapter.Description).ToLowerInvariant();
        return text.Contains("vpn", StringComparison.Ordinal)
            || text.Contains("tunnel", StringComparison.Ordinal)
            || text.Contains("stormshield", StringComparison.Ordinal)
            || text.Contains("openvpn", StringComparison.Ordinal)
            || text.Contains("wireguard", StringComparison.Ordinal)
            || text.Contains("nordlynx", StringComparison.Ordinal)
            || text.Contains("wintun", StringComparison.Ordinal)
            || text.Contains("tap", StringComparison.Ordinal)
            || text.Contains("anyconnect", StringComparison.Ordinal)
            || text.Contains("fortinet", StringComparison.Ordinal)
            || text.Contains("globalprotect", StringComparison.Ordinal)
            || text.Contains("palo alto", StringComparison.Ordinal)
            || text.Contains("check point", StringComparison.Ordinal)
            || text.Contains("checkpoint", StringComparison.Ordinal)
            || text.Contains("sonicwall", StringComparison.Ordinal)
            || text.Contains("juniper", StringComparison.Ordinal)
            || text.Contains("tailscale", StringComparison.Ordinal)
            || text.Contains("zerotier", StringComparison.Ordinal)
            || text.Contains("hamachi", StringComparison.Ordinal)
            || text.Contains("zscaler", StringComparison.Ordinal)
            || text.Contains("pulse secure", StringComparison.Ordinal);
    }

    private static int PhysicalAdapterScore(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.Ethernet3Megabit
            or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.GigabitEthernet => 40,
        NetworkInterfaceType.Wireless80211 => 30,
        NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => 20,
        _ => 0,
    };

    internal static void BindToPhysicalInterface(Socket socket, int interfaceIndex)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(interfaceIndex);
        const SocketOptionName unicastInterface = (SocketOptionName)31;

        if (socket.AddressFamily == AddressFamily.InterNetwork)
        {
            socket.SetSocketOption(
                SocketOptionLevel.IP,
                unicastInterface,
                IPAddress.HostToNetworkOrder(interfaceIndex));
            return;
        }
        if (socket.AddressFamily == AddressFamily.InterNetworkV6)
        {
            socket.SetSocketOption(SocketOptionLevel.IPv6, unicastInterface, interfaceIndex);
            return;
        }
        throw new NotSupportedException(
            $"Address family '{socket.AddressFamily}' cannot be bound to a physical IP interface.");
    }
}

internal sealed record PhysicalConnectCandidate(
    string AdapterId,
    IPAddress Address,
    int InterfaceIndex,
    bool IsSystemBestRoute,
    int Metric,
    int AdapterScore,
    long Speed);

internal sealed class PhysicalInterfaceChangedException : IOException
{
}

internal interface IPhysicalSocketConnector
{
    Task<Stream> ConnectAsync(
        IPAddress address,
        int port,
        int interfaceIndex,
        CancellationToken cancellationToken);
}

internal sealed class PhysicalSocketConnector : IPhysicalSocketConnector
{
    public async Task<Stream> ConnectAsync(
        IPAddress address,
        int port,
        int interfaceIndex,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        try
        {
            WindowsPhysicalNetworkPathService.BindToPhysicalInterface(socket, interfaceIndex);
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

internal interface IWindowsNetworkAdapterSource
{
    IReadOnlyList<WindowsNetworkAdapter> GetAdapters();
    Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        int? ipv4InterfaceIndex,
        int? ipv6InterfaceIndex,
        CancellationToken cancellationToken);
    int? GetBestRouteInterfaceIndex(IPAddress destination);
}

internal sealed record WindowsNetworkAdapter(
    string Id,
    string Name,
    string Description,
    NetworkInterfaceType InterfaceType,
    OperationalStatus Status,
    long Speed,
    int? Ipv4InterfaceIndex,
    int? Ipv6InterfaceIndex,
    int Ipv4Metric,
    int Ipv6Metric)
{
    public int? GetInterfaceIndex(AddressFamily family) => family switch
    {
        AddressFamily.InterNetwork => Ipv4InterfaceIndex,
        AddressFamily.InterNetworkV6 => Ipv6InterfaceIndex,
        _ => null,
    };

    public int GetMetric(AddressFamily family) => family switch
    {
        AddressFamily.InterNetwork => Ipv4Metric,
        AddressFamily.InterNetworkV6 => Ipv6Metric,
        _ => int.MaxValue,
    };
}

internal sealed class WindowsNetworkAdapterSource : IWindowsNetworkAdapterSource
{
    private static readonly SemaphoreSlim NativeDnsGate = new(8, 8);
    private const uint ErrorBufferOverflow = 111;
    private const ushort DnsTypeA = 1;
    private const ushort DnsTypeAaaa = 28;
    private const ulong DnsQueryBypassCache = 0x00000008;

    public IReadOnlyList<WindowsNetworkAdapter> GetAdapters()
    {
        var metrics = GetInterfaceMetrics();
        var adapters = new List<WindowsNetworkAdapter>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var properties = networkInterface.GetIPProperties();
                var ipv4Index = properties.GetIPv4Properties()?.Index;
                var ipv6Index = properties.GetIPv6Properties()?.Index;
                adapters.Add(new WindowsNetworkAdapter(
                    networkInterface.Id,
                    networkInterface.Name,
                    networkInterface.Description,
                    networkInterface.NetworkInterfaceType,
                    networkInterface.OperationalStatus,
                    networkInterface.Speed,
                    ipv4Index,
                    ipv6Index,
                    ipv4Index is { } v4 && metrics.Ipv4.TryGetValue(v4, out var ipv4Metric)
                        ? ipv4Metric
                        : int.MaxValue,
                    ipv6Index is { } v6 && metrics.Ipv6.TryGetValue(v6, out var ipv6Metric)
                        ? ipv6Metric
                        : int.MaxValue));
            }
            catch (NetworkInformationException)
            {
                // An adapter may disappear while Windows is enumerating it.
            }
        }
        return adapters;
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        int? ipv4InterfaceIndex,
        int? ipv6InterfaceIndex,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var literal))
            return new[] { literal };
        if (ipv4InterfaceIndex is not > 0 && ipv6InterfaceIndex is not > 0)
            return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);

        // DnsQueryEx is synchronous when no completion callback is supplied. Isolate it from
        // the caller and let cancellation stop waiting immediately. The process-wide gate also
        // prevents repeated cancelled connects from accumulating unbounded native DNS workers.
        await NativeDnsGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task<IReadOnlyList<IPAddress>> query;
        try
        {
            query = Task.Run<IReadOnlyList<IPAddress>>(() =>
            {
                try
                {
                    return ResolveHostOnInterface(
                        host, ipv4InterfaceIndex, ipv6InterfaceIndex);
                }
                finally
                {
                    NativeDnsGate.Release();
                }
            });
        }
        catch
        {
            NativeDnsGate.Release();
            throw;
        }
        return await query.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public int? GetBestRouteInterfaceIndex(IPAddress destination)
    {
        if (destination.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            return null;

        var socketAddress = new IPEndPoint(destination, 0).Serialize();
        var buffer = Marshal.AllocHGlobal(socketAddress.Size);
        try
        {
            for (var i = 0; i < socketAddress.Size; i++)
                Marshal.WriteByte(buffer, i, socketAddress[i]);

            return GetBestInterfaceEx(buffer, out var interfaceIndex) == 0
                && interfaceIndex is > 0 and <= int.MaxValue
                    ? unchecked((int)interfaceIndex)
                    : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IPAddress[] ResolveHostOnInterface(
        string host,
        int? ipv4InterfaceIndex,
        int? ipv6InterfaceIndex)
    {
        var addresses = new List<IPAddress>();
        var failures = new List<Exception>();
        if (ipv4InterfaceIndex is > 0)
        {
            try
            {
                QueryDns(host, ipv4InterfaceIndex.Value, DnsTypeA, addresses);
            }
            catch (InvalidOperationException ex)
            {
                failures.Add(ex);
            }
        }
        if (ipv6InterfaceIndex is > 0)
        {
            try
            {
                QueryDns(host, ipv6InterfaceIndex.Value, DnsTypeAaaa, addresses);
            }
            catch (InvalidOperationException ex)
            {
                failures.Add(ex);
            }
        }
        if (addresses.Count == 0 && failures.Count > 0)
            throw new AggregateException(failures);
        return addresses.Distinct().ToArray();
    }

    private static void QueryDns(
        string host,
        int interfaceIndex,
        ushort recordType,
        List<IPAddress> addresses)
    {
        var queryName = Marshal.StringToHGlobalUni(host);
        try
        {
            var request = new DnsQueryRequest
            {
                Version = 1,
                QueryName = queryName,
                QueryType = recordType,
                QueryOptions = DnsQueryBypassCache,
                InterfaceIndex = unchecked((uint)interfaceIndex),
            };
            var result = new DnsQueryResult { Version = 1 };
            var status = DnsQueryEx(ref request, ref result, IntPtr.Zero);
            try
            {
                if (status != 0)
                    throw new InvalidOperationException(
                        $"DnsQueryEx failed with status {status} for interface {interfaceIndex}.");
                if (result.QueryStatus != 0)
                    throw new InvalidOperationException(
                        $"DnsQueryEx completed with status {result.QueryStatus} for interface {interfaceIndex}.");

                for (var record = result.QueryRecords; record != IntPtr.Zero;)
                {
                    var header = Marshal.PtrToStructure<DnsRecordHeader>(record);
                    if (header.Type == recordType)
                    {
                        var length = recordType == DnsTypeA ? 4 : 16;
                        var bytes = new byte[length];
                        Marshal.Copy(IntPtr.Add(record, DnsRecordHeader.DataOffset), bytes, 0, length);
                        addresses.Add(new IPAddress(bytes));
                    }
                    record = header.Next;
                }
            }
            finally
            {
                if (result.QueryRecords != IntPtr.Zero)
                    DnsRecordListFree(result.QueryRecords, DnsFreeType.RecordList);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(queryName);
        }
    }

    private static InterfaceMetrics GetInterfaceMetrics()
    {
        uint bufferSize = 0;
        if (GetAdaptersAddresses(0, 0, IntPtr.Zero, IntPtr.Zero, ref bufferSize) != ErrorBufferOverflow
            || bufferSize == 0)
        {
            return new InterfaceMetrics(
                new Dictionary<int, int>(),
                new Dictionary<int, int>());
        }

        var ipv4 = new Dictionary<int, int>();
        var ipv6 = new Dictionary<int, int>();
        var buffer = Marshal.AllocHGlobal(checked((int)bufferSize));
        try
        {
            if (GetAdaptersAddresses(0, 0, IntPtr.Zero, buffer, ref bufferSize) != 0)
                return new InterfaceMetrics(ipv4, ipv6);

            for (var current = buffer; current != IntPtr.Zero;)
            {
                var adapter = Marshal.PtrToStructure<IpAdapterAddresses>(current);
                if (adapter.IfIndex is > 0 and <= int.MaxValue)
                    ipv4[unchecked((int)adapter.IfIndex)] = ToMetric(adapter.Ipv4Metric);
                if (adapter.Ipv6IfIndex is > 0 and <= int.MaxValue)
                    ipv6[unchecked((int)adapter.Ipv6IfIndex)] = ToMetric(adapter.Ipv6Metric);
                current = adapter.Next;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return new InterfaceMetrics(ipv4, ipv6);
    }

    private static int ToMetric(uint metric) =>
        metric <= int.MaxValue ? unchecked((int)metric) : int.MaxValue;

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    private static extern int DnsQueryEx(
        ref DnsQueryRequest queryRequest,
        ref DnsQueryResult queryResults,
        IntPtr cancelHandle);

    [DllImport("dnsapi.dll")]
    private static extern void DnsRecordListFree(IntPtr recordList, DnsFreeType freeType);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetAdaptersAddresses(
        uint family,
        uint flags,
        IntPtr reserved,
        IntPtr adapterAddresses,
        ref uint sizePointer);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestInterfaceEx(IntPtr destinationAddress, out uint bestInterfaceIndex);

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsQueryRequest
    {
        public uint Version;
        public IntPtr QueryName;
        public ushort QueryType;
        public ulong QueryOptions;
        public IntPtr DnsServerList;
        public uint InterfaceIndex;
        public IntPtr QueryCompletionCallback;
        public IntPtr QueryContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsQueryResult
    {
        public uint Version;
        public int QueryStatus;
        public ulong QueryOptions;
        public IntPtr QueryRecords;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsRecordHeader
    {
        public static readonly int DataOffset =
            Marshal.OffsetOf<DnsRecordHeader>(nameof(Data)).ToInt32();

        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
        public uint Ttl;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Data;
    }

    private enum DnsFreeType
    {
        Flat = 0,
        RecordList = 1,
        ParsedMessageFields = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IpAdapterAddresses
    {
        public uint Length;
        public uint IfIndex;
        public IntPtr Next;
        public IntPtr AdapterName;
        public IntPtr FirstUnicastAddress;
        public IntPtr FirstAnycastAddress;
        public IntPtr FirstMulticastAddress;
        public IntPtr FirstDnsServerAddress;
        public IntPtr DnsSuffix;
        public IntPtr Description;
        public IntPtr FriendlyName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysicalAddress;
        public uint PhysicalAddressLength;
        public uint Flags;
        public uint Mtu;
        public uint IfType;
        public uint OperStatus;
        public uint Ipv6IfIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public uint[] ZoneIndices;
        public IntPtr FirstPrefix;
        public ulong TransmitLinkSpeed;
        public ulong ReceiveLinkSpeed;
        public IntPtr FirstWinsServerAddress;
        public IntPtr FirstGatewayAddress;
        public uint Ipv4Metric;
        public uint Ipv6Metric;
    }

    private sealed record InterfaceMetrics(
        IReadOnlyDictionary<int, int> Ipv4,
        IReadOnlyDictionary<int, int> Ipv6);
}
