using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling;

public interface IWindowsTemporaryHostRouteService
{
    Task<WindowsHostRouteLease> PrepareGatewayBypassAsync(
        string configName,
        IReadOnlyCollection<string> hosts,
        bool enableBypass,
        CancellationToken cancellationToken);
}

public sealed class WindowsHostRouteLease : IAsyncDisposable
{
    private readonly IReadOnlyList<IAsyncDisposable> _routeReleases;
    private int _disposedFlag;

    internal WindowsHostRouteLease(
        IReadOnlyList<WindowsHostRouteDiagnostic> diagnostics,
        IReadOnlyList<IAsyncDisposable> routeReleases)
    {
        Diagnostics = diagnostics;
        _routeReleases = routeReleases;
    }

    public IReadOnlyList<WindowsHostRouteDiagnostic> Diagnostics { get; }

    public bool HasNativeVpnConflict => Diagnostics.Any(d => d.NativeVpnConflict);
    public bool HasInstalledBypassRoutes => Diagnostics.Any(d => d.BypassRouteInstalled);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        for (var i = _routeReleases.Count - 1; i >= 0; i--)
        {
            await _routeReleases[i].DisposeAsync().ConfigureAwait(false);
        }
    }
}

public sealed record WindowsHostRouteDiagnostic(
    string Host,
    IPAddress? Address,
    bool NativeVpnConflict,
    bool BypassRouteInstalled,
    string Message);

public sealed class WindowsTemporaryHostRouteService : IWindowsTemporaryHostRouteService, IDisposable
{
    internal static readonly IPAddress HostRouteMask = IPAddress.Parse("255.255.255.255");

    private readonly IWindowsRouteSystem _system;
    private readonly ILogger<WindowsTemporaryHostRouteService> _logger;
    private readonly SemaphoreSlim _routeGate = new(1, 1);
    private readonly Dictionary<HostRouteKey, RefCountedRoute> _activeRoutes = new();

    public WindowsTemporaryHostRouteService(ILogger<WindowsTemporaryHostRouteService> logger)
        : this(new WindowsRouteSystem(), logger)
    {
    }

    internal WindowsTemporaryHostRouteService(
        IWindowsRouteSystem system,
        ILogger<WindowsTemporaryHostRouteService> logger)
    {
        _system = system;
        _logger = logger;
    }

    public void Dispose() => _routeGate.Dispose();

    public async Task<WindowsHostRouteLease> PrepareGatewayBypassAsync(
        string configName,
        IReadOnlyCollection<string> hosts,
        bool enableBypass,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hosts);

        var diagnostics = new List<WindowsHostRouteDiagnostic>();
        var releases = new List<IAsyncDisposable>();
        var distinctHosts = hosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        try
        {
            foreach (var host in distinctHosts)
            {
                var addresses = await ResolveHostAsync(host, enableBypass, cancellationToken).ConfigureAwait(false);
                if (addresses.Count == 0)
                {
                    diagnostics.Add(new WindowsHostRouteDiagnostic(
                        host,
                        Address: null,
                        NativeVpnConflict: false,
                        BypassRouteInstalled: false,
                        Message: $"Could not resolve '{host}' to an IPv4 address; the native-VPN route bypass is IPv4-only."));
                    continue;
                }

                foreach (var address in addresses)
                {
                    var release = await PrepareAddressAsync(
                        configName, host, address, enableBypass, diagnostics, cancellationToken)
                        .ConfigureAwait(false);
                    if (release is not null) releases.Add(release);
                }
            }

            return new WindowsHostRouteLease(diagnostics, releases);
        }
        catch
        {
            foreach (var release in releases)
            {
                try { await release.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogDebug(ex, "Failed to roll back a temporary host route after setup failed."); }
            }
            throw;
        }
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        bool enableBypass,
        CancellationToken cancellationToken)
    {
        try
        {
            return (await _system.ResolveHostAsync(host, cancellationToken).ConfigureAwait(false))
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Distinct()
                .ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (enableBypass)
            {
                throw new InvalidOperationException(
                    $"Native-VPN route bypass is enabled, but Wormhole could not resolve Stormshield gateway '{host}' "
                    + "to an IPv4 address before installing a host route.",
                    ex);
            }
            return Array.Empty<IPAddress>();
        }
    }

    private async Task<IAsyncDisposable?> PrepareAddressAsync(
        string configName,
        string host,
        IPAddress address,
        bool enableBypass,
        List<WindowsHostRouteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        if (enableBypass)
        {
            var activeRelease = await TryReferenceActiveRouteAsync(address, cancellationToken).ConfigureAwait(false);
            if (activeRelease is not null)
            {
                diagnostics.Add(new WindowsHostRouteDiagnostic(
                    host,
                    address,
                    NativeVpnConflict: true,
                    BypassRouteInstalled: true,
                    Message: $"Reusing an existing temporary host route for {host} ({address})."));
                return activeRelease;
            }
        }

        var route = _system.GetBestRoute(address);
        if (route is null)
        {
            diagnostics.Add(new WindowsHostRouteDiagnostic(
                host,
                address,
                NativeVpnConflict: false,
                BypassRouteInstalled: false,
                Message: $"Windows did not return a best route for {address}."));
            return null;
        }

        var adapters = _system.GetAdapters();
        var routedAdapter = adapters.FirstOrDefault(a => a.InterfaceIndex == route.InterfaceIndex);
        var routedName = DescribeAdapter(route.InterfaceIndex, routedAdapter);
        var routeUsesVpn = IsVpnLikeAdapter(routedAdapter);
        if (!routeUsesVpn)
        {
            if (enableBypass)
            {
                var existingRelease = await TryReferenceActiveRouteAsync(address, cancellationToken).ConfigureAwait(false);
                if (existingRelease is not null)
                {
                    diagnostics.Add(new WindowsHostRouteDiagnostic(
                        host,
                        address,
                        NativeVpnConflict: true,
                        BypassRouteInstalled: true,
                        Message: $"Reusing an existing temporary host route for {host} ({address}) through {routedName}."));
                    return existingRelease;
                }
            }

            diagnostics.Add(new WindowsHostRouteDiagnostic(
                host,
                address,
                NativeVpnConflict: false,
                BypassRouteInstalled: false,
                Message: $"Windows routes {host} ({address}) through {routedName}; no native-VPN bypass is needed."));
            return null;
        }

        if (!enableBypass)
        {
            diagnostics.Add(new WindowsHostRouteDiagnostic(
                host,
                address,
                NativeVpnConflict: true,
                BypassRouteInstalled: false,
                Message: $"Windows currently routes {host} ({address}) through VPN-like adapter {routedName}."));
            return null;
        }

        if (!_system.IsAdministrator)
        {
            throw new InvalidOperationException(
                "The Stormshield native-VPN route bypass requires Wormhole to be running as Administrator, "
                + $"because Windows currently routes {host} ({address}) through VPN-like adapter {routedName}.");
        }

        if (route.PrefixLength >= 32)
        {
            throw new InvalidOperationException(
                $"Windows already has a host route for Stormshield gateway {host} ({address}) through VPN-like adapter "
                + $"{routedName}. Wormhole will not override an equal host route; disconnect the native VPN or remove "
                + "that route before connecting this tunnel.");
        }

        var physical = SelectBestPhysicalGateway(adapters);
        if (physical is null)
        {
            throw new InvalidOperationException(
                $"Windows routes Stormshield gateway {host} ({address}) through VPN-like adapter {routedName}, "
                + "but Wormhole could not find an active physical adapter with an IPv4 default gateway to bypass it.");
        }

        var gateway = physical.IPv4Gateways[0];
        var key = new HostRouteKey(address, gateway, physical.InterfaceIndex);
        var release = await AddOrReferenceRouteAsync(key, cancellationToken).ConfigureAwait(false);
        diagnostics.Add(new WindowsHostRouteDiagnostic(
            host,
            address,
            NativeVpnConflict: true,
            BypassRouteInstalled: true,
            Message: $"Installed a temporary host route for {host} ({address}) via {gateway} on {DescribeAdapter(physical.InterfaceIndex, physical)}."));
        _logger.LogInformation(
            "Stormshield '{Name}': temporary host route installed for {Host} ({Address}) via {Gateway} on interface {InterfaceIndex}.",
            configName, host, address, gateway, physical.InterfaceIndex);
        return release;
    }

    private async Task<IAsyncDisposable?> TryReferenceActiveRouteAsync(
        IPAddress destination,
        CancellationToken cancellationToken)
    {
        await _routeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var active = _activeRoutes.FirstOrDefault(kvp => kvp.Key.Destination.Equals(destination));
            if (active.Value is null) return null;

            active.Value.RefCount++;
            return new RouteReference(this, active.Key);
        }
        finally
        {
            _routeGate.Release();
        }
    }

    private async Task<IAsyncDisposable> AddOrReferenceRouteAsync(HostRouteKey key, CancellationToken cancellationToken)
    {
        await _routeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_activeRoutes.TryGetValue(key, out var existing))
            {
                existing.RefCount++;
                return new RouteReference(this, key);
            }

            cancellationToken.ThrowIfCancellationRequested();
            await _system.AddHostRouteAsync(key.Destination, key.Gateway, key.InterfaceIndex, CancellationToken.None)
                .ConfigureAwait(false);
            _activeRoutes[key] = new RefCountedRoute { RefCount = 1 };
            return new RouteReference(this, key);
        }
        finally
        {
            _routeGate.Release();
        }
    }

    private async ValueTask ReleaseRouteAsync(HostRouteKey key)
    {
        await _routeGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_activeRoutes.TryGetValue(key, out var existing)) return;
            existing.RefCount--;
            if (existing.RefCount > 0) return;

            try
            {
                await _system.DeleteHostRouteAsync(key.Destination, key.Gateway, key.InterfaceIndex, CancellationToken.None)
                    .ConfigureAwait(false);
                _logger.LogInformation(
                    "Removed temporary host route for {Destination} via {Gateway} on interface {InterfaceIndex}.",
                    key.Destination, key.Gateway, key.InterfaceIndex);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to remove temporary host route for {Destination} via {Gateway} on interface {InterfaceIndex}.",
                    key.Destination, key.Gateway, key.InterfaceIndex);
            }
            finally
            {
                _activeRoutes.Remove(key);
            }
        }
        finally
        {
            _routeGate.Release();
        }
    }

    internal static WindowsRouteAdapter? SelectBestPhysicalGateway(IReadOnlyList<WindowsRouteAdapter> adapters) =>
        adapters
            .Where(IsPhysicalGatewayCandidate)
            .Select(a => (Adapter: a, Score: PhysicalAdapterScore(a.InterfaceType)))
            .Where(x => x.Score > 0)
            .OrderBy(x => x.Adapter.DefaultRouteMetric)
            .ThenByDescending(x => x.Score)
            .ThenByDescending(x => x.Adapter.Speed)
            .Select(x => x.Adapter)
            .FirstOrDefault();

    private static bool IsPhysicalGatewayCandidate(WindowsRouteAdapter adapter) =>
        adapter.Status == OperationalStatus.Up
        && adapter.IPv4Gateways.Count > 0
        && !IsVpnLikeAdapter(adapter)
        && !IsVirtualLikeAdapter(adapter);

    internal static bool IsVpnLikeAdapter(WindowsRouteAdapter? adapter)
    {
        if (adapter is null) return false;
        if (adapter.InterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel)
            return true;

        var text = (adapter.Name + " " + adapter.Description).ToLowerInvariant();
        return text.Contains("vpn", StringComparison.Ordinal)
            || text.Contains("stormshield", StringComparison.Ordinal)
            || text.Contains("openvpn", StringComparison.Ordinal)
            || text.Contains("wireguard", StringComparison.Ordinal)
            || text.Contains("wintun", StringComparison.Ordinal)
            || text.Contains("tap-windows", StringComparison.Ordinal)
            || text.Contains("tun", StringComparison.Ordinal)
            || text.Contains("anyconnect", StringComparison.Ordinal)
            || text.Contains("fortinet", StringComparison.Ordinal)
            || text.Contains("globalprotect", StringComparison.Ordinal)
            || text.Contains("check point", StringComparison.Ordinal)
            || text.Contains("sonicwall", StringComparison.Ordinal)
            || text.Contains("juniper", StringComparison.Ordinal);
    }

    private static bool IsVirtualLikeAdapter(WindowsRouteAdapter adapter)
    {
        var text = (adapter.Name + " " + adapter.Description).ToLowerInvariant();
        return text.Contains("virtual", StringComparison.Ordinal)
            || text.Contains("vethernet", StringComparison.Ordinal)
            || text.Contains("hyper-v", StringComparison.Ordinal)
            || text.Contains("vmware", StringComparison.Ordinal)
            || text.Contains("virtualbox", StringComparison.Ordinal)
            || text.Contains("docker", StringComparison.Ordinal)
            || text.Contains("wsl", StringComparison.Ordinal)
            || text.Contains("loopback", StringComparison.Ordinal);
    }

    private static int PhysicalAdapterScore(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.Ethernet3Megabit
            or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.GigabitEthernet => 30,
        NetworkInterfaceType.Wireless80211 => 20,
        NetworkInterfaceType.Unknown => 10,
        _ => 0,
    };

    private static string DescribeAdapter(int interfaceIndex, WindowsRouteAdapter? adapter) =>
        adapter is null
            ? $"interface {interfaceIndex}"
            : $"'{adapter.Name}' (interface {adapter.InterfaceIndex})";

    private sealed class RefCountedRoute
    {
        public int RefCount { get; set; }
    }

    private sealed class RouteReference : IAsyncDisposable
    {
        private readonly WindowsTemporaryHostRouteService _owner;
        private readonly HostRouteKey _key;
        private int _disposedFlag;

        public RouteReference(WindowsTemporaryHostRouteService owner, HostRouteKey key)
        {
            _owner = owner;
            _key = key;
        }

        public ValueTask DisposeAsync() =>
            Interlocked.Exchange(ref _disposedFlag, 1) == 0
                ? _owner.ReleaseRouteAsync(_key)
                : ValueTask.CompletedTask;
    }

    private sealed record HostRouteKey(IPAddress Destination, IPAddress Gateway, int InterfaceIndex);
}

internal interface IWindowsRouteSystem
{
    bool IsAdministrator { get; }
    Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, CancellationToken cancellationToken);
    WindowsBestRoute? GetBestRoute(IPAddress destination);
    IReadOnlyList<WindowsRouteAdapter> GetAdapters();
    Task AddHostRouteAsync(IPAddress destination, IPAddress gateway, int interfaceIndex, CancellationToken cancellationToken);
    Task DeleteHostRouteAsync(IPAddress destination, IPAddress gateway, int interfaceIndex, CancellationToken cancellationToken);
}

internal sealed record WindowsRouteAdapter(
    int InterfaceIndex,
    string Name,
    string Description,
    NetworkInterfaceType InterfaceType,
    OperationalStatus Status,
    long Speed,
    IReadOnlyList<IPAddress> IPv4Gateways,
    int DefaultRouteMetric);

internal sealed record WindowsBestRoute(
    IPAddress Destination,
    IPAddress Netmask,
    IPAddress NextHop,
    int InterfaceIndex,
    int Metric)
{
    public int PrefixLength => CountPrefixBits(Netmask);

    private static int CountPrefixBits(IPAddress mask)
    {
        var count = 0;
        foreach (var b in mask.GetAddressBytes())
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                if ((b & (1 << bit)) == 0) return count;
                count++;
            }
        }
        return count;
    }
}

internal sealed class WindowsRouteSystem : IWindowsRouteSystem
{
    private const uint ErrorInsufficientBuffer = 122;

    public bool IsAdministrator
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var literal))
            return new[] { literal };

        return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
    }

    public WindowsBestRoute? GetBestRoute(IPAddress destination)
    {
        if (destination.AddressFamily != AddressFamily.InterNetwork)
            return null;

        var rc = GetBestRoute(ToRouteAddress(destination), 0, out var row);
        if (rc != 0)
            return null;

        return new WindowsBestRoute(
            FromRouteAddress(row.dwForwardDest),
            FromRouteAddress(row.dwForwardMask),
            FromRouteAddress(row.dwForwardNextHop),
            unchecked((int)row.dwForwardIfIndex),
            unchecked((int)row.dwForwardMetric1));
    }

    public IReadOnlyList<WindowsRouteAdapter> GetAdapters()
    {
        var defaultRouteMetrics = GetDefaultRouteMetrics();
        var adapters = new List<WindowsRouteAdapter>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            IPInterfaceProperties props;
            IPv4InterfaceProperties? ipv4;
            try
            {
                props = ni.GetIPProperties();
                ipv4 = props.GetIPv4Properties();
            }
            catch
            {
                continue;
            }

            if (ipv4 is null) continue;
            var gateways = props.GatewayAddresses
                .Select(g => g.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.Any.Equals(a))
                .Distinct()
                .ToArray();

            adapters.Add(new WindowsRouteAdapter(
                ipv4.Index,
                ni.Name,
                ni.Description,
                ni.NetworkInterfaceType,
                ni.OperationalStatus,
                ni.Speed,
                gateways,
                defaultRouteMetrics.TryGetValue(ipv4.Index, out var metric) ? metric : int.MaxValue));
        }
        return adapters;
    }

    private static Dictionary<int, int> GetDefaultRouteMetrics()
    {
        var metrics = new Dictionary<int, int>();
        uint bufferSize = 0;
        var rc = GetIpForwardTable(IntPtr.Zero, ref bufferSize, true);
        if (rc != ErrorInsufficientBuffer || bufferSize == 0) return metrics;

        var buffer = Marshal.AllocHGlobal((int)bufferSize);
        try
        {
            rc = GetIpForwardTable(buffer, ref bufferSize, true);
            if (rc != 0) return metrics;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibIpForwardRow>();
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibIpForwardRow>(rowPtr)!;
                if (row.dwForwardDest == 0 && row.dwForwardMask == 0)
                {
                    var interfaceIndex = unchecked((int)row.dwForwardIfIndex);
                    var metric = unchecked((int)row.dwForwardMetric1);
                    if (!metrics.TryGetValue(interfaceIndex, out var existing) || metric < existing)
                        metrics[interfaceIndex] = metric;
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return metrics;
    }

    public Task AddHostRouteAsync(
        IPAddress destination,
        IPAddress gateway,
        int interfaceIndex,
        CancellationToken cancellationToken) =>
        RunRouteAsync(
            cancellationToken,
            "ADD", destination.ToString(),
            "MASK", WindowsTemporaryHostRouteService.HostRouteMask.ToString(),
            gateway.ToString(),
            "METRIC", "1",
            "IF", interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));

    public Task DeleteHostRouteAsync(
        IPAddress destination,
        IPAddress gateway,
        int interfaceIndex,
        CancellationToken cancellationToken) =>
        RunRouteAsync(
            cancellationToken,
            "DELETE", destination.ToString(),
            "MASK", WindowsTemporaryHostRouteService.HostRouteMask.ToString(),
            gateway.ToString(),
            "IF", interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static async Task RunRouteAsync(CancellationToken cancellationToken, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "route.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start route.exe.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            var detail = string.Join(" ", new[] { stdout.Trim(), stderr.Trim() }.Where(s => s.Length > 0));
            throw new InvalidOperationException(
                $"route.exe {string.Join(' ', args)} failed with exit code {process.ExitCode}: {detail}");
        }
    }

    private static uint ToRouteAddress(IPAddress address) =>
        BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    private static IPAddress FromRouteAddress(uint address) =>
        new(BitConverter.GetBytes(address));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetBestRoute(uint dwDestAddr, uint dwSourceAddr, out MibIpForwardRow pBestRoute);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpForwardTable(IntPtr pIpForwardTable, ref uint pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpForwardRow
    {
        public uint dwForwardDest;
        public uint dwForwardMask;
        public uint dwForwardPolicy;
        public uint dwForwardNextHop;
        public uint dwForwardIfIndex;
        public uint dwForwardType;
        public uint dwForwardProto;
        public uint dwForwardAge;
        public uint dwForwardNextHopAS;
        public uint dwForwardMetric1;
        public uint dwForwardMetric2;
        public uint dwForwardMetric3;
        public uint dwForwardMetric4;
        public uint dwForwardMetric5;
    }
}
