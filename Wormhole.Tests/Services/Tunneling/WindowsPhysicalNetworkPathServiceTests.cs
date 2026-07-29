using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WindowsPhysicalNetworkPathServiceTests
{
    [Fact]
    public async Task GetBestPath_ExcludesVpnAndKeepsStablePhysicalFallbacks()
    {
        var source = new FakeAdapterSource(
            Adapter("filter", "WFP filter", NetworkInterfaceType.Ethernet, 1, 1, null, null),
            Adapter("vpn", "Stormshield VPN", NetworkInterfaceType.Tunnel, 1, 1, 7, 8),
            Adapter("wifi", "Wi-Fi", NetworkInterfaceType.Wireless80211, 25, 30, 13, 14),
            Adapter(
                "ethernet",
                "Ethernet",
                NetworkInterfaceType.Ethernet,
                5,
                8,
                21,
                22,
                OperationalStatus.Down));

        var path = await new WindowsPhysicalNetworkPathService(source)
            .GetBestPathAsync(["vpn.example.test"], CancellationToken.None);

        Assert.True(path.HasAnyInterface);
        Assert.Equal(["wifi", "ethernet"], path.AdapterIds);
        Assert.Collection(
            path.Adapters,
            adapter =>
            {
                Assert.Equal("wifi", adapter.Id);
                Assert.True(adapter.IsActive);
            },
            adapter =>
            {
                Assert.Equal("ethernet", adapter.Id);
                Assert.False(adapter.IsActive);
            });
        Assert.Empty(source.ResolveCalls);
    }

    [Fact]
    public async Task GetBestPath_UsesIndependentFamilyMetrics()
    {
        var source = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, 50, 2, 11, 12),
            Adapter("wifi", "Wi-Fi", NetworkInterfaceType.Wireless80211, 5, 60, 21, 22));

        var path = await new WindowsPhysicalNetworkPathService(source)
            .GetBestPathAsync([], CancellationToken.None);

        // The best metric available on either family ranks the adapter list; actual
        // connects retain every adapter and use the metric for the endpoint family.
        Assert.Equal(["ethernet", "wifi"], path.AdapterIds);
        Assert.Equal(2, source.Adapters[0].Ipv6Metric);
        Assert.Equal(5, source.Adapters[1].Ipv4Metric);
    }

    [Fact]
    public async Task GetBestPath_NoActivePhysicalInterface_IsUnavailable()
    {
        var source = new FakeAdapterSource(
            Adapter(
                "ethernet",
                "Ethernet",
                NetworkInterfaceType.Ethernet,
                1,
                1,
                11,
                12,
                OperationalStatus.Down),
            Adapter("vpn", "Native VPN", NetworkInterfaceType.Ppp, 1, 1, 31, 32));

        var path = await new WindowsPhysicalNetworkPathService(source)
            .GetBestPathAsync([], CancellationToken.None);

        Assert.False(path.HasAnyInterface);
        Assert.Single(path.Adapters);
        Assert.Equal("ethernet", path.Adapters[0].Id);
    }

    [Fact]
    public void NetworkPath_BlankStableAdapterId_IsUnavailable()
    {
        var path = new WindowsPhysicalNetworkPath(
            [new WindowsPhysicalNetworkAdapter("", "Ethernet", true, 11, 12)]);

        Assert.False(path.HasAnyInterface);
        Assert.Empty(path.AdapterIds);
    }

    [Theory]
    [InlineData("NordLynx", "NordLynx Tunnel")]
    [InlineData("Tailscale", "Tailscale Tunnel")]
    [InlineData("Corporate adapter", "Palo Alto Networks Virtual Ethernet Adapter")]
    public void IsVpnLikeAdapter_RejectsVirtualAndTunnelAdapters(
        string name,
        string description)
    {
        var adapter = Adapter(
            "virtual",
            name,
            NetworkInterfaceType.Ethernet,
            1,
            1,
            31,
            32) with
        {
            Description = description,
        };

        Assert.True(WindowsPhysicalNetworkPathService.IsVpnLikeAdapter(adapter));
    }

    [Fact]
    public async Task GetBestPath_RejectsUnknownInterfaceTypes()
    {
        var source = new FakeAdapterSource(
            Adapter("opaque", "Opaque adapter", NetworkInterfaceType.Unknown, 1, 1, 41, 42));

        var path = await new WindowsPhysicalNetworkPathService(source)
            .GetBestPathAsync([], CancellationToken.None);

        Assert.Empty(path.Adapters);
        Assert.False(path.HasAnyInterface);
    }

    [Fact]
    public void IsVpnLikeAdapter_AllowsVirtualMachinePrimaryUplink()
    {
        var adapter = Adapter(
            "vm-uplink",
            "Ethernet",
            NetworkInterfaceType.Ethernet,
            1,
            1,
            11,
            12) with
        {
            Description = "Microsoft Hyper-V Network Adapter",
        };

        Assert.False(WindowsPhysicalNetworkPathService.IsVpnLikeAdapter(adapter));
    }

    [Fact]
    public async Task ConnectTcp_ResolvesDnsOnEachPhysicalInterfaceAndFailsOverPerEndpoint()
    {
        var firstAddress = IPAddress.Parse("192.0.2.10");
        var secondAddress = IPAddress.Parse("198.51.100.20");
        var source = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, 10, 10, 11, null),
            Adapter("wifi", "Wi-Fi", NetworkInterfaceType.Wireless80211, 20, 20, 21, null));
        source.SetResolution("vpn.example.test", 11, firstAddress);
        source.SetResolution("vpn.example.test", 21, secondAddress);
        source.SetBestRoute(firstAddress, 11);
        source.SetBestRoute(secondAddress, 21);

        var connector = new FakeSocketConnector
        {
            ConnectOverride = (address, _, _, _) =>
                address.Equals(firstAddress)
                    ? Task.FromException<Stream>(new SocketException((int)SocketError.HostUnreachable))
                    : Task.FromResult<Stream>(new MemoryStream()),
        };
        var service = new WindowsPhysicalNetworkPathService(source, connector);

        await using var stream = await service.ConnectTcpAsync(
            new DnsEndPoint("vpn.example.test", 443),
            CancellationToken.None);

        Assert.Equal([11, 21], source.ResolveCalls.Select(call => call.Ipv4InterfaceIndex));
        Assert.Contains(connector.Calls, call =>
            call.Address.Equals(firstAddress) && call.InterfaceIndex == 11);
        Assert.Contains(connector.Calls, call =>
            call.Address.Equals(secondAddress) && call.InterfaceIndex == 21);
    }

    [Fact]
    public async Task ConnectTcp_FallsBackToSystemDnsButKeepsPhysicalSocketBinding()
    {
        var address = IPAddress.Parse("198.51.100.30");
        var source = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, 10, 10, 11, null));
        source.SetSystemResolution("vpn.example.test", address);
        var connector = new FakeSocketConnector();
        var service = new WindowsPhysicalNetworkPathService(source, connector);

        await using var stream = await service.ConnectTcpAsync(
            new DnsEndPoint("vpn.example.test", 443),
            CancellationToken.None);

        Assert.Collection(
            source.ResolveCalls,
            call => Assert.Equal(11, call.Ipv4InterfaceIndex),
            call =>
            {
                Assert.Null(call.Ipv4InterfaceIndex);
                Assert.Null(call.Ipv6InterfaceIndex);
            });
        var connect = Assert.Single(connector.Calls);
        Assert.Equal(address, connect.Address);
        Assert.Equal(11, connect.InterfaceIndex);
    }

    [Fact]
    public async Task ConnectTcp_UsesSystemDnsOnlyForPhysicalAdaptersThatDidNotResolve()
    {
        var ethernetAddress = IPAddress.Parse("192.0.2.20");
        var systemAddress = IPAddress.Parse("198.51.100.30");
        var source = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, 10, 10, 11, null),
            Adapter("wifi", "Wi-Fi", NetworkInterfaceType.Wireless80211, 20, 20, 21, null));
        source.SetResolution("vpn.example.test", 11, ethernetAddress);
        source.SetSystemResolution("vpn.example.test", systemAddress);
        var connector = new FakeSocketConnector
        {
            ConnectOverride = (address, _, _, _) =>
                address.Equals(ethernetAddress)
                    ? Task.FromException<Stream>(
                        new SocketException((int)SocketError.HostUnreachable))
                    : Task.FromResult<Stream>(new MemoryStream()),
        };
        var service = new WindowsPhysicalNetworkPathService(source, connector);

        await using var stream = await service.ConnectTcpAsync(
            new DnsEndPoint("vpn.example.test", 443),
            CancellationToken.None);

        Assert.Contains(connector.Calls, call =>
            call.Address.Equals(ethernetAddress) && call.InterfaceIndex == 11);
        Assert.Contains(connector.Calls, call =>
            call.Address.Equals(systemAddress) && call.InterfaceIndex == 21);
        Assert.DoesNotContain(connector.Calls, call =>
            call.Address.Equals(systemAddress) && call.InterfaceIndex == 11);
    }

    [Fact]
    public async Task ConnectTcp_StaggersIpv6WithoutWaitingForBlackholedIpv4()
    {
        var ipv4 = IPAddress.Parse("192.0.2.30");
        var ipv6 = IPAddress.Parse("2001:db8::30");
        var source = new FakeAdapterSource(
            Adapter("uplink", "Ethernet", NetworkInterfaceType.Ethernet, 1, 1, 11, 12));
        source.SetResolution("dual.example.test", 11, ipv4);
        source.SetResolution("dual.example.test", 12, ipv6);
        var connector = new FakeSocketConnector
        {
            ConnectOverride = async (address, _, _, cancellationToken) =>
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                    throw new InvalidOperationException("Unreachable");
                }
                return new MemoryStream();
            },
        };
        var service = new WindowsPhysicalNetworkPathService(source, connector);
        var stopwatch = Stopwatch.StartNew();

        await using var stream = await service.ConnectTcpAsync(
            new DnsEndPoint("dual.example.test", 443),
            CancellationToken.None);

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2), stopwatch.Elapsed.ToString());
        Assert.Collection(
            connector.Calls,
            call => Assert.Equal(AddressFamily.InterNetwork, call.Address.AddressFamily),
            call => Assert.Equal(AddressFamily.InterNetworkV6, call.Address.AddressFamily));
    }

    [Fact]
    public async Task ConnectTcp_RefreshesInterfaceIndexImmediatelyBeforeConnect()
    {
        var address = IPAddress.Parse("203.0.113.40");
        var initial = Adapter(
            "ethernet",
            "Ethernet",
            NetworkInterfaceType.Ethernet,
            1,
            1,
            11,
            null);
        var refreshed = initial with { Ipv4InterfaceIndex = 77 };
        var source = new FakeAdapterSource(initial);
        source.SetResolution("vpn.example.test", 11, address);
        source.SetResolution("vpn.example.test", 77, address);
        source.GetAdaptersOverride = call => call == 1 ? [initial] : [refreshed];
        var connector = new FakeSocketConnector();
        var service = new WindowsPhysicalNetworkPathService(source, connector);

        await using var stream = await service.ConnectTcpAsync(
            new DnsEndPoint("vpn.example.test", 443),
            CancellationToken.None);

        Assert.Single(connector.Calls);
        Assert.Equal(77, connector.Calls[0].InterfaceIndex);
        Assert.Equal([11, 77], source.ResolveCalls.Select(call => call.Ipv4InterfaceIndex));
    }

    [Fact]
    public async Task ConnectTcp_CancellationStopsHappyEyeballsAttempts()
    {
        var address = IPAddress.Parse("192.0.2.50");
        var source = new FakeAdapterSource(
            Adapter("uplink", "Ethernet", NetworkInterfaceType.Ethernet, 1, 1, 11, null));
        source.SetResolution("vpn.example.test", 11, address);
        var connector = new FakeSocketConnector
        {
            ConnectOverride = async (_, _, _, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("Unreachable");
            },
        };
        var service = new WindowsPhysicalNetworkPathService(source, connector);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await service.ConnectTcpAsync(
                new DnsEndPoint("vpn.example.test", 443),
                cancellation.Token));
    }

    [Fact]
    public async Task ConnectTcp_UnexpectedResolverFailure_Propagates()
    {
        var source = new FakeAdapterSource(
            Adapter("uplink", "Ethernet", NetworkInterfaceType.Ethernet, 1, 1, 11, null))
        {
            ResolveOverride = (_, _, _, _) =>
                Task.FromException<IReadOnlyList<IPAddress>>(
                    new FormatException("unexpected resolver failure")),
        };
        var service = new WindowsPhysicalNetworkPathService(source);

        await Assert.ThrowsAsync<FormatException>(async () =>
            await service.ConnectTcpAsync(
                new DnsEndPoint("vpn.example.test", 443),
                CancellationToken.None));
    }

    [Fact]
    public void BindToPhysicalInterface_SetsWindowsIpv4UnicastInterface()
    {
        if (!OperatingSystem.IsWindows()) return;
        var interfaceIndex = FindInterfaceIndex(AddressFamily.InterNetwork);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        WindowsPhysicalNetworkPathService.BindToPhysicalInterface(socket, interfaceIndex);

        var stored = Assert.IsType<int>(
            socket.GetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31));
        Assert.Equal(interfaceIndex, stored);
    }

    [Fact]
    public void BindToPhysicalInterface_SetsWindowsIpv6UnicastInterface()
    {
        if (!OperatingSystem.IsWindows()) return;
        var interfaceIndex = FindInterfaceIndex(AddressFamily.InterNetworkV6);
        using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);

        WindowsPhysicalNetworkPathService.BindToPhysicalInterface(socket, interfaceIndex);

        var stored = Assert.IsType<int>(
            socket.GetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)31));
        Assert.Equal(interfaceIndex, stored);
    }

    [Fact]
    public void WindowsAdapterSource_ResolvesBestInterfaceForIpv4AndIpv6()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = new WindowsNetworkAdapterSource();

        Assert.True(source.GetBestRouteInterfaceIndex(IPAddress.Loopback) is > 0);
        Assert.True(source.GetBestRouteInterfaceIndex(IPAddress.IPv6Loopback) is > 0);
        Assert.All(source.GetAdapters(), adapter =>
        {
            Assert.True(adapter.Ipv4Metric >= 0);
            Assert.True(adapter.Ipv6Metric >= 0);
        });
    }

    private static int FindInterfaceIndex(AddressFamily family) =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Select(networkInterface =>
            {
                try
                {
                    var properties = networkInterface.GetIPProperties();
                    return family == AddressFamily.InterNetwork
                        ? properties.GetIPv4Properties()?.Index
                        : properties.GetIPv6Properties()?.Index;
                }
                catch
                {
                    return null;
                }
            })
            .First(index => index is > 0)!.Value;

    private static WindowsNetworkAdapter Adapter(
        string id,
        string name,
        NetworkInterfaceType type,
        int ipv4Metric,
        int ipv6Metric,
        int? ipv4Index,
        int? ipv6Index,
        OperationalStatus status = OperationalStatus.Up,
        long speed = 1_000_000_000) =>
        new(
            id,
            name,
            name,
            type,
            status,
            speed,
            ipv4Index,
            ipv6Index,
            ipv4Metric,
            ipv6Metric);

    private sealed class FakeAdapterSource : IWindowsNetworkAdapterSource
    {
        private readonly Dictionary<(string Host, int InterfaceIndex), IReadOnlyList<IPAddress>>
            _resolutions = new();
        private readonly Dictionary<string, IReadOnlyList<IPAddress>> _systemResolutions =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<IPAddress, int> _bestRoutes = [];
        private int _getAdaptersCalls;

        public FakeAdapterSource(params WindowsNetworkAdapter[] adapters)
        {
            Adapters = adapters;
        }

        public WindowsNetworkAdapter[] Adapters { get; set; }
        public List<(string Host, int? Ipv4InterfaceIndex, int? Ipv6InterfaceIndex)> ResolveCalls { get; } = [];
        public Func<int, IReadOnlyList<WindowsNetworkAdapter>>? GetAdaptersOverride { get; set; }
        public Func<string, int?, int?, CancellationToken, Task<IReadOnlyList<IPAddress>>>?
            ResolveOverride
        { get; set; }

        public IReadOnlyList<WindowsNetworkAdapter> GetAdapters()
        {
            var call = Interlocked.Increment(ref _getAdaptersCalls);
            return GetAdaptersOverride?.Invoke(call) ?? Adapters;
        }

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
            string host,
            int? ipv4InterfaceIndex,
            int? ipv6InterfaceIndex,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ResolveOverride is not null)
            {
                return ResolveOverride(
                    host, ipv4InterfaceIndex, ipv6InterfaceIndex, cancellationToken);
            }
            lock (ResolveCalls)
            {
                ResolveCalls.Add((host, ipv4InterfaceIndex, ipv6InterfaceIndex));
            }
            if (ipv4InterfaceIndex is null && ipv6InterfaceIndex is null)
            {
                return Task.FromResult(
                    _systemResolutions.TryGetValue(host, out var systemAddresses)
                        ? systemAddresses
                        : (IReadOnlyList<IPAddress>)[]);
            }
            var addresses = new List<IPAddress>();
            if (ipv4InterfaceIndex is { } ipv4
                && _resolutions.TryGetValue((host, ipv4), out var ipv4Addresses))
            {
                addresses.AddRange(ipv4Addresses);
            }
            if (ipv6InterfaceIndex is { } ipv6
                && ipv6 != ipv4InterfaceIndex
                && _resolutions.TryGetValue((host, ipv6), out var ipv6Addresses))
            {
                addresses.AddRange(ipv6Addresses);
            }
            return Task.FromResult<IReadOnlyList<IPAddress>>(addresses);
        }

        public int? GetBestRouteInterfaceIndex(IPAddress destination) =>
            _bestRoutes.TryGetValue(destination, out var interfaceIndex)
                ? interfaceIndex
                : null;

        public void SetResolution(
            string host,
            int interfaceIndex,
            params IPAddress[] addresses) =>
            _resolutions[(host, interfaceIndex)] = addresses;

        public void SetBestRoute(IPAddress destination, int interfaceIndex) =>
            _bestRoutes[destination] = interfaceIndex;

        public void SetSystemResolution(string host, params IPAddress[] addresses) =>
            _systemResolutions[host] = addresses;
    }

    private sealed class FakeSocketConnector : IPhysicalSocketConnector
    {
        public List<(IPAddress Address, int Port, int InterfaceIndex)> Calls { get; } = [];
        public Func<IPAddress, int, int, CancellationToken, Task<Stream>>? ConnectOverride { get; set; }

        public Task<Stream> ConnectAsync(
            IPAddress address,
            int port,
            int interfaceIndex,
            CancellationToken cancellationToken)
        {
            Calls.Add((address, port, interfaceIndex));
            return ConnectOverride?.Invoke(address, port, interfaceIndex, cancellationToken)
                ?? Task.FromResult<Stream>(new MemoryStream());
        }
    }
}
