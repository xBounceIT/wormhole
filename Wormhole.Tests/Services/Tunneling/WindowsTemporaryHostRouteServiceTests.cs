using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Services.Tunneling;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WindowsTemporaryHostRouteServiceTests
{
    [Fact]
    public async Task PrepareGatewayBypassAsync_PhysicalRoute_NoopsWhenBypassDisabled()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var system = NewSystem();
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(PhysicalAdapter());
        system.Routes[ip.ToString()] = DefaultRoute(PhysicalInterfaceIndex);

        var lease = await NewService(system).PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: false, CancellationToken.None);
        try
        {
            var diagnostic = Assert.Single(lease.Diagnostics);
            Assert.False(diagnostic.NativeVpnConflict);
            Assert.False(diagnostic.BypassRouteInstalled);
            Assert.Contains("no native-VPN bypass", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Empty(system.AddedRoutes);
        }
        finally
        {
            await lease.DisposeAsync();
        }

        Assert.Empty(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassDisabled_WarnsWhenBestRouteUsesVpnAdapter()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var system = NewSystem();
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter());
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);

        var lease = await NewService(system).PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: false, CancellationToken.None);
        try
        {
            var diagnostic = Assert.Single(lease.Diagnostics);
            Assert.True(diagnostic.NativeVpnConflict);
            Assert.False(diagnostic.BypassRouteInstalled);
            Assert.Contains("VPN-like adapter", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Empty(system.AddedRoutes);
        }
        finally
        {
            await lease.DisposeAsync();
        }

        Assert.Empty(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_InstallsTemporaryHostRouteViaPhysicalGateway()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var gateway = IPAddress.Parse("192.168.1.1");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter(gateway));
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);

        var lease = await NewService(system).PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);
        try
        {
            var diagnostic = Assert.Single(lease.Diagnostics);
            Assert.True(diagnostic.NativeVpnConflict);
            Assert.True(diagnostic.BypassRouteInstalled);
            var added = Assert.Single(system.AddedRoutes);
            Assert.Equal(ip, added.Destination);
            Assert.Equal(gateway, added.Gateway);
            Assert.Equal(PhysicalInterfaceIndex, added.InterfaceIndex);
        }
        finally
        {
            await lease.DisposeAsync();
        }

        var deleted = Assert.Single(system.DeletedRoutes);
        Assert.Equal(ip, deleted.Destination);
        Assert.Equal(gateway, deleted.Gateway);
        Assert.Equal(PhysicalInterfaceIndex, deleted.InterfaceIndex);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_SkipsFasterVirtualDefaultGateway()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var physicalGateway = IPAddress.Parse("192.168.1.1");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(VirtualAdapter());
        system.Adapters.Add(PhysicalAdapter(physicalGateway, speed: 100_000_000));
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);

        var lease = await NewService(system).PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);
        try
        {
            var added = Assert.Single(system.AddedRoutes);
            Assert.Equal(physicalGateway, added.Gateway);
            Assert.Equal(PhysicalInterfaceIndex, added.InterfaceIndex);
        }
        finally
        {
            await lease.DisposeAsync();
        }
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_RefCountsSharedTemporaryRoutes()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var gateway = IPAddress.Parse("192.168.1.1");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter(gateway));
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);
        var service = NewService(system);

        var first = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);
        var second = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);

        Assert.Single(system.AddedRoutes);
        await first.DisposeAsync();
        Assert.Empty(system.DeletedRoutes);
        await second.DisposeAsync();
        Assert.Single(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_ReferencesActiveRouteWhenWindowsNowPrefersIt()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var gateway = IPAddress.Parse("192.168.1.1");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter(gateway));
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);
        var service = NewService(system);

        var first = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);
        system.Routes[ip.ToString()] = HostRoute(ip, PhysicalInterfaceIndex);
        var second = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);

        Assert.Single(system.AddedRoutes);
        var diagnostic = Assert.Single(second.Diagnostics);
        Assert.True(diagnostic.BypassRouteInstalled);
        Assert.Contains("existing temporary host route", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
        await first.DisposeAsync();
        Assert.Empty(system.DeletedRoutes);
        await second.DisposeAsync();
        Assert.Single(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassDisabled_DoesNotReferenceActiveRouteWhenWindowsNowPrefersIt()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var gateway = IPAddress.Parse("192.168.1.1");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter(gateway));
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);
        var service = NewService(system);

        var first = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: true, CancellationToken.None);
        system.Routes[ip.ToString()] = HostRoute(ip, PhysicalInterfaceIndex);
        var second = await service.PrepareGatewayBypassAsync(
            "cfg", GatewayHosts, enableBypass: false, CancellationToken.None);

        var diagnostic = Assert.Single(second.Diagnostics);
        Assert.False(diagnostic.NativeVpnConflict);
        Assert.False(diagnostic.BypassRouteInstalled);
        await first.DisposeAsync();
        Assert.Single(system.DeletedRoutes);
        await second.DisposeAsync();
        Assert.Single(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_RequiresAdministrator()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var system = NewSystem(isAdministrator: false);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter());
        system.Routes[ip.ToString()] = DefaultRoute(VpnInterfaceIndex);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewService(system).PrepareGatewayBypassAsync(
                "cfg", GatewayHosts, enableBypass: true, CancellationToken.None));

        Assert.Contains("Administrator", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(system.AddedRoutes);
        Assert.Empty(system.DeletedRoutes);
    }

    [Fact]
    public async Task PrepareGatewayBypassAsync_BypassEnabled_RefusesExistingVpnHostRoute()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        var system = NewSystem(isAdministrator: true);
        system.Resolve("rpv.example.com", ip);
        system.Adapters.Add(VpnAdapter());
        system.Adapters.Add(PhysicalAdapter());
        system.Routes[ip.ToString()] = HostRoute(ip, VpnInterfaceIndex);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewService(system).PrepareGatewayBypassAsync(
                "cfg", GatewayHosts, enableBypass: true, CancellationToken.None));

        Assert.Contains("host route", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(system.AddedRoutes);
        Assert.Empty(system.DeletedRoutes);
    }

    private static readonly string[] GatewayHosts = { "rpv.example.com" };
    private const int VpnInterfaceIndex = 7;
    private const int PhysicalInterfaceIndex = 11;
    private const int VirtualInterfaceIndex = 20;

    private static WindowsTemporaryHostRouteService NewService(FakeRouteSystem system) =>
        new(system, NullLogger<WindowsTemporaryHostRouteService>.Instance);

    private static FakeRouteSystem NewSystem(bool isAdministrator = false) => new() { IsAdministrator = isAdministrator };

    private static WindowsRouteAdapter VpnAdapter() =>
        new(
            VpnInterfaceIndex,
            "Stormshield VPN",
            "Stormshield SSL VPN Adapter",
            NetworkInterfaceType.Ppp,
            OperationalStatus.Up,
            100_000_000,
            Array.Empty<IPAddress>());

    private static WindowsRouteAdapter PhysicalAdapter(IPAddress? gateway = null, long speed = 1_000_000_000) =>
        new(
            PhysicalInterfaceIndex,
            "Ethernet",
            "Intel(R) Ethernet Connection",
            NetworkInterfaceType.Ethernet,
            OperationalStatus.Up,
            speed,
            new[] { gateway ?? IPAddress.Parse("192.168.1.1") });

    private static WindowsRouteAdapter VirtualAdapter() =>
        new(
            VirtualInterfaceIndex,
            "vEthernet (Default Switch)",
            "Hyper-V Virtual Ethernet Adapter",
            NetworkInterfaceType.Ethernet,
            OperationalStatus.Up,
            10_000_000_000,
            new[] { IPAddress.Parse("172.20.0.1") });

    private static WindowsBestRoute DefaultRoute(int interfaceIndex) =>
        new(
            IPAddress.Parse("0.0.0.0"),
            IPAddress.Parse("0.0.0.0"),
            IPAddress.Parse("0.0.0.0"),
            interfaceIndex,
            10);

    private static WindowsBestRoute HostRoute(IPAddress destination, int interfaceIndex) =>
        new(
            destination,
            IPAddress.Parse("255.255.255.255"),
            IPAddress.Parse("0.0.0.0"),
            interfaceIndex,
            1);

    private sealed class FakeRouteSystem : IWindowsRouteSystem
    {
        private readonly Dictionary<string, IReadOnlyList<IPAddress>> _resolutions = new(StringComparer.OrdinalIgnoreCase);

        public bool IsAdministrator { get; set; }
        public Dictionary<string, WindowsBestRoute?> Routes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<WindowsRouteAdapter> Adapters { get; } = new();
        public List<RouteOperation> AddedRoutes { get; } = new();
        public List<RouteOperation> DeletedRoutes { get; } = new();

        public void Resolve(string host, params IPAddress[] addresses) => _resolutions[host] = addresses;

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, CancellationToken cancellationToken)
        {
            if (IPAddress.TryParse(host, out var literal))
                return Task.FromResult<IReadOnlyList<IPAddress>>(new[] { literal });

            if (_resolutions.TryGetValue(host, out var addresses))
                return Task.FromResult(addresses);

            throw new InvalidOperationException($"No test resolution for {host}.");
        }

        public WindowsBestRoute? GetBestRoute(IPAddress destination) =>
            Routes.TryGetValue(destination.ToString(), out var route) ? route : null;

        public IReadOnlyList<WindowsRouteAdapter> GetAdapters() => Adapters;

        public Task AddHostRouteAsync(
            IPAddress destination,
            IPAddress gateway,
            int interfaceIndex,
            CancellationToken cancellationToken)
        {
            AddedRoutes.Add(new RouteOperation(destination, gateway, interfaceIndex));
            return Task.CompletedTask;
        }

        public Task DeleteHostRouteAsync(
            IPAddress destination,
            IPAddress gateway,
            int interfaceIndex,
            CancellationToken cancellationToken)
        {
            DeletedRoutes.Add(new RouteOperation(destination, gateway, interfaceIndex));
            return Task.CompletedTask;
        }
    }

    private sealed record RouteOperation(IPAddress Destination, IPAddress Gateway, int InterfaceIndex);
}
