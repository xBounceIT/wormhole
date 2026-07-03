using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenWebDataOriginLeaseRegistryTests
{
    [Fact]
    public void Release_DoesNotClearOriginStillUsedBySiblingLease()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var first = registry.Register(@"C:\Wormhole\Profiles\Default", ["https://example.test"]);
        var second = registry.Register(@"C:\Wormhole\Profiles\Default\", ["https://EXAMPLE.test"]);

        Assert.Empty(first.Release());
        Assert.Equal(["https://example.test"], second.Release());
    }

    [Fact]
    public void Release_ClearsUniqueRedirectOriginButPreservesSharedOrigin()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var first = registry.Register(@"C:\Wormhole\Profiles\Default", ["https://example.test"]);
        var second = registry.Register(@"C:\Wormhole\Profiles\Default", ["https://example.test"]);
        first.AddOrigins(["https://login.example.test"]);

        var clearable = first.Release();

        Assert.DoesNotContain("https://example.test", clearable);
        Assert.Contains("https://login.example.test", clearable);

        second.Release();
    }

    [Fact]
    public void Release_TreatsSameOriginInDifferentProfilesAsIndependent()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var first = registry.Register(@"C:\Wormhole\Profiles\A", ["https://example.test"]);
        registry.Register(@"C:\Wormhole\Profiles\B", ["https://example.test"]);

        Assert.Equal(["https://example.test"], first.Release());
    }

    [Fact]
    public void Release_IsIdempotent()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var lease = registry.Register(@"C:\Wormhole\Profiles\Default", ["https://example.test"]);

        Assert.Equal(["https://example.test"], lease.Release());
        Assert.Empty(lease.Release());
    }

    [Fact]
    public void GetInactiveOrigins_ExcludesOriginsUsedByLiveLeaseInSameProfile()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        registry.Register(@"C:\Wormhole\Profiles\Default", ["https://active.example"]);

        var inactive = registry.GetInactiveOrigins(
            @"C:\Wormhole\Profiles\Default\",
            ["https://ACTIVE.example/path", "https://stale.example"]);

        Assert.Equal(["https://stale.example"], inactive);
    }

    [Fact]
    public void GetInactiveOrigins_ExcludesOriginsUsedByHiddenLiveView()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var owner = new object();
        registry.TrackLiveOrigins(owner, @"C:\Wormhole\Profiles\Default", ["https://hidden.example"]);

        var inactive = registry.GetInactiveOrigins(
            @"C:\Wormhole\Profiles\Default\",
            ["https://HIDDEN.example/path", "https://stale.example"]);

        Assert.Equal(["https://stale.example"], inactive);

        registry.UntrackLiveOrigins(owner);
        Assert.Equal(
            ["https://hidden.example"],
            registry.GetInactiveOrigins(@"C:\Wormhole\Profiles\Default", ["https://hidden.example"]));
    }

    [Fact]
    public void GetInactiveOrigins_ExcludesAllOriginsUsedByHiddenLiveView()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var owner = new object();
        registry.TrackLiveOrigins(
            owner,
            @"C:\Wormhole\Profiles\Default",
            ["https://first.example", "https://second.example"]);

        var inactive = registry.GetInactiveOrigins(
            @"C:\Wormhole\Profiles\Default",
            ["https://first.example/path", "https://second.example", "https://stale.example"]);

        Assert.Equal(["https://stale.example"], inactive);
    }

    [Fact]
    public void TrackLiveOrigins_ReplacesOriginsForSameOwner()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var owner = new object();
        registry.TrackLiveOrigins(owner, @"C:\Wormhole\Profiles\Default", ["https://old.example"]);
        registry.TrackLiveOrigins(owner, @"C:\Wormhole\Profiles\Default", ["https://new.example"]);

        var inactive = registry.GetInactiveOrigins(
            @"C:\Wormhole\Profiles\Default",
            ["https://old.example", "https://new.example"]);

        Assert.Equal(["https://old.example"], inactive);
    }

    [Fact]
    public void Release_DoesNotClearOriginUsedByHiddenLiveView()
    {
        var registry = new BitwardenWebDataOriginLeaseRegistry();
        var owner = new object();
        registry.TrackLiveOrigins(owner, @"C:\Wormhole\Profiles\Default", ["https://hidden.example"]);
        var lease = registry.Register(@"C:\Wormhole\Profiles\Default", ["https://hidden.example"]);

        Assert.Empty(lease.Release());

        registry.UntrackLiveOrigins(owner);
        Assert.Equal(
            ["https://hidden.example"],
            registry.GetInactiveOrigins(@"C:\Wormhole\Profiles\Default", ["https://hidden.example"]));
    }
}
