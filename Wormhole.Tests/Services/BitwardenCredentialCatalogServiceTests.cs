using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenCredentialCatalogServiceTests
{
    [Fact]
    public void VirtualIds_AreStablePerItemAndProtocol()
    {
        var ssh1 = BitwardenVirtualCredentialIds.ForItem("item-1", ProtocolType.Ssh);
        var ssh2 = BitwardenVirtualCredentialIds.ForItem("item-1", ProtocolType.Ssh);
        var rdp = BitwardenVirtualCredentialIds.ForItem("item-1", ProtocolType.Rdp);

        Assert.Equal(ssh1, ssh2);
        Assert.NotEqual(ssh1, rdp);
    }

    [Fact]
    public async Task GetProfilesForProtocol_ProjectsBitwardenCacheAndHidesLocalLinkedDuplicate()
    {
        var linked = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "Router local link",
            Protocol = ProtocolType.Rdp,
            SecretProvider = CredentialSecretProvider.Bitwarden,
            BitwardenItemId = "router",
        };
        var repo = new FakeCredentialRepository(linked);
        var cache = new FakeBitwardenCacheRepository(
            Cache("router", "Router", "admin"),
            Cache("server", "Server", "root"));
        var catalog = new BitwardenCredentialCatalogService(repo, cache, EnabledSettings());

        var rdp = await catalog.GetProfilesForProtocolAsync(ProtocolType.Rdp);
        var ssh = await catalog.GetProfilesForProtocolAsync(ProtocolType.Ssh);

        Assert.Contains(rdp, c => c.Id == linked.Id);
        Assert.DoesNotContain(rdp, c => c.IsVirtualBitwarden && c.BitwardenItemId == "router");
        var server = Assert.Single(rdp, c => c.IsVirtualBitwarden && c.BitwardenItemId == "server");
        Assert.Equal(ProtocolType.Rdp, server.Protocol);
        Assert.Equal(CredentialSecretProvider.Bitwarden, server.SecretProvider);
        Assert.Equal("root", server.Username);

        Assert.Contains(ssh, c => c.IsVirtualBitwarden && c.BitwardenItemId == "router");
    }

    [Fact]
    public async Task GetByIdAsync_ResolvesVirtualCredentialFromCache()
    {
        var entry = Cache("server", "Server", "root");
        var catalog = new BitwardenCredentialCatalogService(
            new FakeCredentialRepository(),
            new FakeBitwardenCacheRepository(entry),
            EnabledSettings());

        var profile = await catalog.GetByIdAsync(entry.RdpCredentialId);

        Assert.NotNull(profile);
        Assert.True(profile!.IsVirtualBitwarden);
        Assert.Equal(ProtocolType.Rdp, profile.Protocol);
        Assert.Equal("server", profile.BitwardenItemId);
        Assert.Equal(BitwardenDefaults.PasswordFieldPath, profile.BitwardenFieldPath);
    }

    private static BitwardenCredentialCacheEntry Cache(string itemId, string name, string username)
    {
        var entry = new BitwardenCredentialCacheEntry
        {
            ItemId = itemId,
            Name = name,
            Username = username,
            LastSeenSyncUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        BitwardenVirtualCredentialIds.EnsureIds(entry);
        return entry;
    }

    private static FakeSettings EnabledSettings() =>
        new FakeSettings { Current = { EnableBitwardenVault = true } };

    private sealed class FakeSettings : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class FakeBitwardenCacheRepository : IBitwardenCredentialCacheRepository
    {
        private readonly IReadOnlyList<BitwardenCredentialCacheEntry> _entries;

        public FakeBitwardenCacheRepository(params BitwardenCredentialCacheEntry[] entries)
        {
            _entries = entries;
        }

        public Task<IReadOnlyList<BitwardenCredentialCacheEntry>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(_entries);

        public Task ReplaceFromFullSyncAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            DateTimeOffset syncTimeUtc,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UpsertImportedAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
