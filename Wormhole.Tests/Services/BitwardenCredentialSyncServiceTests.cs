using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenCredentialSyncServiceTests
{
    [Fact]
    public async Task SyncNowAsync_SavesLoginMetadataWithoutPersistingPasswords()
    {
        var vault = new FakeBitwardenVaultClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Unlocked),
            Items =
            [
                new BitwardenLoginItem("item-1", "Firewall", "admin", "secret-password", "2026-07-02T10:00:00Z"),
            ],
        };
        var cache = new FakeBitwardenCacheRepository();
        var settings = EnabledSettings();
        var session = new BitwardenSessionService();
        session.SetSessionKey("SESSION");
        var service = NewService(vault, cache, settings, session);

        await service.SyncNowAsync();

        Assert.Equal(1, vault.SyncCount);
        Assert.Equal(1, vault.ListCount);
        var entry = Assert.Single(cache.LastFullSync);
        Assert.Equal("item-1", entry.ItemId);
        Assert.Equal("Firewall", entry.Name);
        Assert.Equal("admin", entry.Username);
        Assert.Equal("2026-07-02T10:00:00Z", entry.RevisionDate);
        Assert.DoesNotContain("secret-password", entry.Name);
        Assert.DoesNotContain("secret-password", entry.Username ?? string.Empty);
        Assert.Equal(1, settings.Current.BitwardenCredentialAvailableCount);
        Assert.Null(settings.Current.BitwardenCredentialLastSyncError);
    }

    [Fact]
    public async Task SyncNowAsync_WhenLockedWithoutSession_LeavesCacheUntouched()
    {
        var vault = new FakeBitwardenVaultClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Locked),
        };
        var cache = new FakeBitwardenCacheRepository();
        var settings = EnabledSettings();
        var service = NewService(vault, cache, settings, new BitwardenSessionService());

        await service.SyncNowAsync();

        Assert.Equal(0, vault.SyncCount);
        Assert.Equal(0, vault.ListCount);
        Assert.Empty(cache.LastFullSync);
        Assert.Contains("unlock", settings.Current.BitwardenCredentialLastSyncStatus, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SyncIfStaleAsync_LockedAttemptDoesNotSuppressRetryAfterUnlock()
    {
        var vault = new FakeBitwardenVaultClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Locked),
            Items = [new BitwardenLoginItem("item-1", "Firewall", "admin", "secret-password")],
        };
        var cache = new FakeBitwardenCacheRepository();
        var settings = EnabledSettings();
        var session = new BitwardenSessionService();
        var service = NewService(vault, cache, settings, session);

        await service.SyncIfStaleAsync();

        Assert.Null(settings.Current.BitwardenCredentialLastSyncUtc);
        Assert.Equal(0, vault.SyncCount);

        session.SetSessionKey("SESSION");
        vault.Status = new BitwardenStatus(BitwardenVaultStatus.Unlocked);
        await service.SyncIfStaleAsync();

        Assert.Equal(1, vault.SyncCount);
        Assert.NotNull(settings.Current.BitwardenCredentialLastSyncUtc);
        Assert.Single(cache.LastFullSync);
    }

    [Fact]
    public async Task SyncIfStaleAsync_FailedAttemptDoesNotSuppressRetryAfterRecovery()
    {
        var vault = new FakeBitwardenVaultClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Unlocked),
            Items = [new BitwardenLoginItem("item-1", "Firewall", "admin", "secret-password")],
            SyncException = new BitwardenVaultException("temporary failure"),
        };
        var cache = new FakeBitwardenCacheRepository();
        var settings = EnabledSettings();
        var session = new BitwardenSessionService();
        session.SetSessionKey("SESSION");
        var service = NewService(vault, cache, settings, session);

        await service.SyncIfStaleAsync();

        Assert.Null(settings.Current.BitwardenCredentialLastSyncUtc);
        Assert.Equal(1, vault.SyncCount);
        Assert.Empty(cache.LastFullSync);

        vault.SyncException = null;
        await service.SyncIfStaleAsync();

        Assert.Equal(2, vault.SyncCount);
        Assert.NotNull(settings.Current.BitwardenCredentialLastSyncUtc);
        Assert.Single(cache.LastFullSync);
    }

    private static BitwardenCredentialSyncService NewService(
        FakeBitwardenVaultClient vault,
        FakeBitwardenCacheRepository cache,
        IAppSettingsService settings,
        IBitwardenSessionService session) =>
        new(vault, session, cache, settings, NullLogger<BitwardenCredentialSyncService>.Instance);

    private static FakeSettings EnabledSettings() =>
        new() { Current = { EnableBitwardenVault = true } };

    private sealed class FakeSettings : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public int SaveCount { get; private set; }
        public void Save() => SaveCount++;
    }

    private sealed class FakeBitwardenCacheRepository : IBitwardenCredentialCacheRepository
    {
        public IReadOnlyList<BitwardenCredentialCacheEntry> LastFullSync { get; private set; } =
            Array.Empty<BitwardenCredentialCacheEntry>();

        public Task<IReadOnlyList<BitwardenCredentialCacheEntry>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(LastFullSync);

        public Task ReplaceFromFullSyncAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            DateTimeOffset syncTimeUtc,
            CancellationToken cancellationToken = default)
        {
            LastFullSync = entries.ToArray();
            return Task.CompletedTask;
        }

        public Task UpsertImportedAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeBitwardenVaultClient : IBitwardenVaultClient
    {
        public BitwardenStatus Status { get; set; } = new(BitwardenVaultStatus.Unlocked);
        public IReadOnlyList<BitwardenLoginItem> Items { get; set; } = Array.Empty<BitwardenLoginItem>();
        public int SyncCount { get; private set; }
        public int ListCount { get; private set; }
        public Exception? SyncException { get; set; }

        public Task<BitwardenStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Status);

        public Task<string> LoginAsync(
            string email,
            string masterPassword,
            string? authenticatorCode = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult("SESSION");

        public Task<string> UnlockAsync(string masterPassword, CancellationToken cancellationToken = default) =>
            Task.FromResult("SESSION");

        public Task<IReadOnlyList<BitwardenLoginItem>> ListLoginItemsAsync(
            string? sessionKey,
            CancellationToken cancellationToken = default)
        {
            ListCount++;
            return Task.FromResult(Items);
        }

        public Task<IReadOnlyList<BitwardenLoginItem>> SearchLoginItemsAsync(
            string query,
            string? sessionKey,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Items);

        public Task<BitwardenLoginItem?> GetLoginItemAsync(
            string itemId,
            string? sessionKey,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Items.FirstOrDefault(i => i.Id == itemId));

        public Task SyncAsync(string? sessionKey, CancellationToken cancellationToken = default)
        {
            SyncCount++;
            return SyncException is null ? Task.CompletedTask : Task.FromException(SyncException);
        }
    }
}
