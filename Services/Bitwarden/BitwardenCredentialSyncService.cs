using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public sealed class BitwardenCredentialSyncService : IBitwardenCredentialSyncService, IDisposable
{
    private static readonly TimeSpan SyncInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(5);

    private readonly IBitwardenVaultClient _vault;
    private readonly IBitwardenSessionService _session;
    private readonly IBitwardenCredentialCacheRepository _cache;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<BitwardenCredentialSyncService> _logger;
    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private Timer? _timer;
    private bool _started;

    public BitwardenCredentialSyncService(
        IBitwardenVaultClient vault,
        IBitwardenSessionService session,
        IBitwardenCredentialCacheRepository cache,
        IAppSettingsService settings,
        ILogger<BitwardenCredentialSyncService> logger)
    {
        _vault = vault;
        _session = session;
        _cache = cache;
        _settings = settings;
        _logger = logger;
    }

    public event EventHandler? SyncCompleted;

    public void Start()
    {
        if (_started) return;
        _started = true;
        _timer = new Timer(
            static state => _ = ((BitwardenCredentialSyncService)state!).RunTimerSyncAsync(),
            this,
            SyncInterval,
            SyncInterval);
        _ = SyncIfStaleAsync();
    }

    public async Task SyncIfStaleAsync(CancellationToken cancellationToken = default)
    {
        if (!_settings.Current.EnableBitwardenVault) return;
        var lastSync = _settings.Current.BitwardenCredentialLastSyncUtc;
        if (lastSync is not null && DateTimeOffset.UtcNow - lastSync < StaleAfter) return;
        await SyncNowAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SyncNowAsync(CancellationToken cancellationToken = default)
    {
        if (!_settings.Current.EnableBitwardenVault) return;
        if (!await _syncLock.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            _syncLock.Release();
            return;
        }

        try
        {
            await SyncCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    private async Task RunTimerSyncAsync()
    {
        try
        {
            await SyncIfStaleAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden credential background sync failed.");
        }
    }

    private async Task SyncCoreAsync(CancellationToken cancellationToken)
    {
        string? sessionKey = _session.SessionKey;
        try
        {
            var status = await _vault.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (status.Status == BitwardenVaultStatus.Unauthenticated)
            {
                StampStatus("Needs Bitwarden login to refresh.", null, availableCount: null, refreshed: false);
                return;
            }

            if (status.Status == BitwardenVaultStatus.Locked && string.IsNullOrWhiteSpace(sessionKey))
            {
                StampStatus("Needs Bitwarden unlock to refresh.", null, availableCount: null, refreshed: false);
                return;
            }

            await _vault.SyncAsync(sessionKey, cancellationToken).ConfigureAwait(false);
            var items = await _vault.ListLoginItemsAsync(sessionKey, cancellationToken).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            var entries = new List<BitwardenCredentialCacheEntry>(items.Count);
            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item.Id)) continue;
                var entry = new BitwardenCredentialCacheEntry
                {
                    ItemId = item.Id,
                    Name = string.IsNullOrWhiteSpace(item.Name) ? item.Id : item.Name,
                    Username = string.IsNullOrWhiteSpace(item.Username) ? null : item.Username,
                    RevisionDate = string.IsNullOrWhiteSpace(item.RevisionDate) ? null : item.RevisionDate,
                    LastSeenSyncUtc = now,
                    UpdatedAtUtc = now,
                };
                BitwardenVirtualCredentialIds.EnsureIds(entry);
                entries.Add(entry);
            }

            await _cache.ReplaceFromFullSyncAsync(entries, now, cancellationToken).ConfigureAwait(false);
            StampStatus($"Synced {entries.Count} Bitwarden login item(s).", null, entries.Count, refreshed: true);
            SyncCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var message = Redact(ex.Message);
            StampStatus("Bitwarden sync failed; using cached credentials.", message, availableCount: null, refreshed: false);
            _logger.LogWarning(ex, "Bitwarden credential sync failed; keeping existing cache.");
        }
    }

    private void StampStatus(string status, string? error, int? availableCount, bool refreshed)
    {
        if (refreshed) _settings.Current.BitwardenCredentialLastSyncUtc = DateTimeOffset.UtcNow;
        _settings.Current.BitwardenCredentialLastSyncStatus = status;
        _settings.Current.BitwardenCredentialLastSyncError = string.IsNullOrWhiteSpace(error) ? null : error;
        if (availableCount is not null)
        {
            _settings.Current.BitwardenCredentialAvailableCount = availableCount;
        }
        _settings.Save();
    }

    private static string Redact(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var trimmed = value.Trim();
        return trimmed.Length <= 300 ? trimmed : trimmed[..300];
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _syncLock.Dispose();
    }
}
