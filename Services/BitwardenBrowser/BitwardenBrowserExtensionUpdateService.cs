using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Services.BitwardenBrowser;

public sealed class BitwardenBrowserExtensionUpdateService : IBitwardenBrowserExtensionUpdateService, IDisposable
{
    internal static readonly TimeSpan UpdateCheckInterval = TimeSpan.FromHours(24);

    private readonly IAppSettingsService _settings;
    private readonly IBitwardenBrowserExtensionInstaller _installer;
    private readonly ILogger<BitwardenBrowserExtensionUpdateService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public BitwardenBrowserExtensionUpdateService(
        IAppSettingsService settings,
        IBitwardenBrowserExtensionInstaller installer,
        ILogger<BitwardenBrowserExtensionUpdateService> logger)
    {
        _settings = settings;
        _installer = installer;
        _logger = logger;
    }

    public async Task UpdateIfStaleAsync(CancellationToken cancellationToken = default)
    {
        if (!ShouldCheck()) return;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!ShouldCheck()) return;

            var now = DateTimeOffset.UtcNow;
            try
            {
                var result = await _installer.UpdateIfAvailableAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
                ApplySuccess(now, result);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Bitwarden browser extension auto-update failed.");
                ApplyFailure(now, ex);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private bool ShouldCheck()
    {
        var settings = _settings.Current;
        if (!settings.EnableBitwardenBrowserExtension) return false;
        if (settings.BitwardenBrowserExtensionSource != BitwardenBrowserExtensionSource.OfficialGitHub) return false;

        var lastCheck = settings.BitwardenBrowserExtensionLastUpdateCheckUtc;
        if (lastCheck is not null && DateTimeOffset.UtcNow - lastCheck.Value < UpdateCheckInterval) return false;

        return _installer.GetConfiguredInstall() is not null;
    }

    private void ApplySuccess(DateTimeOffset checkedAtUtc, BitwardenBrowserExtensionUpdateResult result)
    {
        _settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = checkedAtUtc;
        _settings.Current.BitwardenBrowserExtensionAvailableVersion = result.Check.IsUpdateAvailable && !result.WasUpdated
            ? result.Check.LatestVersion
            : null;
        _settings.Current.BitwardenBrowserExtensionLastUpdateError = null;
        _settings.Current.BitwardenBrowserExtensionLastUpdateStatus = result.WasUpdated
            ? $"Auto-updated from official release to {result.Install?.Version ?? result.Check.LatestVersion}."
            : $"Up to date with official release {result.Check.LatestVersion}.";
        _settings.Save();
    }

    private void ApplyFailure(DateTimeOffset checkedAtUtc, Exception ex)
    {
        _settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = checkedAtUtc;
        _settings.Current.BitwardenBrowserExtensionLastUpdateStatus = "Auto-update check failed.";
        _settings.Current.BitwardenBrowserExtensionLastUpdateError = SummarizeError(ex);
        _settings.Save();
    }

    private static string SummarizeError(Exception ex)
    {
        var message = ex is BitwardenBrowserExtensionException && ex.InnerException is { } inner
            ? inner.Message
            : ex.Message;
        if (string.IsNullOrWhiteSpace(message)) return ex.GetType().Name;
        return message.Length <= 240 ? message : message[..240];
    }
}
