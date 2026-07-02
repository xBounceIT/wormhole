using Microsoft.Extensions.Logging;

namespace Wormhole.Services;

public sealed class BitwardenOnboardingNoticeService : IBitwardenOnboardingNoticeService
{
    public const int CurrentBitwardenOnboardingNoticeVersion = 1;
    private const string Title = "New Bitwarden integration";
    private const string Message =
        "Wormhole now supports Bitwarden as an optional vault for credentials and as a browser extension in HTTPS windows. Enable it from Settings > Extensions > Bitwarden.";

    private readonly IAppSettingsService _settings;
    private readonly IDialogService _dialog;
    private readonly ILogger<BitwardenOnboardingNoticeService> _logger;

    public BitwardenOnboardingNoticeService(
        IAppSettingsService settings,
        IDialogService dialog,
        ILogger<BitwardenOnboardingNoticeService> logger)
    {
        _settings = settings;
        _dialog = dialog;
        _logger = logger;
    }

    public async Task ShowIfNeededAsync(CancellationToken cancellationToken = default)
    {
        if (_settings.Current.BitwardenOnboardingNoticeSeenVersion >= CurrentBitwardenOnboardingNoticeVersion)
        {
            return;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _dialog.ShowBitwardenOnboardingNoticeAsync(Title, Message).ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            _settings.Current.BitwardenOnboardingNoticeSeenVersion = CurrentBitwardenOnboardingNoticeVersion;
            _settings.Save();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not show Bitwarden onboarding notice.");
        }
    }
}
