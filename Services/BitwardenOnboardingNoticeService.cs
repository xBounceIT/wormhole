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
    private readonly Version _currentVersion;

    public BitwardenOnboardingNoticeService(
        IAppSettingsService settings,
        IDialogService dialog,
        ILogger<BitwardenOnboardingNoticeService> logger)
        : this(settings, dialog, logger, GetCurrentVersion())
    {
    }

    internal BitwardenOnboardingNoticeService(
        IAppSettingsService settings,
        IDialogService dialog,
        ILogger<BitwardenOnboardingNoticeService> logger,
        Version currentVersion)
    {
        _settings = settings;
        _dialog = dialog;
        _logger = logger;
        _currentVersion = currentVersion;
    }

    public async Task ShowIfNeededAsync(CancellationToken cancellationToken = default)
    {
        if (!ShouldShowNotice()) return;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _dialog.ShowBitwardenOnboardingNoticeAsync(Title, Message).ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            _settings.Current.BitwardenOnboardingNoticeSeenVersion = CurrentBitwardenOnboardingNoticeVersion;
            _settings.Current.BitwardenOnboardingNoticePendingVersion = 0;
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

    private bool ShouldShowNotice() =>
        _settings.Current.BitwardenOnboardingNoticeSeenVersion < CurrentBitwardenOnboardingNoticeVersion &&
        _settings.Current.BitwardenOnboardingNoticePendingVersion >= CurrentBitwardenOnboardingNoticeVersion &&
        _currentVersion.Major == 0 &&
        _currentVersion.Minor == 7;

    private static Version GetCurrentVersion() =>
        typeof(BitwardenOnboardingNoticeService).Assembly.GetName().Version ?? new Version(0, 0);
}
