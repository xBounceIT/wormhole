using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Windows.Storage.Pickers;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Models.Backup;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Wormhole.Services.BitwardenBrowser;
using Wormhole.Services.Mcp;
using Wormhole.Services.Security;

namespace Wormhole.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IAppSettingsService _settingsService;
    private readonly IDialogService _dialog;
    private readonly IBitwardenVaultClient _bitwardenVault;
    private readonly IBitwardenSessionService _bitwardenSession;
    private readonly IBitwardenCliInstaller _bitwardenCliInstaller;
    private readonly IBitwardenCredentialSyncService _bitwardenCredentialSync;
    private readonly IBitwardenBrowserExtensionInstaller _bitwardenBrowserExtensionInstaller;
    private readonly ConnectionTreeViewModel _connectionTree;
    private readonly CredentialsViewModel _credentials;
    private readonly TunnelConfigsViewModel _tunnels;
    private readonly IMcpServerHost _mcpHost;
    private readonly IAppAuthenticationService _appAuthentication;
    private readonly IAppAuthenticationVerifier _appAuthenticationVerifier;
    private readonly IWindowsHelloService _windowsHello;
    private readonly ILogger<SettingsViewModel> _logger;
    private static readonly int?[] IdleTimeoutOptions = [null, 1, 5, 15, 30, 60];

    // Guards against re-entrant OnEnableMcpServerChanged when we revert the toggle after a
    // start failure.
    private bool _suppressMcpToggle;
    private bool _suppressSecurityChanges;
    private bool _suppressBitwardenBrowserExtensionToggle;
    private bool _suppressBitwardenVaultAutoEnable;

    [ObservableProperty]
    private ApplicationTheme theme;

    [ObservableProperty]
    private bool confirmOnTabClose;

    [ObservableProperty]
    private bool autoCheckForUpdates;

    [ObservableProperty]
    private bool autoCopyOnSelect;

    [ObservableProperty]
    private bool promptBeforeTunnelConnect;

    [ObservableProperty]
    private bool enableBitwardenVault;

    [ObservableProperty]
    private string bitwardenCliPath = "bw";

    [ObservableProperty]
    private string bitwardenStatus = "Disabled";

    [ObservableProperty]
    private bool isBitwardenBusy;

    [ObservableProperty]
    private bool enableBitwardenBrowserExtension;

    [ObservableProperty]
    private string bitwardenBrowserExtensionStatus = "Disabled";

    [ObservableProperty]
    private bool isBitwardenBrowserExtensionBusy;

    [ObservableProperty]
    private bool enableMcpServer;

    [ObservableProperty]
    private bool streamMcpCommandTyping;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsAppAuthenticationEnabled))]
    [NotifyPropertyChangedFor(nameof(ShowWindowsHelloFallback))]
    [NotifyPropertyChangedFor(nameof(CanTestAppAuthentication))]
    [NotifyPropertyChangedFor(nameof(CanSetOrChangeAppAuthenticationSecret))]
    [NotifyPropertyChangedFor(nameof(SetOrChangeAppAuthenticationSecretButtonText))]
    private int appAuthenticationModeIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SetOrChangeAppAuthenticationSecretButtonText))]
    private int appAuthenticationHelloFallbackIndex;

    [ObservableProperty]
    private int appAuthenticationIdleTimeoutIndex;

    [ObservableProperty]
    private string appAuthenticationStatus = string.Empty;

    [ObservableProperty]
    private string windowsHelloStatus = string.Empty;

    [ObservableProperty]
    private string currentLogFilePath = string.Empty;

    [ObservableProperty]
    private double logRetentionDays;

    public bool IsAppAuthenticationEnabled => AppAuthenticationModeIndex != 0;

    public bool ShowWindowsHelloFallback => AppAuthenticationModeIndex == (int)AppAuthenticationMode.WindowsHello;

    public bool CanTestAppAuthentication => AppAuthenticationModeIndex != 0;

    public bool CanSetOrChangeAppAuthenticationSecret => AppAuthenticationModeIndex != 0;

    public string SetOrChangeAppAuthenticationSecretButtonText =>
        "Set / change " + SecretActionLabel(SelectedSecretMethod());

    // double (not int) so it binds directly to NumberBox.Value.
    [ObservableProperty]
    private double mcpServerPort;

    [ObservableProperty]
    private string mcpEndpoint = string.Empty;

    [ObservableProperty]
    private string mcpStatus = string.Empty;

    [ObservableProperty]
    private string mcpToken = string.Empty;

    [ObservableProperty]
    private bool isMcpTokenRevealed;

    [ObservableProperty]
    private string mcpConfigJson = string.Empty;

    // 0 = Claude Code CLI, 1 = Claude Desktop, 2 = Codex (matches the ComboBox item order).
    [ObservableProperty]
    private int mcpClientIndex;

    [ObservableProperty]
    private string mcpConfigLabel = "Config";

    [ObservableProperty]
    private string mcpConfigCaption = string.Empty;

    public UpdateViewModel Update { get; }

    public SettingsViewModel(
        IAppSettingsService settingsService,
        UpdateViewModel update,
        IDialogService dialog,
        IBitwardenVaultClient bitwardenVault,
        IBitwardenSessionService bitwardenSession,
        IBitwardenCliInstaller bitwardenCliInstaller,
        IBitwardenCredentialSyncService bitwardenCredentialSync,
        IBitwardenBrowserExtensionInstaller bitwardenBrowserExtensionInstaller,
        ConnectionTreeViewModel connectionTree,
        CredentialsViewModel credentials,
        TunnelConfigsViewModel tunnels,
        IMcpServerHost mcpHost,
        IAppAuthenticationService appAuthentication,
        IAppAuthenticationVerifier appAuthenticationVerifier,
        IWindowsHelloService windowsHello,
        ILogger<SettingsViewModel> logger)
    {
        _settingsService = settingsService;
        _dialog = dialog;
        _bitwardenVault = bitwardenVault;
        _bitwardenSession = bitwardenSession;
        _bitwardenCliInstaller = bitwardenCliInstaller;
        _bitwardenCredentialSync = bitwardenCredentialSync;
        _bitwardenBrowserExtensionInstaller = bitwardenBrowserExtensionInstaller;
        _connectionTree = connectionTree;
        _credentials = credentials;
        _tunnels = tunnels;
        _mcpHost = mcpHost;
        _appAuthentication = appAuthentication;
        _appAuthenticationVerifier = appAuthenticationVerifier;
        _windowsHello = windowsHello;
        _logger = logger;
        Update = update;
        theme = _settingsService.Current.Theme;
        confirmOnTabClose = _settingsService.Current.ConfirmOnTabClose;
        autoCheckForUpdates = _settingsService.Current.AutoCheckForUpdates;
        autoCopyOnSelect = _settingsService.Current.AutoCopyOnSelect;
        promptBeforeTunnelConnect = _settingsService.Current.PromptBeforeTunnelConnect;
        enableBitwardenVault = _settingsService.Current.EnableBitwardenVault;
        bitwardenCliPath = _settingsService.Current.BitwardenCliPath;
        BitwardenStatus = EnableBitwardenVault ? "Not checked" : "Disabled";
        enableBitwardenBrowserExtension = _settingsService.Current.EnableBitwardenBrowserExtension;
        RefreshBitwardenBrowserExtensionStatus();
        enableMcpServer = _settingsService.Current.EnableMcpServer;
        streamMcpCommandTyping = _settingsService.Current.StreamMcpCommandTyping;
        mcpServerPort = _settingsService.Current.McpServerPort;
        appAuthenticationModeIndex = (int)_settingsService.Current.AppAuthenticationMode;
        appAuthenticationHelloFallbackIndex = (int)_settingsService.Current.AppAuthenticationHelloFallback;
        appAuthenticationIdleTimeoutIndex = TimeoutMinutesToIndex(_settingsService.Current.AppAuthenticationIdleTimeoutMinutes);
        currentLogFilePath = LogFiles.GetCurrentDayLogFilePath();
        logRetentionDays = LogFiles.NormalizeRetentionDays(_settingsService.Current.LogRetentionDays);
        UpdateMcpStatus();
        _ = RefreshSecurityStatusAsync();
        if (EnableBitwardenVault) _ = RefreshBitwardenStatusAsync();
    }

    partial void OnThemeChanged(ApplicationTheme value)
    {
        _settingsService.Current.Theme = value;
        _settingsService.Save();
    }

    partial void OnConfirmOnTabCloseChanged(bool value)
    {
        _settingsService.Current.ConfirmOnTabClose = value;
        _settingsService.Save();
    }

    partial void OnAutoCheckForUpdatesChanged(bool value)
    {
        _settingsService.Current.AutoCheckForUpdates = value;
        _settingsService.Save();
    }

    partial void OnAutoCopyOnSelectChanged(bool value)
    {
        _settingsService.Current.AutoCopyOnSelect = value;
        _settingsService.Save();
    }

    partial void OnPromptBeforeTunnelConnectChanged(bool value)
    {
        _settingsService.Current.PromptBeforeTunnelConnect = value;
        _settingsService.Save();
    }

    partial void OnEnableBitwardenVaultChanged(bool value)
    {
        _settingsService.Current.EnableBitwardenVault = value;
        _settingsService.Save();
        if (value)
        {
            if (!_suppressBitwardenVaultAutoEnable)
            {
                _ = EnableBitwardenVaultAsync();
            }
        }
        else
        {
            _bitwardenSession.ClearSessionKey();
            BitwardenStatus = "Disabled";
        }
    }

    private async Task EnableBitwardenVaultAsync()
    {
        try
        {
            await RefreshBitwardenStatusAsync().ConfigureAwait(true);
            if (_bitwardenCliInstaller.GetConfiguredInstall() is null) return;

            _bitwardenCredentialSync.Start();
            await _bitwardenCredentialSync.SyncIfStaleAsync().ConfigureAwait(true);
            await _credentials.LoadCommand.ExecuteAsync(null).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden vault enable flow failed.");
            BitwardenStatus = ex.Message;
        }
    }

    partial void OnBitwardenCliPathChanged(string value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? "bw" : value.Trim();
        if (!string.Equals(_settingsService.Current.BitwardenCliPath, normalized, StringComparison.OrdinalIgnoreCase))
        {
            _settingsService.Current.BitwardenCliVersion = null;
            _settingsService.Current.BitwardenCliSha256 = null;
            _settingsService.Current.BitwardenCliAssetName = null;
            _settingsService.Current.BitwardenCliDownloadUrl = null;
            _settingsService.Current.BitwardenCliInstallStatus = null;
            _settingsService.Current.BitwardenCliInstallError = null;
        }

        _settingsService.Current.BitwardenCliPath = normalized;
        _settingsService.Save();
    }

    partial void OnStreamMcpCommandTypingChanged(bool value)
    {
        _settingsService.Current.StreamMcpCommandTyping = value;
        _settingsService.Save();
    }

    partial void OnLogRetentionDaysChanged(double value)
    {
        if (!double.IsFinite(value))
        {
            LogRetentionDays = LogFiles.NormalizeRetentionDays(_settingsService.Current.LogRetentionDays);
            return;
        }

        var days = (int)Math.Round(value, MidpointRounding.AwayFromZero);
        var normalized = LogFiles.NormalizeRetentionDays(days);
        if (normalized != days || Math.Abs(value - normalized) > 0.001)
        {
            LogRetentionDays = normalized;
            return;
        }

        if (_settingsService.Current.LogRetentionDays == normalized) return;
        _settingsService.Current.LogRetentionDays = normalized;
        _settingsService.Save();
    }

    [RelayCommand]
    private async Task OpenCurrentLogFileAsync()
    {
        try
        {
            var path = LogFiles.GetCurrentDayLogFilePath();
            Directory.CreateDirectory(AppPaths.GetLogsDirectory());
            using (File.Open(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            {
            }

            CurrentLogFilePath = path;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to open current log file.");
            await _dialog.ShowMessageAsync("Couldn't open log file", ex.Message);
        }
    }

    [RelayCommand]
    private async Task OpenLogsFolderAsync()
    {
        try
        {
            var path = AppPaths.GetLogsDirectory();
            Directory.CreateDirectory(path);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to open logs folder.");
            await _dialog.ShowMessageAsync("Couldn't open logs folder", ex.Message);
        }
    }

    // === Bitwarden credential vault ======================================

    [RelayCommand]
    private async Task RefreshBitwardenStatusAsync()
    {
        if (!EnableBitwardenVault)
        {
            BitwardenStatus = "Disabled";
            return;
        }

        if (_bitwardenCliInstaller.GetConfiguredInstall() is null)
        {
            await RunBitwardenCliInstallAsync("Installing Bitwarden CLI...", showErrorDialog: false, forceInstall: false).ConfigureAwait(true);
            if (_bitwardenCliInstaller.GetConfiguredInstall() is null) return;
        }

        IsBitwardenBusy = true;
        try
        {
            var status = await _bitwardenVault.GetStatusAsync().ConfigureAwait(true);
            BitwardenStatus = AppendBitwardenCredentialSyncStatus(
                DescribeBitwardenStatus(status, _bitwardenSession.HasSessionKey, _bitwardenCliInstaller.GetConfiguredInstall()));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read Bitwarden vault status.");
            BitwardenStatus = ex.Message;
        }
        finally
        {
            IsBitwardenBusy = false;
        }
    }

    [RelayCommand]
    private async Task InstallBitwardenCliAsync()
    {
        if (!EnableBitwardenVault)
        {
            _suppressBitwardenVaultAutoEnable = true;
            try
            {
                EnableBitwardenVault = true;
            }
            finally
            {
                _suppressBitwardenVaultAutoEnable = false;
            }
        }

        await RunBitwardenCliInstallAsync("Installing Bitwarden CLI...", showErrorDialog: true, forceInstall: true).ConfigureAwait(true);
        if (_bitwardenCliInstaller.GetConfiguredInstall() is not null)
        {
            await EnableBitwardenVaultAsync().ConfigureAwait(true);
        }
    }

    private async Task RunBitwardenCliInstallAsync(string initialStatus, bool showErrorDialog, bool forceInstall)
    {
        if (IsBitwardenBusy) return;

        IsBitwardenBusy = true;
        BitwardenStatus = initialStatus;
        var progress = new Progress<string>(message => BitwardenStatus = message);
        try
        {
            _ = forceInstall
                ? await _bitwardenCliInstaller.InstallLatestAsync(progress).ConfigureAwait(true)
                : await _bitwardenCliInstaller.EnsureInstalledAsync(progress).ConfigureAwait(true);
            BitwardenCliPath = _settingsService.Current.BitwardenCliPath;
            BitwardenStatus = _settingsService.Current.BitwardenCliInstallStatus ?? "Bitwarden CLI installed.";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden CLI install failed.");
            _settingsService.Current.BitwardenCliInstallError = ex.Message;
            _settingsService.Current.BitwardenCliInstallStatus = "Bitwarden CLI install failed.";
            _settingsService.Save();
            BitwardenStatus = "Bitwarden CLI install failed: " + ex.Message;
            if (showErrorDialog)
            {
                await _dialog.ShowMessageAsync("Couldn't install Bitwarden CLI", ex.Message).ConfigureAwait(true);
            }
        }
        finally
        {
            IsBitwardenBusy = false;
        }
    }

    [RelayCommand]
    private async Task LoginBitwardenAsync()
    {
        if (!EnableBitwardenVault)
        {
            await _dialog.ShowMessageAsync("Bitwarden disabled", "Enable Bitwarden before logging in to the vault.");
            return;
        }

        if (_bitwardenCliInstaller.GetConfiguredInstall() is null)
        {
            await RunBitwardenCliInstallAsync("Installing Bitwarden CLI...", showErrorDialog: true, forceInstall: false).ConfigureAwait(true);
            if (_bitwardenCliInstaller.GetConfiguredInstall() is null) return;
        }

        var credentials = await _dialog.PromptBitwardenLoginAsync().ConfigureAwait(true);
        if (credentials is null) return;

        IsBitwardenBusy = true;
        BitwardenStatus = "Logging in to Bitwarden...";
        try
        {
            var sessionKey = await _bitwardenVault.LoginAsync(credentials.Value.Email, credentials.Value.MasterPassword, credentials.Value.AuthenticatorCode).ConfigureAwait(true);
            _bitwardenSession.SetSessionKey(sessionKey);
            await _bitwardenCredentialSync.SyncNowAsync().ConfigureAwait(true);
            await _credentials.LoadCommand.ExecuteAsync(null).ConfigureAwait(true);
            await RefreshBitwardenStatusAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden vault login failed.");
            await _dialog.ShowMessageAsync("Couldn't log in to Bitwarden", ex.Message).ConfigureAwait(true);
            BitwardenStatus = ex.Message;
        }
        finally
        {
            IsBitwardenBusy = false;
        }
    }

    [RelayCommand]
    private async Task UnlockBitwardenAsync()
    {
        if (!EnableBitwardenVault)
        {
            await _dialog.ShowMessageAsync("Bitwarden disabled", "Enable Bitwarden before unlocking the vault.");
            return;
        }

        var password = await _dialog.PromptSecretAsync(
            "Unlock Bitwarden vault",
            "Enter your Bitwarden master password. Wormhole passes it to bw through an environment variable and never stores it.",
            "Master password",
            "Unlock").ConfigureAwait(true);
        if (password is null) return;

        IsBitwardenBusy = true;
        try
        {
            var sessionKey = await _bitwardenVault.UnlockAsync(password).ConfigureAwait(true);
            _bitwardenSession.SetSessionKey(sessionKey);
            await _bitwardenCredentialSync.SyncNowAsync().ConfigureAwait(true);
            await _credentials.LoadCommand.ExecuteAsync(null).ConfigureAwait(true);
            await RefreshBitwardenStatusAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden vault unlock failed.");
            await _dialog.ShowMessageAsync("Couldn't unlock Bitwarden", ex.Message).ConfigureAwait(true);
            BitwardenStatus = ex.Message;
        }
        finally
        {
            IsBitwardenBusy = false;
        }
    }

    [RelayCommand]
    private async Task SyncBitwardenAsync()
    {
        if (!EnableBitwardenVault)
        {
            await _dialog.ShowMessageAsync("Bitwarden disabled", "Enable Bitwarden before syncing the vault.");
            return;
        }

        IsBitwardenBusy = true;
        try
        {
            await _bitwardenCredentialSync.SyncNowAsync().ConfigureAwait(true);
            await _credentials.LoadCommand.ExecuteAsync(null).ConfigureAwait(true);
            await RefreshBitwardenStatusAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden vault sync failed.");
            await _dialog.ShowMessageAsync("Couldn't sync Bitwarden", ex.Message).ConfigureAwait(true);
            BitwardenStatus = ex.Message;
        }
        finally
        {
            IsBitwardenBusy = false;
        }
    }

    private string AppendBitwardenCredentialSyncStatus(string status)
    {
        var syncStatus = _settingsService.Current.BitwardenCredentialLastSyncStatus;
        if (string.IsNullOrWhiteSpace(syncStatus)) return status;

        var count = _settingsService.Current.BitwardenCredentialAvailableCount;
        var suffix = count is null
            ? syncStatus
            : $"{syncStatus} Cached logins: {count.Value}.";
        return $"{status} {suffix}";
    }

    private static string DescribeBitwardenStatus(BitwardenStatus status, bool hasSessionKey, BitwardenCliInstall? cliInstall)
    {
        var state = status.Status switch
        {
            BitwardenVaultStatus.Unauthenticated => "Unauthenticated",
            BitwardenVaultStatus.Locked => "Locked",
            BitwardenVaultStatus.Unlocked => "Unlocked",
            _ => "Unknown",
        };
        var identity = string.IsNullOrWhiteSpace(status.UserEmail) ? string.Empty : $" ({status.UserEmail})";
        var session = hasSessionKey ? " Session key is available in memory." : string.Empty;
        var cli = cliInstall is null || cliInstall.Version == "external" ? string.Empty : $" CLI {cliInstall.Version} installed automatically.";
        return $"{state}{identity}.{session}{cli}";
    }

    // === Bitwarden HTTPS browser extension ==============================

    partial void OnEnableBitwardenBrowserExtensionChanged(bool value)
    {
        if (_suppressBitwardenBrowserExtensionToggle) return;

        SaveBitwardenBrowserExtensionEnabled(value);
        RefreshBitwardenBrowserExtensionStatus();
        if (value && _bitwardenBrowserExtensionInstaller.GetConfiguredInstall() is null)
        {
            _ = AutoInstallBitwardenBrowserExtensionAsync();
        }
    }

    [RelayCommand]
    private async Task InstallBitwardenBrowserExtensionAsync()
    {
        EnableBitwardenBrowserExtensionWithoutAutoInstall();
        await RunBitwardenBrowserExtensionInstallAsync(
            progress => _bitwardenBrowserExtensionInstaller.InstallLatestAsync(progress),
            "Installing Bitwarden browser extension...").ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ImportBitwardenBrowserExtensionZipAsync()
    {
        var zipPath = await PickBitwardenExtensionZipAsync().ConfigureAwait(true);
        if (zipPath is null) return;
        EnableBitwardenBrowserExtensionWithoutAutoInstall();
        await RunBitwardenBrowserExtensionInstallAsync(
            _ => _bitwardenBrowserExtensionInstaller.ImportZipAsync(zipPath),
            "Importing Bitwarden browser extension ZIP...").ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ImportBitwardenBrowserExtensionFolderAsync()
    {
        var folderPath = await PickBitwardenExtensionFolderAsync().ConfigureAwait(true);
        if (folderPath is null) return;
        EnableBitwardenBrowserExtensionWithoutAutoInstall();
        await RunBitwardenBrowserExtensionInstallAsync(
            _ => _bitwardenBrowserExtensionInstaller.ImportUnpackedAsync(folderPath),
            "Importing Bitwarden browser extension folder...").ConfigureAwait(true);
    }

    private Task AutoInstallBitwardenBrowserExtensionAsync() =>
        RunBitwardenBrowserExtensionInstallAsync(
            progress => _bitwardenBrowserExtensionInstaller.InstallLatestAsync(progress),
            "Installing Bitwarden browser extension...");

    private void EnableBitwardenBrowserExtensionWithoutAutoInstall()
    {
        if (!EnableBitwardenBrowserExtension)
        {
            _suppressBitwardenBrowserExtensionToggle = true;
            try
            {
                EnableBitwardenBrowserExtension = true;
            }
            finally
            {
                _suppressBitwardenBrowserExtensionToggle = false;
            }
        }

        SaveBitwardenBrowserExtensionEnabled(true);
        RefreshBitwardenBrowserExtensionStatus();
    }

    private void SaveBitwardenBrowserExtensionEnabled(bool value)
    {
        _settingsService.Current.EnableBitwardenBrowserExtension = value;
        _settingsService.Save();
    }

    private async Task RunBitwardenBrowserExtensionInstallAsync(
        Func<IProgress<string>, Task<BitwardenBrowserExtensionInstall>> installAsync,
        string initialStatus)
    {
        if (IsBitwardenBrowserExtensionBusy) return;

        IsBitwardenBrowserExtensionBusy = true;
        BitwardenBrowserExtensionStatus = initialStatus;
        var progress = new Progress<string>(message => BitwardenBrowserExtensionStatus = message);
        try
        {
            _ = await installAsync(progress).ConfigureAwait(true);
            RefreshBitwardenBrowserExtensionStatus();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bitwarden browser extension install failed.");
            BitwardenBrowserExtensionStatus = ex.Message;
            await _dialog.ShowMessageAsync("Couldn't install Bitwarden extension", ex.Message).ConfigureAwait(true);
        }
        finally
        {
            IsBitwardenBrowserExtensionBusy = false;
        }
    }

    private void RefreshBitwardenBrowserExtensionStatus()
    {
        if (!EnableBitwardenBrowserExtension)
        {
            BitwardenBrowserExtensionStatus = "Disabled";
            return;
        }

        var install = _bitwardenBrowserExtensionInstaller.GetConfiguredInstall();
        if (install is null)
        {
            BitwardenBrowserExtensionStatus = "Not installed. Wormhole will install the official Bitwarden browser extension automatically.";
            return;
        }

        var settings = _settingsService.Current;
        var source = settings.BitwardenBrowserExtensionSource switch
        {
            BitwardenBrowserExtensionSource.ManualZip => "manual ZIP, pinned",
            BitwardenBrowserExtensionSource.ManualFolder => "manual folder, pinned",
            _ => "official release, auto-update enabled",
        };

        var parts = new List<string>
        {
            $"Installed {install.Version} ({source}). HTTPS tabs will load the Bitwarden extension."
        };

        if (settings.BitwardenBrowserExtensionLastUpdateCheckUtc is { } lastCheck)
        {
            parts.Add($"Last update check: {lastCheck.ToLocalTime():g}.");
        }
        if (!string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionLastUpdateStatus))
        {
            parts.Add(settings.BitwardenBrowserExtensionLastUpdateStatus!);
        }
        if (!string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionAvailableVersion))
        {
            parts.Add($"Available version: {settings.BitwardenBrowserExtensionAvailableVersion}.");
        }
        if (!string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionLastUpdateError))
        {
            parts.Add($"Last update error: {settings.BitwardenBrowserExtensionLastUpdateError}.");
        }

        BitwardenBrowserExtensionStatus = string.Join(" ", parts);
    }

    private static async Task<string?> PickBitwardenExtensionZipAsync()
    {
        var hwnd = App.Current.MainWindow?.GetHwnd() ?? IntPtr.Zero;
        if (hwnd == IntPtr.Zero) throw new InvalidOperationException("No active window to host the file picker.");

        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.Downloads,
        };
        picker.FileTypeFilter.Add(".zip");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
        var file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    private static async Task<string?> PickBitwardenExtensionFolderAsync()
    {
        var hwnd = App.Current.MainWindow?.GetHwnd() ?? IntPtr.Zero;
        if (hwnd == IntPtr.Zero) throw new InvalidOperationException("No active window to host the folder picker.");

        var picker = new FolderPicker
        {
            SuggestedStartLocation = PickerLocationId.Downloads,
        };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
        var folder = await picker.PickSingleFolderAsync();
        return folder?.Path;
    }

    // === App authentication ==============================================

    partial void OnAppAuthenticationModeIndexChanged(int value)
    {
        if (_suppressSecurityChanges) return;
        _ = ChangeAppAuthenticationModeAsync(value);
    }

    partial void OnAppAuthenticationHelloFallbackIndexChanged(int value)
    {
        if (_suppressSecurityChanges) return;
        _ = ChangeHelloFallbackAsync(value);
    }

    partial void OnAppAuthenticationIdleTimeoutIndexChanged(int value)
    {
        if (_suppressSecurityChanges) return;
        _ = ChangeIdleTimeoutAsync(value);
    }

    private async Task ChangeAppAuthenticationModeAsync(int value)
    {
        if (value is < 0 or > 3)
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        var oldMode = _settingsService.Current.AppAuthenticationMode;
        var newMode = (AppAuthenticationMode)value;
        if (oldMode == newMode) return;

        if (!await RequireCurrentAuthenticationAsync("Confirm security change").ConfigureAwait(true))
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        if (newMode == AppAuthenticationMode.Disabled)
        {
            await _appAuthentication.DeleteAllAsync().ConfigureAwait(true);
            _settingsService.Current.AppAuthenticationMode = AppAuthenticationMode.Disabled;
            _settingsService.Save();
            await RefreshSecurityStatusAsync().ConfigureAwait(true);
            return;
        }

        var requiredSecret = newMode == AppAuthenticationMode.WindowsHello
            ? await ResolveWindowsHelloFallbackAsync().ConfigureAwait(true)
            : RequiredSecretForMode(newMode, _settingsService.Current.AppAuthenticationHelloFallback);

        if (!await EnsureSecretConfiguredAsync(requiredSecret).ConfigureAwait(true))
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        _settingsService.Current.AppAuthenticationMode = newMode;
        if (newMode == AppAuthenticationMode.WindowsHello)
        {
            _settingsService.Current.AppAuthenticationHelloFallback = requiredSecret;
        }
        _settingsService.Current.AppAuthenticationIdleTimeoutMinutes ??= 15;
        _settingsService.Save();
        SetSecurityIndexesFromSettings();
        await RefreshSecurityStatusAsync().ConfigureAwait(true);
    }

    private async Task ChangeHelloFallbackAsync(int value)
    {
        if (value is < 0 or > 1)
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        var fallback = (AppAuthenticationFallbackMethod)value;
        if (_settingsService.Current.AppAuthenticationHelloFallback == fallback) return;

        if (!await RequireCurrentAuthenticationAsync("Confirm fallback change").ConfigureAwait(true))
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        if (!await EnsureSecretConfiguredAsync(fallback).ConfigureAwait(true))
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        _settingsService.Current.AppAuthenticationHelloFallback = fallback;
        _settingsService.Save();
        SetSecurityIndexesFromSettings();
        await RefreshSecurityStatusAsync().ConfigureAwait(true);
    }

    private async Task ChangeIdleTimeoutAsync(int value)
    {
        if (value < 0 || value >= IdleTimeoutOptions.Length)
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        var minutes = TimeoutIndexToMinutes(value);
        if (_settingsService.Current.AppAuthenticationIdleTimeoutMinutes == minutes) return;

        if (_settingsService.Current.AppAuthenticationMode != AppAuthenticationMode.Disabled &&
            !await RequireCurrentAuthenticationAsync("Confirm timeout change").ConfigureAwait(true))
        {
            SetSecurityIndexesFromSettings();
            return;
        }

        _settingsService.Current.AppAuthenticationIdleTimeoutMinutes = minutes;
        _settingsService.Save();
        SetSecurityIndexesFromSettings();
        await RefreshSecurityStatusAsync().ConfigureAwait(true);
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SetOrChangeAppAuthenticationSecretAsync()
    {
        if (AppAuthenticationModeIndex == 0) return;

        var method = SelectedSecretMethod();
        if (!await RequireCurrentAuthenticationAsync($"Confirm {SecretActionLabel(method)} change").ConfigureAwait(true)) return;
        if (!await PromptAndStoreSecretAsync(method).ConfigureAwait(true)) return;

        if (_settingsService.Current.AppAuthenticationMode == AppAuthenticationMode.Disabled)
        {
            _settingsService.Current.AppAuthenticationMode = method == AppAuthenticationFallbackMethod.Password
                ? AppAuthenticationMode.Password
                : AppAuthenticationMode.Pin;
            _settingsService.Current.AppAuthenticationIdleTimeoutMinutes ??= 15;
        }
        _settingsService.Save();
        SetSecurityIndexesFromSettings();
        await RefreshSecurityStatusAsync().ConfigureAwait(true);
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task TestAppAuthenticationAsync()
    {
        var mode = _settingsService.Current.AppAuthenticationMode;
        if (mode == AppAuthenticationMode.Disabled)
        {
            await _dialog.ShowMessageAsync("App authentication", "App authentication is disabled.");
            return;
        }

        var result = await VerifyConfiguredAuthenticationAsync("Test app authentication").ConfigureAwait(true);
        await _dialog.ShowMessageAsync(
            result ? "Authentication succeeded" : "Authentication failed",
            result ? "Wormhole accepted the configured unlock method." : "Wormhole could not verify the unlock method.");
    }

    [RelayCommand]
    private async Task RefreshWindowsHelloStatusAsync()
    {
        var availability = await _windowsHello.CheckAvailabilityAsync().ConfigureAwait(true);
        WindowsHelloStatus = availability.Message;
    }

    private async Task RefreshSecurityStatusAsync()
    {
        try
        {
            var status = await _appAuthentication.GetStatusAsync().ConfigureAwait(true);
            var parts = new List<string>
            {
                _settingsService.Current.AppAuthenticationMode == AppAuthenticationMode.Disabled
                    ? "App authentication is disabled."
                    : $"App authentication is enabled ({DisplayMode(_settingsService.Current.AppAuthenticationMode)}).",
                status.HasPin ? "PIN set." : "PIN not set.",
                status.HasPassword ? "Password set." : "Password not set.",
            };
            if (status.IsCorrupted)
            {
                parts.Add("Verifier store is unreadable; set a new PIN or password.");
            }
            AppAuthenticationStatus = string.Join(" ", parts);
            await RefreshWindowsHelloStatusAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to refresh app authentication status.");
            AppAuthenticationStatus = "Could not read app authentication status.";
        }
    }

    private async Task<bool> RequireCurrentAuthenticationAsync(string title)
    {
        var mode = _settingsService.Current.AppAuthenticationMode;
        if (mode == AppAuthenticationMode.Disabled) return true;

        var configured = await _appAuthentication.IsConfiguredForModeAsync(
            mode,
            _settingsService.Current.AppAuthenticationHelloFallback).ConfigureAwait(true);
        if (!configured) return true;

        var ok = await VerifyConfiguredAuthenticationAsync(title).ConfigureAwait(true);
        if (!ok)
        {
            await _dialog.ShowMessageAsync("Authentication required", "The security setting was not changed.");
        }
        return ok;
    }

    private async Task<bool> VerifyConfiguredAuthenticationAsync(string title)
    {
        var ownerHwnd = App.Current.MainWindow?.GetHwnd() ?? IntPtr.Zero;
        var result = await _appAuthenticationVerifier.VerifyAsync(
            _settingsService.Current.AppAuthenticationMode,
            _settingsService.Current.AppAuthenticationHelloFallback,
            ownerHwnd,
            "Unlock Wormhole",
            method => _dialog.PromptSecretAsync(
                title,
                "Confirm your current Wormhole unlock secret.",
                SecretLabel(method),
                "Confirm")).ConfigureAwait(true);
        if (!result.Succeeded && !string.IsNullOrWhiteSpace(result.Message))
        {
            _logger.LogInformation("App authentication verification failed while changing settings: {Message}", result.Message);
        }
        return result.Succeeded;
    }

    private async Task<bool> EnsureSecretConfiguredAsync(AppAuthenticationFallbackMethod method)
    {
        var status = await _appAuthentication.GetStatusAsync().ConfigureAwait(true);
        var hasSecret = HasSecret(status, method);
        return hasSecret || await PromptAndStoreSecretAsync(method).ConfigureAwait(true);
    }

    private async Task<AppAuthenticationFallbackMethod> ResolveWindowsHelloFallbackAsync()
    {
        var fallback = AppAuthenticationHelloFallbackIndex is >= 0 and <= 1
            ? (AppAuthenticationFallbackMethod)AppAuthenticationHelloFallbackIndex
            : _settingsService.Current.AppAuthenticationHelloFallback;

        var status = await _appAuthentication.GetStatusAsync().ConfigureAwait(true);
        if (HasSecret(status, fallback)) return fallback;

        var alternate = fallback == AppAuthenticationFallbackMethod.Pin
            ? AppAuthenticationFallbackMethod.Password
            : AppAuthenticationFallbackMethod.Pin;
        return HasSecret(status, alternate) ? alternate : fallback;
    }

    private async Task<bool> PromptAndStoreSecretAsync(AppAuthenticationFallbackMethod method)
    {
        var label = SecretLabel(method);
        var entered = await _dialog.PromptNewSecretAsync(
            $"Set Wormhole {label.ToLowerInvariant()}",
            SecretRequirementText(method),
            label,
            "Save").ConfigureAwait(true);
        if (entered is null) return false;

        if (entered.Value.Secret != entered.Value.Confirmation)
        {
            await _dialog.ShowMessageAsync("Secret mismatch", $"{label} and confirmation do not match.");
            return false;
        }

        var validation = _appAuthentication.ValidateSecret(method, entered.Value.Secret);
        if (!validation.IsValid)
        {
            await _dialog.ShowMessageAsync($"Invalid {label.ToLowerInvariant()}", validation.Error ?? "The secret is not valid.");
            return false;
        }

        await _appAuthentication.SetSecretAsync(method, entered.Value.Secret).ConfigureAwait(true);
        return true;
    }

    private void SetSecurityIndexesFromSettings()
    {
        _suppressSecurityChanges = true;
        AppAuthenticationModeIndex = (int)_settingsService.Current.AppAuthenticationMode;
        AppAuthenticationHelloFallbackIndex = (int)_settingsService.Current.AppAuthenticationHelloFallback;
        AppAuthenticationIdleTimeoutIndex = TimeoutMinutesToIndex(_settingsService.Current.AppAuthenticationIdleTimeoutMinutes);
        _suppressSecurityChanges = false;
        OnPropertyChanged(nameof(IsAppAuthenticationEnabled));
        OnPropertyChanged(nameof(ShowWindowsHelloFallback));
        OnPropertyChanged(nameof(CanTestAppAuthentication));
        OnPropertyChanged(nameof(CanSetOrChangeAppAuthenticationSecret));
        OnPropertyChanged(nameof(SetOrChangeAppAuthenticationSecretButtonText));
    }

    private static int? TimeoutIndexToMinutes(int index) =>
        index >= 0 && index < IdleTimeoutOptions.Length ? IdleTimeoutOptions[index] : 15;

    public static int TimeoutMinutesToIndex(int? minutes)
    {
        var index = Array.IndexOf(IdleTimeoutOptions, minutes);
        return index >= 0 ? index : 3;
    }

    private static AppAuthenticationFallbackMethod RequiredSecretForMode(
        AppAuthenticationMode mode,
        AppAuthenticationFallbackMethod helloFallback) => mode switch
        {
            AppAuthenticationMode.Password => AppAuthenticationFallbackMethod.Password,
            AppAuthenticationMode.WindowsHello => helloFallback,
            _ => AppAuthenticationFallbackMethod.Pin,
        };

    private AppAuthenticationFallbackMethod SelectedSecretMethod() =>
        AppAuthenticationModeIndex == (int)AppAuthenticationMode.WindowsHello
            ? (AppAuthenticationFallbackMethod)AppAuthenticationHelloFallbackIndex
            : RequiredSecretForMode((AppAuthenticationMode)AppAuthenticationModeIndex, AppAuthenticationFallbackMethod.Pin);

    private static bool HasSecret(AppAuthenticationSecretStatus status, AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin ? status.HasPin : status.HasPassword;

    private static string SecretLabel(AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin ? "PIN" : "Password";

    private static string SecretActionLabel(AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin ? "PIN" : "password";

    private static string SecretRequirementText(AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin
            ? "Choose a 4 to 12 digit PIN."
            : "Choose a password between 8 and 128 characters.";

    private static string DisplayMode(AppAuthenticationMode mode) => mode switch
    {
        AppAuthenticationMode.Pin => "PIN",
        AppAuthenticationMode.Password => "password",
        AppAuthenticationMode.WindowsHello => "Windows Hello",
        _ => "disabled",
    };

    // === MCP server ========================================================

    partial void OnEnableMcpServerChanged(bool value)
    {
        if (_suppressMcpToggle) return;
        _settingsService.Current.EnableMcpServer = value;
        _settingsService.Save();
        _ = ApplyMcpToggleAsync(value);
    }

    partial void OnMcpServerPortChanged(double value)
    {
        // Port only takes effect on the next start; editing is disabled while the server runs.
        var port = (int)value;
        if (port <= 0 || port > 65535) return;
        _settingsService.Current.McpServerPort = port;
        _settingsService.Save();
        UpdateMcpStatus();
    }

    private async Task ApplyMcpToggleAsync(bool enabled)
    {
        try
        {
            if (enabled)
            {
                await _mcpHost.StartAsync();
            }
            else
            {
                await _mcpHost.StopAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to {Action} the MCP server.", enabled ? "start" : "stop");
            await _dialog.ShowMessageAsync(
                enabled ? "Couldn't start MCP server" : "Couldn't stop MCP server",
                ex.Message);
            if (enabled)
            {
                // Revert the toggle without re-triggering this handler.
                _suppressMcpToggle = true;
                EnableMcpServer = false;
                _suppressMcpToggle = false;
                _settingsService.Current.EnableMcpServer = false;
                _settingsService.Save();
            }
        }
        finally
        {
            UpdateMcpStatus();
        }
    }

    private void UpdateMcpStatus()
    {
        McpEndpoint = _mcpHost.EndpointUrl;
        McpStatus = _mcpHost.IsRunning
            ? $"Running — connect an MCP client to {_mcpHost.EndpointUrl}"
            : "Stopped";
    }

    // Keep the copyable config in sync with the endpoint, the revealed token, and the chosen client.
    partial void OnMcpEndpointChanged(string value) => UpdateMcpConfigJson();

    partial void OnMcpTokenChanged(string value) => UpdateMcpConfigJson();

    partial void OnMcpClientIndexChanged(int value) => UpdateMcpConfigJson();

    private enum McpClient { ClaudeCodeCli = 0, ClaudeDesktop = 1, Codex = 2 }

    private void UpdateMcpConfigJson()
    {
        // Show the real token only once revealed; otherwise a placeholder (Copy config always
        // copies the real token).
        var token = string.IsNullOrEmpty(McpToken) ? "<bearer-token — click Reveal or Copy config>" : McpToken;
        var client = (McpClient)McpClientIndex;
        McpConfigJson = BuildConfig(client, McpEndpoint, token);
        (McpConfigLabel, McpConfigCaption) = client switch
        {
            McpClient.ClaudeDesktop => (
                "Claude Desktop config (claude_desktop_config.json)",
                "Claude Desktop only launches stdio servers, so this bridges through mcp-remote (requires Node.js / npx)."),
            McpClient.Codex => (
                "Codex config (~/.codex/config.toml)",
                "Codex speaks Streamable HTTP directly. Add this to ~/.codex/config.toml — note it's TOML, not JSON."),
            _ => (
                "Claude Code config (.mcp.json)",
                "Claude Code speaks Streamable HTTP directly. Add this to .mcp.json (project) or ~/.claude.json."),
        };
    }

    // The server speaks Streamable HTTP. Each client needs a different shape: Claude Code consumes
    // HTTP natively (JSON), Claude Desktop is stdio-only so it bridges via mcp-remote (JSON), and
    // Codex consumes HTTP natively but is configured in TOML.
    private static string BuildConfig(McpClient client, string endpoint, string token) => client switch
    {
        // Claude Desktop is stdio-only → mcp-remote bridge. Two Windows quirks to dodge:
        //  1. A bare "npx" command is resolved by Claude Desktop to its spaced full path
        //     (C:\Program Files\nodejs\npx.cmd) and run unquoted via cmd /C, which breaks at the
        //     space ("'C:\Program' is not recognized"). Invoking through "cmd /c npx ..." sidesteps
        //     it: cmd.exe has no spaces, and the inner cmd resolves the bare "npx" from PATH.
        //  2. Spaces inside args also get mangled, so the bearer header goes through an env var —
        //     mcp-remote substitutes ${WORMHOLE_MCP_TOKEN} and the space lives in the env value,
        //     never on the command line. (mcp-remote's documented Windows workaround.)
        McpClient.ClaudeDesktop =>
            "{\n" +
            "  \"mcpServers\": {\n" +
            "    \"wormhole\": {\n" +
            "      \"command\": \"cmd\",\n" +
            "      \"args\": [\n" +
            "        \"/c\",\n" +
            "        \"npx\",\n" +
            "        \"mcp-remote@latest\",\n" +
            $"        \"{endpoint}\",\n" +
            "        \"--header\",\n" +
            "        \"Authorization:${WORMHOLE_MCP_TOKEN}\"\n" +
            "      ],\n" +
            "      \"env\": {\n" +
            $"        \"WORMHOLE_MCP_TOKEN\": \"Bearer {token}\"\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}",

        // Codex: native Streamable HTTP in TOML with an inline static Authorization header.
        McpClient.Codex =>
            "[mcp_servers.wormhole]\n" +
            $"url = \"{endpoint}\"\n" +
            $"http_headers = {{ Authorization = \"Bearer {token}\" }}\n",

        // Claude Code CLI: native Streamable HTTP JSON.
        _ =>
            "{\n" +
            "  \"mcpServers\": {\n" +
            "    \"wormhole\": {\n" +
            "      \"type\": \"http\",\n" +
            $"      \"url\": \"{endpoint}\",\n" +
            "      \"headers\": {\n" +
            $"        \"Authorization\": \"Bearer {token}\"\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}",
    };

    [RelayCommand]
    private async Task RevealMcpTokenAsync()
    {
        if (IsMcpTokenRevealed)
        {
            IsMcpTokenRevealed = false;
            McpToken = string.Empty;
            return;
        }
        try
        {
            McpToken = await _mcpHost.GetOrCreateTokenAsync();
            IsMcpTokenRevealed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read MCP token.");
            await _dialog.ShowMessageAsync("Couldn't read MCP token", ex.Message);
        }
    }

    [RelayCommand]
    private async Task CopyMcpTokenAsync()
    {
        try
        {
            var token = await _mcpHost.GetOrCreateTokenAsync();
            ClipboardHelper.CopyText(token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to copy MCP token.");
            await _dialog.ShowMessageAsync("Couldn't copy MCP token", ex.Message);
        }
    }

    [RelayCommand]
    private void CopyMcpEndpoint() => ClipboardHelper.CopyText(_mcpHost.EndpointUrl);

    [RelayCommand]
    private async Task CopyMcpConfigAsync()
    {
        try
        {
            // Always copy with the real token so the pasted config works immediately.
            var token = await _mcpHost.GetOrCreateTokenAsync();
            ClipboardHelper.CopyText(BuildConfig((McpClient)McpClientIndex, _mcpHost.EndpointUrl, token));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to copy MCP config.");
            await _dialog.ShowMessageAsync("Couldn't copy MCP config", ex.Message);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RegenerateMcpTokenAsync()
    {
        var confirmed = await _dialog.ConfirmAsync(
            "Regenerate MCP token?",
            "Any MCP client using the current token will stop working until you give it the new token. Continue?",
            "Regenerate", "Cancel");
        if (!confirmed) return;

        try
        {
            McpToken = await _mcpHost.RegenerateTokenAsync();
            IsMcpTokenRevealed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to regenerate MCP token.");
            await _dialog.ShowMessageAsync("Couldn't regenerate MCP token", ex.Message);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ExportBackupAsync()
    {
        try
        {
            await _dialog.PromptForBackupExportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup export dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't export backup", ex.Message);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ImportBackupAsync()
    {
        try
        {
            _ = await _dialog.PromptForBackupImportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup import dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't import backup", ex.Message);
        }

        // Always refresh after the dialog closes. BackupService.ImportAsync is non-transactional
        // — a cancellation midway returns a null Result but may have already persisted credentials,
        // tunnels, and some nodes. Without an unconditional refresh, that partial state stays
        // invisible until the next restart, leaving the UI desynced from the DB.
        try
        {
            await _connectionTree.RefreshAsync();
            await _credentials.LoadCommand.ExecuteAsync(null);
            await _tunnels.LoadCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh views after backup import.");
        }
    }
}
