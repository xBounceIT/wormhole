namespace Wormhole.Models;

public sealed class AppSettings
{
    public const int CurrentSchemaVersion = 8;
    public const int BitwardenOnboardingIntroducedSchemaVersion = 6;

    public int SettingsSchemaVersion { get; set; } = CurrentSchemaVersion;

    public ApplicationTheme Theme { get; set; } = ApplicationTheme.System;
    public bool ConfirmOnTabClose { get; set; } = true;
    public string DefaultSshFont { get; set; } = "Cascadia Mono";
    public int DefaultSshFontSize { get; set; } = 12;
    public bool AutoCopyOnSelect { get; set; } = true;

    public bool AutoCheckForUpdates { get; set; } = true;
    public DateTimeOffset? LastUpdateCheck { get; set; }
    public string? SkippedUpdateVersion { get; set; }
    public int LogRetentionDays { get; set; } = 14;

    public int SidebarWidth { get; set; } = 320;

    public AppAuthenticationMode AppAuthenticationMode { get; set; } = AppAuthenticationMode.Disabled;
    public AppAuthenticationFallbackMethod AppAuthenticationHelloFallback { get; set; } = AppAuthenticationFallbackMethod.Pin;
    public int? AppAuthenticationIdleTimeoutMinutes { get; set; } = 15;

    // When on, a connection configured to use a VPN tunnel asks — at connect time — whether to
    // route through the tunnel or connect directly. For targets that are local on some networks
    // and only reachable over the VPN on others, this avoids editing the connection every time
    // the user moves networks. On by default: legacy settings files are migrated once so
    // previously saved off values become on, while future explicit opt-outs still persist.
    public bool PromptBeforeTunnelConnect { get; set; } = true;

    // In-app MCP server (lets AI agents control already-open SSH sessions). Off by default;
    // the bearer token is stored in Windows Credential Manager, not here.
    public bool EnableMcpServer { get; set; }
    public int McpServerPort { get; set; } = 8765;
    public bool StreamMcpCommandTyping { get; set; } = true;

    // Optional credential vault provider. Password Manager consumer vaults are accessed via
    // the official Bitwarden CLI; Wormhole stores only item references and keeps the CLI
    // session key in memory.
    public bool EnableBitwardenVault { get; set; }
    public string BitwardenCliPath { get; set; } = "bw";
    public BitwardenCliServerRegion BitwardenCliServerRegion { get; set; } =
        BitwardenCliServerRegion.UnitedStates;
    public string BitwardenCliReleasesUrl { get; set; } =
        "repos/bitwarden/clients/releases?per_page=20";
    public string? BitwardenCliVersion { get; set; }
    public string? BitwardenCliSha256 { get; set; }
    public string? BitwardenCliAssetName { get; set; }
    public string? BitwardenCliDownloadUrl { get; set; }
    public string? BitwardenCliInstallStatus { get; set; }
    public string? BitwardenCliInstallError { get; set; }
    public DateTimeOffset? BitwardenCredentialLastSyncUtc { get; set; }
    public string? BitwardenCredentialLastSyncStatus { get; set; }
    public string? BitwardenCredentialLastSyncError { get; set; }
    public int? BitwardenCredentialAvailableCount { get; set; }
    public int BitwardenOnboardingNoticeSeenVersion { get; set; }
    public int BitwardenOnboardingNoticePendingVersion { get; set; }

    // Optional Bitwarden browser extension inside HTTPS WebView2 sessions. This is deliberately
    // separate from the bw CLI credential vault: the browser extension owns its own login/unlock state.
    public bool EnableBitwardenBrowserExtension { get; set; }
    public BitwardenBrowserExtensionSource BitwardenBrowserExtensionSource { get; set; } =
        BitwardenBrowserExtensionSource.OfficialGitHub;
    public string BitwardenBrowserExtensionReleasesUrl { get; set; } =
        "repos/bitwarden/clients/releases?per_page=20";
    public string? BitwardenBrowserExtensionVersion { get; set; }
    public string? BitwardenBrowserExtensionPath { get; set; }
    public string? BitwardenBrowserExtensionSha256 { get; set; }
    public string? BitwardenBrowserExtensionAssetName { get; set; }
    public string? BitwardenBrowserExtensionDownloadUrl { get; set; }
    public DateTimeOffset? BitwardenBrowserExtensionLastUpdateCheckUtc { get; set; }
    public string? BitwardenBrowserExtensionLastUpdateStatus { get; set; }
    public string? BitwardenBrowserExtensionLastUpdateError { get; set; }
    public string? BitwardenBrowserExtensionAvailableVersion { get; set; }
}

public enum ApplicationTheme
{
    System,
    Light,
    Dark,
}

public enum BitwardenBrowserExtensionSource
{
    OfficialGitHub,
    ManualZip,
    ManualFolder,
}

public enum BitwardenCliServerRegion
{
    UnitedStates,
    Europe,
}
