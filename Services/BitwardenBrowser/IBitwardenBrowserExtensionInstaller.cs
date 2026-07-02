namespace Wormhole.Services.BitwardenBrowser;

public interface IBitwardenBrowserExtensionInstaller
{
    BitwardenBrowserExtensionInstall? GetConfiguredInstall();

    Task<BitwardenBrowserExtensionUpdateCheck> CheckForUpdateAsync(
        CancellationToken cancellationToken = default);

    Task<BitwardenBrowserExtensionUpdateResult> UpdateIfAvailableAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<BitwardenBrowserExtensionInstall> InstallLatestAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<BitwardenBrowserExtensionInstall> ImportZipAsync(
        string zipPath,
        CancellationToken cancellationToken = default);

    Task<BitwardenBrowserExtensionInstall> ImportUnpackedAsync(
        string extensionFolderPath,
        CancellationToken cancellationToken = default);
}

public sealed record BitwardenBrowserExtensionInstall(
    string Version,
    string ExtensionPath,
    string? Sha256,
    string? AssetName,
    string? DownloadUrl);

public sealed record BitwardenBrowserExtensionUpdateCheck(
    string? CurrentVersion,
    string LatestVersion,
    bool IsUpdateAvailable,
    string AssetName,
    string DownloadUrl,
    string? ExpectedSha256);

public sealed record BitwardenBrowserExtensionUpdateResult(
    BitwardenBrowserExtensionUpdateCheck Check,
    BitwardenBrowserExtensionInstall? Install,
    bool WasUpdated);

public sealed class BitwardenBrowserExtensionException : Exception
{
    public BitwardenBrowserExtensionException(string message) : base(message) { }

    public BitwardenBrowserExtensionException(string message, Exception innerException) : base(message, innerException) { }
}
