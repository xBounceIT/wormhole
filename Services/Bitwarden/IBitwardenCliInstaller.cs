namespace Wormhole.Services.Bitwarden;

public interface IBitwardenCliInstaller
{
    BitwardenCliInstall? GetConfiguredInstall();

    Task<BitwardenCliInstall> EnsureInstalledAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<BitwardenCliInstall> InstallLatestAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}

public sealed record BitwardenCliInstall(
    string Version,
    string ExecutablePath,
    string? Sha256,
    string? AssetName,
    string? DownloadUrl);

public sealed class BitwardenCliInstallException : Exception
{
    public BitwardenCliInstallException(string message) : base(message) { }

    public BitwardenCliInstallException(string message, Exception innerException) : base(message, innerException) { }
}
