using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services;

public interface IUpdateService
{
    UpdateCheckResult? LatestKnown { get; }

    event EventHandler<UpdateCheckResult>? UpdateAvailable;

    Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken = default);

    Task<string> DownloadInstallerAsync(
        UpdateCheckResult update,
        IProgress<double>? progress,
        CancellationToken cancellationToken = default);

    Task LaunchInstallerAndExitAsync(string installerPath);
}

public interface IInstallerLauncher
{
    void Launch(string installerPath, string arguments);
    void ExitApp();
}
