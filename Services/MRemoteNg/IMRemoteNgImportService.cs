using Wormhole.Models;

namespace Wormhole.Services.MRemoteNg;

public interface IMRemoteNgImportService
{
    Task<MRemoteNgFileInfo> InspectAsync(string path, CancellationToken cancellationToken = default);
    Task<bool> VerifyPasswordAsync(string path, string password, CancellationToken cancellationToken = default);
    Task<MRemoteNgImportPlan> PlanAsync(
        string path,
        string password,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default);
    Task<MRemoteNgImportResult> CommitAsync(
        MRemoteNgImportPlan plan,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default);
}
