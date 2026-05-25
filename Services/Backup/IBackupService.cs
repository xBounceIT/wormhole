using Wormhole.Models.Backup;

namespace Wormhole.Services.Backup;

public interface IBackupService
{
    /// <summary>
    /// Write every connection / credential / tunnel — including the decrypted secrets — to
    /// <paramref name="targetPath"/> as a JSON file. If <paramref name="password"/> is
    /// non-empty, the payload is AES-GCM encrypted with a PBKDF2-SHA256 derived key.
    /// </summary>
    Task<BackupExportResult> ExportAsync(
        string targetPath,
        string? password,
        IProgress<BackupProgress>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Peek the envelope without decrypting. Lets callers decide whether to prompt for a
    /// password before kicking off the slow PBKDF2 round inside <see cref="ImportAsync"/>.
    /// </summary>
    Task<BackupInspectResult> InspectAsync(
        string sourcePath,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deserialize, decrypt if needed, and merge into the repos / Credential Manager / DPAPI
    /// files. Existing rows with the same Id are skipped (merge-by-ID semantics).
    /// </summary>
    /// <exception cref="BackupPasswordRequiredException">file is encrypted and no password was supplied.</exception>
    /// <exception cref="BackupBadPasswordException">supplied password did not unseal the payload.</exception>
    Task<BackupImportResult> ImportAsync(
        string sourcePath,
        string? password,
        IProgress<BackupProgress>? progress = null,
        CancellationToken cancellationToken = default);
}

public sealed class BackupPasswordRequiredException : Exception
{
    public BackupPasswordRequiredException() : base("Backup file is encrypted; password required.") { }
}

public sealed class BackupBadPasswordException : Exception
{
    public BackupBadPasswordException() : base("Backup password is incorrect or the file is corrupt.") { }
}
