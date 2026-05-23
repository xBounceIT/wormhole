namespace Wormhole.Models;

public sealed record MRemoteNgImportResult(
    int FoldersCreated,
    int ConnectionsCreated,
    int CredentialsCreated,
    int SkippedUnsupportedProtocols,
    IReadOnlyList<string> Warnings,
    int DroppedWarningCount = 0);
