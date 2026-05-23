namespace Wormhole.Models;

public sealed record MRemoteNgImportPlan(
    IReadOnlyList<ConnectionNode> NodesInInsertOrder,
    IReadOnlyList<CredentialProfile> Credentials,
    IReadOnlyDictionary<Guid, string> PasswordsByCredentialId,
    int FolderCount,
    int ConnectionCount,
    int SkippedUnsupportedProtocolCount,
    IReadOnlyList<string> SkippedProtocolSamples,
    IReadOnlyList<string> Warnings,
    int DroppedWarningCount);
