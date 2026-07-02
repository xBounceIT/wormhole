namespace Wormhole.Models.Backup;

// Top-level file envelope. `Encryption` distinguishes the two on-disk shapes:
//   - "none"    -> `Payload` is the inline plaintext object.
//   - "aes-gcm" -> `Payload` is null and `EncryptedPayload` carries the sealed blob.
// Serialized with System.Text.Json (camelCase via JsonSerializerOptions in BackupService).
public sealed class BackupDocument
{
    public int SchemaVersion { get; set; } = 1;
    public string App { get; set; } = "Wormhole";
    public DateTimeOffset ExportedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Encryption { get; set; } = BackupEncryption.None;

    public BackupPayload? Payload { get; set; }
    public BackupEncryptedPayload? EncryptedPayload { get; set; }
}

public static class BackupEncryption
{
    public const string None = "none";
    public const string AesGcm = "aes-gcm";
}

public sealed class BackupEncryptedPayload
{
    public string Kdf { get; set; } = "pbkdf2-sha256";
    public int Iterations { get; set; }
    public string SaltB64 { get; set; } = string.Empty;
    public string NonceB64 { get; set; } = string.Empty;
    public string CiphertextB64 { get; set; } = string.Empty;
    public string TagB64 { get; set; } = string.Empty;
}

public sealed class BackupPayload
{
    public List<ConnectionNode> Nodes { get; set; } = new();
    public List<CredentialProfile> Credentials { get; set; } = new();
    public List<TunnelConfig> Tunnels { get; set; } = new();
    public List<BitwardenCredentialCacheEntry> BitwardenCredentialCache { get; set; } = new();
    public List<BackupPasswordEntry> Passwords { get; set; } = new();
    public List<BackupInlinePasswordEntry> InlinePasswords { get; set; } = new();
    public List<BackupPrivateKeyEntry> PrivateKeys { get; set; } = new();
    public List<BackupTunnelPayloadEntry> TunnelPayloads { get; set; } = new();
}

public sealed class BackupPasswordEntry
{
    public Guid CredentialId { get; set; }
    public string Password { get; set; } = string.Empty;
}

public sealed class BackupInlinePasswordEntry
{
    public Guid NodeId { get; set; }
    public string Password { get; set; } = string.Empty;
}

public sealed class BackupPrivateKeyEntry
{
    public Guid CredentialId { get; set; }
    public string? OriginalFileName { get; set; }
    public string DataB64 { get; set; } = string.Empty;
}

public sealed class BackupTunnelPayloadEntry
{
    public Guid TunnelConfigId { get; set; }
    public string DataB64 { get; set; } = string.Empty;
}

public sealed class BackupExportResult
{
    public string Path { get; set; } = string.Empty;
    public int NodeCount { get; set; }
    public int CredentialCount { get; set; }
    public int TunnelCount { get; set; }
    public int PasswordCount { get; set; }
    public int PrivateKeyCount { get; set; }
    public int TunnelPayloadCount { get; set; }
    public bool Encrypted { get; set; }
}

// Returned per category so the import dialog can show:
//   "Imported N nodes (M skipped as duplicates)."
public sealed class BackupImportResult
{
    public int NodesImported { get; set; }
    public int NodesSkipped { get; set; }
    public int CredentialsImported { get; set; }
    public int CredentialsSkipped { get; set; }
    public int TunnelsImported { get; set; }
    public int TunnelsSkipped { get; set; }
    public int PasswordsImported { get; set; }
    public int PrivateKeysImported { get; set; }
    public int TunnelPayloadsImported { get; set; }
    public List<string> Warnings { get; set; } = new();
}

// Returned from InspectAsync without decrypting — lets the import dialog decide whether
// to prompt for a password before kicking off the slow PBKDF2 round.
public sealed class BackupInspectResult
{
    public bool Encrypted { get; set; }
    public int SchemaVersion { get; set; }
    public DateTimeOffset ExportedAt { get; set; }
}

public sealed class BackupProgress
{
    public int Percent { get; set; }
    public string Status { get; set; } = string.Empty;
}
