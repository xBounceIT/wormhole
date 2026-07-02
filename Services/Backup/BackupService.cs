using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Models.Backup;

namespace Wormhole.Services.Backup;

public sealed class BackupService : IBackupService
{
    // Same iteration count as the mRemoteNG default ceiling on modern hardware — ~250ms on
    // a mid-range desktop. High enough to deter brute-force, low enough that mobile users
    // re-importing don't sit on a spinner.
    private const int Pbkdf2Iterations = 600_000;
    // Upper bound on the iteration count we'll accept from an untrusted file envelope. A
    // hostile or corrupted backup specifying e.g. 2 billion iterations would freeze the
    // background thread for hours inside PBKDF2 with no cancellation point. 5M is ~2s on
    // mid-range desktop hardware — plenty of headroom over the 600k default we write today,
    // and small enough to bail out quickly if someone hands you something pathological.
    private const int Pbkdf2MaxAcceptedIterations = 5_000_000;
    private const int SaltLength = 16;
    private const int NonceLength = 12;   // GCM standard
    private const int KeyLength = 32;     // AES-256
    private const int SecretExportMaxConcurrency = 4;
    private const int BackupFileBufferSize = 128 * 1024;
    // Cap files we open with full deserialization. A real backup of 10k connections is well
    // under 16 MiB even with embedded base64 SSH keys; 64 MiB is a paranoid headroom that
    // still prevents OOM from a hostile gigabyte-scale .json the user might pick by mistake.
    private const long MaxBackupFileBytes = 64L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IConnectionRepository _connectionRepo;
    private readonly ICredentialRepository _credentialRepo;
    private readonly IBitwardenCredentialCacheRepository _bitwardenCacheRepo;
    private readonly ITunnelConfigRepository _tunnelRepo;
    private readonly ICredentialService _credentialService;
    private readonly ILogger<BackupService> _logger;

    public BackupService(
        IConnectionRepository connectionRepo,
        ICredentialRepository credentialRepo,
        ITunnelConfigRepository tunnelRepo,
        ICredentialService credentialService,
        ILogger<BackupService> logger)
        : this(connectionRepo, credentialRepo, NullBitwardenCredentialCacheRepository.Instance, tunnelRepo, credentialService, logger)
    {
    }

    public BackupService(
        IConnectionRepository connectionRepo,
        ICredentialRepository credentialRepo,
        IBitwardenCredentialCacheRepository bitwardenCacheRepo,
        ITunnelConfigRepository tunnelRepo,
        ICredentialService credentialService,
        ILogger<BackupService> logger)
    {
        _connectionRepo = connectionRepo;
        _credentialRepo = credentialRepo;
        _bitwardenCacheRepo = bitwardenCacheRepo;
        _tunnelRepo = tunnelRepo;
        _credentialService = credentialService;
        _logger = logger;
    }

    public async Task<BackupExportResult> ExportAsync(
        string targetPath,
        string? password,
        IProgress<BackupProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

        Report(progress, 5, "Reading metadata...");
        var nodesTask = _connectionRepo.GetAllAsync(cancellationToken);
        var credentialsTask = _credentialRepo.GetAllAsync(cancellationToken);
        var tunnelsTask = _tunnelRepo.GetAllAsync(cancellationToken);
        var bitwardenCacheTask = _bitwardenCacheRepo.GetAllAsync(cancellationToken);
        await Task.WhenAll(nodesTask, credentialsTask, tunnelsTask, bitwardenCacheTask).ConfigureAwait(false);

        var nodes = await nodesTask.ConfigureAwait(false);
        var credentials = await credentialsTask.ConfigureAwait(false);
        var tunnels = await tunnelsTask.ConfigureAwait(false);
        var bitwardenCache = await bitwardenCacheTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var payload = new BackupPayload
        {
            Nodes = AsPayloadList(nodes),
            Credentials = AsPayloadList(credentials),
            Tunnels = AsPayloadList(tunnels),
            BitwardenCredentialCache = AsPayloadList(bitwardenCache),
        };

        // Pull secrets per row. Missing secrets are not an error — a credential row can exist
        // without a stored password yet (e.g. created but never used), and skipping it keeps
        // the export resilient to that state.
        Report(progress, 40, "Reading secrets...");
        await ExportCredentialSecretsAsync(credentials, payload, cancellationToken).ConfigureAwait(false);
        await ExportInlinePasswordSecretsAsync(nodes, payload, cancellationToken).ConfigureAwait(false);
        await ExportTunnelSecretsAsync(tunnels, payload, cancellationToken).ConfigureAwait(false);

        Report(progress, 70, "Serializing...");
        var doc = new BackupDocument
        {
            SchemaVersion = 1,
            App = "Wormhole",
            ExportedAt = DateTimeOffset.UtcNow,
        };

        var encrypt = !string.IsNullOrEmpty(password);
        if (encrypt)
        {
            // Serialize payload to UTF-8 first, then seal. Result envelope carries the KDF
            // parameters needed to re-derive the key on import.
            var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            var sealed_ = SealPayload(payloadBytes, password!);
            doc.Encryption = BackupEncryption.AesGcm;
            doc.EncryptedPayload = sealed_;
            // Clear plaintext payload bytes from heap before they're swept by GC.
            CryptographicOperations.ZeroMemory(payloadBytes);
        }
        else
        {
            doc.Encryption = BackupEncryption.None;
            doc.Payload = payload;
        }

        Report(progress, 90, "Writing file...");
        // File.Create truncates targetPath immediately. If the serialize is cancelled or
        // throws partway, leaving a truncated/empty .json behind would silently overwrite a
        // previous good backup. Write to a sibling .tmp then atomically move into place, and
        // delete the .tmp if anything goes wrong.
        var tempPath = targetPath + ".tmp";
        try
        {
            await using (var stream = CreateBackupWriteStream(tempPath))
            {
                await JsonSerializer.SerializeAsync(stream, doc, JsonOptions, cancellationToken);
            }
            // File.Move with overwrite=true is atomic on the same volume on Windows / .NET 10.
            File.Move(tempPath, targetPath, overwrite: true);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }

        Report(progress, 100, "Export complete.");
        _logger.LogInformation(
            "Backup exported to {Path}: {Nodes} nodes, {Creds} credentials, {Tunnels} tunnels, encrypted={Encrypted}",
            targetPath, payload.Nodes.Count, payload.Credentials.Count, payload.Tunnels.Count, encrypt);

        return new BackupExportResult
        {
            Path = targetPath,
            NodeCount = payload.Nodes.Count,
            CredentialCount = payload.Credentials.Count,
            TunnelCount = payload.Tunnels.Count,
            PasswordCount = payload.Passwords.Count + payload.InlinePasswords.Count,
            PrivateKeyCount = payload.PrivateKeys.Count,
            TunnelPayloadCount = payload.TunnelPayloads.Count,
            Encrypted = encrypt,
        };
    }

    private async Task ExportCredentialSecretsAsync(
        IReadOnlyList<CredentialProfile> credentials,
        BackupPayload payload,
        CancellationToken cancellationToken)
    {
        var passwordEntries = new BackupPasswordEntry?[credentials.Count];
        var keyEntries = new BackupPrivateKeyEntry?[credentials.Count];
        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = SecretExportMaxConcurrency,
        };

        await Parallel.ForAsync(0, credentials.Count, options, async (i, ct) =>
        {
            var cred = credentials[i];
            ct.ThrowIfCancellationRequested();
            if (cred.Kind == CredentialKind.Password)
            {
                if (cred.SecretProvider == CredentialSecretProvider.Bitwarden) return;
                var pwd = await _credentialService.ReadPasswordAsync(cred.Id).ConfigureAwait(false);
                if (pwd is not null)
                {
                    passwordEntries[i] = new BackupPasswordEntry { CredentialId = cred.Id, Password = pwd };
                }
                return;
            }

            if (cred.Kind != CredentialKind.SshKey) return;

            var keyBytes = await _credentialService.ReadPrivateKeyAsync(cred.Id).ConfigureAwait(false);
            if (keyBytes is null) return;
            try
            {
                keyEntries[i] = new BackupPrivateKeyEntry
                {
                    CredentialId = cred.Id,
                    OriginalFileName = cred.PrivateKeyFileName,
                    DataB64 = Convert.ToBase64String(keyBytes),
                };
            }
            finally
            {
                // Zero the decrypted key bytes once they're Base64'd into the payload.
                // The Base64 string copy lives on the managed heap until GC (immutable),
                // but at least the raw key buffer doesn't.
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }).ConfigureAwait(false);

        foreach (var entry in passwordEntries)
        {
            if (entry is not null) payload.Passwords.Add(entry);
        }
        foreach (var entry in keyEntries)
        {
            if (entry is not null) payload.PrivateKeys.Add(entry);
        }
    }

    private async Task ExportInlinePasswordSecretsAsync(
        IReadOnlyList<ConnectionNode> nodes,
        BackupPayload payload,
        CancellationToken cancellationToken)
    {
        var entries = new BackupInlinePasswordEntry?[nodes.Count];
        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = SecretExportMaxConcurrency,
        };

        await Parallel.ForAsync(0, nodes.Count, options, async (i, ct) =>
        {
            var node = nodes[i];
            ct.ThrowIfCancellationRequested();
            if (node.Kind != NodeKind.Connection || node.UseInlinePassword != true) return;

            var pwd = await _credentialService.ReadPasswordAsync(node.Id).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(pwd))
            {
                entries[i] = new BackupInlinePasswordEntry { NodeId = node.Id, Password = pwd };
            }
        }).ConfigureAwait(false);

        foreach (var entry in entries)
        {
            if (entry is not null) payload.InlinePasswords.Add(entry);
        }
    }

    private static List<T> AsPayloadList<T>(IReadOnlyList<T> items)
    {
        if (items is List<T> list) return list;

        var copy = new List<T>(items.Count);
        for (var i = 0; i < items.Count; i++)
        {
            copy.Add(items[i]);
        }
        return copy;
    }

    private async Task ExportTunnelSecretsAsync(
        IReadOnlyList<TunnelConfig> tunnels,
        BackupPayload payload,
        CancellationToken cancellationToken)
    {
        var entries = new BackupTunnelPayloadEntry?[tunnels.Count];
        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = SecretExportMaxConcurrency,
        };

        await Parallel.ForAsync(0, tunnels.Count, options, async (i, ct) =>
        {
            var tunnel = tunnels[i];
            ct.ThrowIfCancellationRequested();
            var configBytes = await _credentialService.ReadTunnelConfigAsync(tunnel.Id).ConfigureAwait(false);
            if (configBytes is null) return;
            try
            {
                entries[i] = new BackupTunnelPayloadEntry
                {
                    TunnelConfigId = tunnel.Id,
                    DataB64 = Convert.ToBase64String(configBytes),
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(configBytes);
            }
        }).ConfigureAwait(false);

        foreach (var entry in entries)
        {
            if (entry is not null) payload.TunnelPayloads.Add(entry);
        }
    }

    public async Task<BackupInspectResult> InspectAsync(
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        EnsureFileSizeAcceptable(sourcePath);
        await using var stream = OpenBackupReadStream(sourcePath);
        var doc = await JsonSerializer.DeserializeAsync<BackupDocument>(stream, JsonOptions, cancellationToken)
                  ?? throw new InvalidDataException("Backup file is empty or malformed.");
        ValidateEncryption(doc.Encryption);
        return new BackupInspectResult
        {
            Encrypted = string.Equals(doc.Encryption, BackupEncryption.AesGcm, StringComparison.OrdinalIgnoreCase),
            SchemaVersion = doc.SchemaVersion,
            ExportedAt = doc.ExportedAt,
        };
    }

    public async Task<BackupImportResult> ImportAsync(
        string sourcePath,
        string? password,
        IProgress<BackupProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        EnsureFileSizeAcceptable(sourcePath);

        Report(progress, 5, "Reading file...");
        BackupDocument doc;
        await using (var stream = OpenBackupReadStream(sourcePath))
        {
            doc = await JsonSerializer.DeserializeAsync<BackupDocument>(stream, JsonOptions, cancellationToken)
                  ?? throw new InvalidDataException("Backup file is empty or malformed.");
        }

        if (doc.SchemaVersion > 1)
        {
            throw new InvalidDataException(
                $"Backup file schema version {doc.SchemaVersion} is newer than this app supports.");
        }

        BackupPayload payload;
        ValidateEncryption(doc.Encryption);
        if (string.Equals(doc.Encryption, BackupEncryption.AesGcm, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(password)) throw new BackupPasswordRequiredException();
            if (doc.EncryptedPayload is null) throw new InvalidDataException("Encrypted backup is missing its sealed payload.");

            Report(progress, 15, "Decrypting...");
            var plaintext = UnsealPayload(doc.EncryptedPayload, password);
            try
            {
                payload = JsonSerializer.Deserialize<BackupPayload>(plaintext, JsonOptions)
                          ?? throw new InvalidDataException("Decrypted payload is empty.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        else
        {
            payload = doc.Payload ?? throw new InvalidDataException("Backup is missing its payload.");
        }

        var result = new BackupImportResult();

        // System.Text.Json overwrites a property's default initializer when the JSON value is
        // explicitly `null`, so a hand-edited backup like `"nodes": null` leaves payload.Nodes
        // as a null reference. Coerce each list field to empty BEFORE filtering — otherwise
        // FilterNullsInPlace would NRE on the null `items.Count` access.
        payload.Credentials ??= new List<CredentialProfile>();
        payload.Tunnels ??= new List<TunnelConfig>();
        payload.BitwardenCredentialCache ??= new List<BitwardenCredentialCacheEntry>();
        payload.Nodes ??= new List<ConnectionNode>();
        payload.Passwords ??= new List<BackupPasswordEntry>();
        payload.InlinePasswords ??= new List<BackupInlinePasswordEntry>();
        payload.PrivateKeys ??= new List<BackupPrivateKeyEntry>();
        payload.TunnelPayloads ??= new List<BackupTunnelPayloadEntry>();

        // Then filter null array elements — STJ admits JSON null as a literal null inside a
        // List<T> even when T is a non-nullable reference type. Counting drops lets us surface
        // a single summary warning rather than scattering them.
        var nullDrops = 0;
        nullDrops += FilterNullsInPlace(payload.Credentials);
        nullDrops += FilterNullsInPlace(payload.Tunnels);
        nullDrops += FilterNullsInPlace(payload.BitwardenCredentialCache);
        nullDrops += FilterNullsInPlace(payload.Nodes);
        nullDrops += FilterNullsInPlace(payload.Passwords);
        nullDrops += FilterNullsInPlace(payload.InlinePasswords);
        nullDrops += FilterNullsInPlace(payload.PrivateKeys);
        nullDrops += FilterNullsInPlace(payload.TunnelPayloads);
        if (nullDrops > 0)
        {
            result.Warnings.Add(
                $"Dropped {nullDrops} null entries from the backup payload (malformed or hand-edited file).");
        }

        // Insert order: credentials first (no FKs), then tunnels (no FKs), then nodes
        // (topological order on ParentId, since the FK is enforced with PRAGMA foreign_keys=ON).

        Report(progress, 25, "Reading existing records...");
        var existingCredentialsTask = _credentialRepo.GetAllAsync(cancellationToken);
        var existingTunnelsTask = _tunnelRepo.GetAllAsync(cancellationToken);
        var existingNodesTask = _connectionRepo.GetAllAsync(cancellationToken);
        var existingBitwardenCacheTask = _bitwardenCacheRepo.GetAllAsync(cancellationToken);
        await Task.WhenAll(existingCredentialsTask, existingTunnelsTask, existingNodesTask, existingBitwardenCacheTask).ConfigureAwait(false);

        Report(progress, 30, "Importing credentials...");
        var existingCredentials = await existingCredentialsTask.ConfigureAwait(false);
        // Track BOTH ids and names: CredentialProfiles.Name has a UNIQUE index, so a backup
        // row whose Id is new but whose Name collides with a locally-renamed credential would
        // fail the FK on AddAsync. Skip-with-warning matches the "merge by ID; never overwrite"
        // policy. StringComparer.Ordinal matches SQLite's default BINARY collation, so we
        // only skip what SQLite would actually reject — Alice and ALICE coexist in the DB and
        // here too.
        var existingCredentialIds = new HashSet<Guid>(existingCredentials.Count);
        // Coerce null defensively here too — the DB schema currently enforces NOT NULL on
        // Name, but if that constraint ever relaxes (or some non-Dapper write bypasses it),
        // ToHashSet under Ordinal would otherwise throw ArgumentNullException at construction.
        var existingCredentialNames = new HashSet<string>(existingCredentials.Count, StringComparer.Ordinal);
        var credentialProvidersById = new Dictionary<Guid, CredentialSecretProvider>(
            existingCredentials.Count + payload.Credentials.Count);
        foreach (var existingCredential in existingCredentials)
        {
            existingCredentialIds.Add(existingCredential.Id);
            existingCredentialNames.Add(existingCredential.Name ?? string.Empty);
            credentialProvidersById[existingCredential.Id] = existingCredential.SecretProvider;
        }
        var insertedCredentialIds = new HashSet<Guid>();
        foreach (var cred in payload.Credentials)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // The DB schema enforces NOT NULL on Name, but a hostile or hand-edited JSON file
            // can deserialize cred.Name to null; HashSet<string>.Contains(null) and .Add(null)
            // throw under the Ordinal comparer. Coerce to empty string here.
            cred.Name ??= string.Empty;
            if (existingCredentialIds.Contains(cred.Id))
            {
                result.CredentialsSkipped++;
                continue;
            }
            if (existingCredentialNames.Contains(cred.Name))
            {
                result.CredentialsSkipped++;
                result.Warnings.Add(
                    $"Credential '{cred.Name}' already exists with a different ID and was skipped.");
                continue;
            }
            await _credentialRepo.AddAsync(cred, cancellationToken);
            // Update the in-loop tracking sets so a backup file containing the same Id or Name
            // twice doesn't blow up on the second insert with a UNIQUE constraint error.
            existingCredentialIds.Add(cred.Id);
            existingCredentialNames.Add(cred.Name);
            credentialProvidersById[cred.Id] = cred.SecretProvider;
            insertedCredentialIds.Add(cred.Id);
            result.CredentialsImported++;
        }

        if (payload.BitwardenCredentialCache.Count > 0)
        {
            await _bitwardenCacheRepo.UpsertImportedAsync(payload.BitwardenCredentialCache, cancellationToken).ConfigureAwait(false);
        }

        Report(progress, 45, "Importing tunnels...");
        var existingTunnels = await existingTunnelsTask.ConfigureAwait(false);
        var existingTunnelIds = new HashSet<Guid>(existingTunnels.Count);
        var existingTunnelNames = new HashSet<string>(existingTunnels.Count, StringComparer.Ordinal);
        foreach (var existingTunnel in existingTunnels)
        {
            existingTunnelIds.Add(existingTunnel.Id);
            existingTunnelNames.Add(existingTunnel.Name ?? string.Empty);
        }
        var insertedTunnelIds = new HashSet<Guid>();
        foreach (var tunnel in payload.Tunnels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            tunnel.Name ??= string.Empty;
            if (existingTunnelIds.Contains(tunnel.Id))
            {
                result.TunnelsSkipped++;
                continue;
            }
            if (existingTunnelNames.Contains(tunnel.Name))
            {
                result.TunnelsSkipped++;
                result.Warnings.Add(
                    $"Tunnel '{tunnel.Name}' already exists with a different ID and was skipped.");
                continue;
            }
            // TunnelConfigRepository.AddAsync stamps CreatedAt/UpdatedAt to UtcNow — accepted
            // tradeoff: preserves "imported on" semantics over "originally created on".
            await _tunnelRepo.AddAsync(tunnel, cancellationToken);
            existingTunnelIds.Add(tunnel.Id);
            existingTunnelNames.Add(tunnel.Name);
            insertedTunnelIds.Add(tunnel.Id);
            result.TunnelsImported++;
        }

        Report(progress, 60, "Importing connections...");
        var existingNodes = await existingNodesTask.ConfigureAwait(false);
        var existingNodeIds = new HashSet<Guid>(existingNodes.Count);
        foreach (var existingNode in existingNodes)
        {
            existingNodeIds.Add(existingNode.Id);
        }
        // Topologically sort by ParentId: a node can be inserted once its parent is null or
        // already present. The backup file's order is whatever GetAllAsync returned at export
        // time (sorted by SortOrder, Name), which is NOT guaranteed to be parent-before-child.
        var ordered = TopologicallyOrderNodes(payload.Nodes, existingNodeIds, result);

        // Build the set of credential/tunnel ids that will satisfy a node's foreign-pointer-
        // shaped fields (CredentialId, RdpGatewayCredentialId, TunnelConfigId). A node whose
        // credential was skipped by name-collision (different local Id, same name) would
        // otherwise import with a dangling pointer that produces "credential not found" at
        // connect time. The schema doesn't enforce these as FKs, so SQLite won't catch it.
        var existingBitwardenCache = await existingBitwardenCacheTask.ConfigureAwait(false);
        var resolvableCredentialIds = new HashSet<Guid>(existingCredentialIds);
        AddBitwardenVirtualCredentialIds(resolvableCredentialIds, existingBitwardenCache);
        AddBitwardenVirtualCredentialIds(resolvableCredentialIds, payload.BitwardenCredentialCache);
        var resolvableTunnelIds = new HashSet<Guid>(existingTunnelIds);
        var nodesById = new Dictionary<Guid, ConnectionNode>(existingNodes.Count + ordered.Count);
        foreach (var existingNode in existingNodes)
        {
            nodesById[existingNode.Id] = existingNode;
        }
        foreach (var node in ordered)
        {
            nodesById.TryAdd(node.Id, node);
        }

        var insertedNodeIds = new HashSet<Guid>();
        foreach (var node in ordered)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (existingNodeIds.Contains(node.Id))
            {
                result.NodesSkipped++;
                continue;
            }
            ScrubDanglingReferences(node, resolvableCredentialIds, resolvableTunnelIds, nodesById, result);
            // AddAsync overwrites CreatedAt/UpdatedAt with UtcNow. The merge-skip semantics
            // mean we never overwrite an existing row, so the original timestamps for older
            // entries are preserved; only freshly-imported entries lose the source timestamps,
            // which is acceptable.
            await _connectionRepo.AddAsync(node, cancellationToken);
            existingNodeIds.Add(node.Id);
            insertedNodeIds.Add(node.Id);
            result.NodesImported++;
        }

        // Secret-restoration policy:
        //   * Just-inserted row (insertedCredentialIds / insertedNodeIds / insertedTunnelIds) → always store.
        //   * Pre-existing row (in the matching existing-id set but NOT just-inserted) → store ONLY if
        //     the existing row has no secret yet. This recovers from a prior partial import that
        //     wrote rows but cancelled/crashed before writing secrets — without it, the user's
        //     second attempt skips the IDs as duplicates and the missing secrets are never
        //     recovered. Never overwrite an existing secret: a user who's changed their password
        //     since the backup was taken must not have it silently rolled back.
        //   * Orphan secret (ID not in DB at all) → skip silently.

        Report(progress, 78, "Restoring passwords...");
        foreach (var entry in payload.Passwords)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (credentialProvidersById.TryGetValue(entry.CredentialId, out var provider) &&
                provider == CredentialSecretProvider.Bitwarden)
            {
                continue;
            }
            if (!await ShouldRestoreSecretAsync(
                    entry.CredentialId, insertedCredentialIds, existingCredentialIds,
                    _credentialService.ReadPasswordAsync, p => p is null)) continue;
            // Hostile JSON can deserialize Password to null even though the property is
            // declared non-nullable; CredentialManager.WriteCredential would NRE on null.
            // Treat null as empty — the credential row still gets a Credential Manager entry,
            // just with an empty password the user must replace.
            await _credentialService.StorePasswordAsync(entry.CredentialId, entry.Password ?? string.Empty);
            result.PasswordsImported++;
        }
        foreach (var entry in payload.InlinePasswords)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!await ShouldRestoreSecretAsync(
                    entry.NodeId, insertedNodeIds, existingNodeIds,
                    _credentialService.ReadPasswordAsync, p => p is null)) continue;
            await _credentialService.StorePasswordAsync(entry.NodeId, entry.Password ?? string.Empty);
            result.PasswordsImported++;
        }

        Report(progress, 87, "Restoring SSH keys...");
        foreach (var entry in payload.PrivateKeys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!await ShouldRestoreSecretAsync(
                    entry.CredentialId, insertedCredentialIds, existingCredentialIds,
                    _credentialService.ReadPrivateKeyAsync,
                    bytes =>
                    {
                        var missing = bytes is null;
                        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
                        return missing;
                    },
                    IsRecoverableSecretReadFailure,
                    ex => result.Warnings.Add(
                        $"Existing private key for credential {entry.CredentialId} could not be read ({ex.GetType().Name}); restoring it from backup."))) continue;
            if (!TryDecodeBase64(entry.DataB64, out var keyBytes))
            {
                result.Warnings.Add($"Private key for credential {entry.CredentialId} was malformed and was skipped.");
                continue;
            }
            try
            {
                await _credentialService.StorePrivateKeyAsync(entry.CredentialId, keyBytes);
                result.PrivateKeysImported++;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        Report(progress, 96, "Restoring tunnel payloads...");
        foreach (var entry in payload.TunnelPayloads)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!await ShouldRestoreSecretAsync(
                    entry.TunnelConfigId, insertedTunnelIds, existingTunnelIds,
                    _credentialService.ReadTunnelConfigAsync,
                    bytes =>
                    {
                        var missing = bytes is null;
                        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
                        return missing;
                    },
                    IsRecoverableSecretReadFailure,
                    ex => result.Warnings.Add(
                        $"Existing tunnel payload for {entry.TunnelConfigId} could not be read ({ex.GetType().Name}); restoring it from backup."))) continue;
            if (!TryDecodeBase64(entry.DataB64, out var configBytes))
            {
                result.Warnings.Add($"Tunnel payload for {entry.TunnelConfigId} was malformed and was skipped.");
                continue;
            }
            try
            {
                await _credentialService.StoreTunnelConfigAsync(entry.TunnelConfigId, configBytes);
                result.TunnelPayloadsImported++;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(configBytes);
            }
        }

        Report(progress, 100, "Import complete.");
        foreach (var warning in result.Warnings)
        {
            _logger.LogWarning("Backup import warning for {Path}: {Warning}", sourcePath, warning);
        }
        _logger.LogInformation(
            "Backup imported from {Path}: nodes={NodesImp}/{NodesSkip} creds={CredsImp}/{CredsSkip} tunnels={TunImp}/{TunSkip}",
            sourcePath,
            result.NodesImported, result.NodesSkipped,
            result.CredentialsImported, result.CredentialsSkipped,
            result.TunnelsImported, result.TunnelsSkipped);
        return result;
    }

    /// <summary>
    /// Returns nodes in an order where every node's <see cref="ConnectionNode.ParentId"/> is
    /// either null, already-existing in the DB, or appears earlier in the returned list. Nodes
    /// whose parent is missing from both the backup and the DB are surfaced as warnings and
    /// dropped (they would otherwise hit the FK and fail the whole import).
    /// </summary>
    private static List<ConnectionNode> TopologicallyOrderNodes(
        List<ConnectionNode> nodes,
        HashSet<Guid> existingNodeIds,
        BackupImportResult result)
    {
        // Use TryAdd instead of ToDictionary so duplicate Ids in the payload don't blow up the
        // whole import. The first occurrence wins; subsequent ones are dropped with a warning
        // because the SQLite PK would reject them anyway.
        var byId = new Dictionary<Guid, ConnectionNode>(nodes.Count);
        foreach (var n in nodes)
        {
            // Coerce null Name — same rationale as the credentials/tunnels loops. Nodes.Name
            // is NOT NULL in the schema, so a null on the C# side would fail AddAsync with a
            // generic SqliteException once we got there.
            n.Name ??= string.Empty;
            if (!byId.TryAdd(n.Id, n))
            {
                result.Warnings.Add($"Duplicate node id {n.Id} in backup; only the first occurrence was imported.");
            }
        }
        var ordered = new List<ConnectionNode>(byId.Count);
        var visited = new HashSet<Guid>(byId.Count);
        var inFlight = new HashSet<Guid>(byId.Count);

        // Depth cap: each Visit frame consumes a portion of the calling thread's stack
        // (default ~1 MB on the WinUI STA). A linear chain of ~10k nodes fits comfortably in
        // a 64 MiB backup but will StackOverflowException long before that — and SOE is
        // unrecoverable, taking the process down. 4096 is well above realistic tree depths
        // (mRemoteNG documents users with at most a few hundred levels) and well below the
        // stack-frame ceiling.
        const int MaxRecursionDepth = 4096;

        // `from` is the recursion's immediate caller: the node whose ParentId points at the
        // current `node`. When we detect that `node` is already in flight (cycle), nulling
        // `from.ParentId` rather than `node.ParentId` is what actually breaks the cycle:
        // `from` is the one that's about to be added to `ordered` AFTER `node`, so it must
        // not retain a forward reference to a row that doesn't exist yet.
        void Visit(ConnectionNode node, ConnectionNode? from, int depth)
        {
            if (depth > MaxRecursionDepth)
            {
                throw new InvalidDataException(
                    $"Backup nesting depth exceeds {MaxRecursionDepth}; refusing to import.");
            }
            if (visited.Contains(node.Id)) return;
            if (!inFlight.Add(node.Id))
            {
                if (from is not null)
                {
                    result.Warnings.Add(
                        $"Cycle detected between '{from.Name}' and '{node.Name}'; " +
                        $"'{from.Name}' imported at root.");
                    from.ParentId = null;
                }
                return;
            }
            // Self-reference (ParentId == Id) is a degenerate cycle the above check would catch
            // only after a stack frame. Handle it directly here for a cleaner warning.
            if (node.ParentId is Guid selfRef && selfRef == node.Id)
            {
                result.Warnings.Add(
                    $"Node '{node.Name}' references itself as parent; imported at root.");
                node.ParentId = null;
            }
            else if (node.ParentId is Guid parentId
                && !existingNodeIds.Contains(parentId)
                && byId.TryGetValue(parentId, out var parent))
            {
                Visit(parent, node, depth + 1);
            }
            else if (node.ParentId is Guid orphan
                     && !existingNodeIds.Contains(orphan)
                     && !byId.ContainsKey(orphan))
            {
                result.Warnings.Add(
                    $"Node '{node.Name}' references unknown parent {orphan}; will be imported at root.");
                node.ParentId = null;
            }
            inFlight.Remove(node.Id);
            visited.Add(node.Id);
            ordered.Add(node);
        }

        foreach (var node in byId.Values) Visit(node, from: null, depth: 0);
        return ordered;
    }

    private static BackupEncryptedPayload SealPayload(byte[] plaintext, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var key = DeriveKey(password, salt);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return new BackupEncryptedPayload
        {
            Kdf = "pbkdf2-sha256",
            Iterations = Pbkdf2Iterations,
            SaltB64 = Convert.ToBase64String(salt),
            NonceB64 = Convert.ToBase64String(nonce),
            CiphertextB64 = Convert.ToBase64String(ciphertext),
            TagB64 = Convert.ToBase64String(tag),
        };
    }

    private static byte[] UnsealPayload(BackupEncryptedPayload sealed_, string password)
    {
        if (!string.Equals(sealed_.Kdf, "pbkdf2-sha256", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Encrypted backup uses an unsupported key derivation function.");
        }

        byte[] salt, nonce, ciphertext, tag;
        try
        {
            salt = Convert.FromBase64String(sealed_.SaltB64);
            nonce = Convert.FromBase64String(sealed_.NonceB64);
            ciphertext = Convert.FromBase64String(sealed_.CiphertextB64);
            tag = Convert.FromBase64String(sealed_.TagB64);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Encrypted backup envelope is malformed.", ex);
        }
        catch (ArgumentNullException ex)
        {
            throw new InvalidDataException("Encrypted backup envelope is malformed.", ex);
        }

        var iterations = sealed_.Iterations > 0 ? sealed_.Iterations : Pbkdf2Iterations;
        if (iterations > Pbkdf2MaxAcceptedIterations)
        {
            // Caller cannot tell wrong-password from "deliberately astronomical iteration
            // count"; surface as the latter so the dialog can show a meaningful message and
            // we don't spin a thread for hours on what may be a hostile file.
            throw new InvalidDataException(
                $"Backup file declares {iterations} PBKDF2 iterations, which exceeds the maximum " +
                $"accepted value ({Pbkdf2MaxAcceptedIterations}). Refusing to decrypt.");
        }
        // Pre-validate envelope geometry: AesGcm's constructor + Decrypt throw ArgumentException
        // (NOT CryptographicException) when nonce/tag lengths fall outside the GCM-spec ranges,
        // so without this check those errors would bubble past our catch and leak a raw
        // ArgumentException message ("tagSizeInBytes must be between 12 and 16...") to the user.
        if (nonce.Length != NonceLength
            || tag.Length is < 12 or > 16
            || salt.Length == 0
            || ciphertext.Length == 0)
        {
            // ciphertext.Length==0 path: an empty ciphertext can decrypt 'successfully' under
            // GCM with a matching empty-tag, yielding an empty plaintext that then fails JSON
            // deserialization with a confusing 'no JSON tokens' error — and even when it
            // fails GCM authentication, it's a useful oracle to a hostile crafter. Reject
            // empty ciphertext outright.
            throw new InvalidDataException(
                "Encrypted backup envelope has malformed nonce, tag, salt, or ciphertext lengths.");
        }
        var key = DeriveKey(password, salt, iterations);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            // GCM auth-tag mismatch — either wrong password or tampered ciphertext. We
            // collapse both into a single error so we don't leak which one happened.
            throw new BackupBadPasswordException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return plaintext;
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations = Pbkdf2Iterations)
    {
        // Normalize to NFC before encoding so that passwords typed via different IMEs / OSes
        // (precomposed vs decomposed accents, etc.) hash the same way across machines. Without
        // this, a backup exported on macOS-NFD and imported on Windows-NFC would fail the GCM
        // tag check with no way to recover.
        var normalized = password.Normalize(NormalizationForm.FormC);
        // Encode into a buffer we own so we can zero it after PBKDF2 returns. The constructor-
        // based Rfc2898DeriveBytes is SYSLIB0060'd in .NET 10; the static Pbkdf2 helper is the
        // documented replacement.
        var passwordBytes = Encoding.UTF8.GetBytes(normalized);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes, salt, iterations, HashAlgorithmName.SHA256, KeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void AddBitwardenVirtualCredentialIds(
        HashSet<Guid> target,
        IEnumerable<BitwardenCredentialCacheEntry> entries)
    {
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.ItemId)) continue;
            Wormhole.Services.Bitwarden.BitwardenVirtualCredentialIds.EnsureIds(entry);
            if (entry.SshCredentialId != Guid.Empty) target.Add(entry.SshCredentialId);
            if (entry.RdpCredentialId != Guid.Empty) target.Add(entry.RdpCredentialId);
            if (entry.VncCredentialId != Guid.Empty) target.Add(entry.VncCredentialId);
        }
    }


    /// <summary>Null out CredentialId / RdpGatewayCredentialId / TunnelConfigId fields that
    /// don't resolve to any row this import will produce. The DB schema doesn't FK-enforce
    /// these pointers, so without scrubbing the connection would import with a dangling
    /// reference that surfaces as a runtime error at connect time.</summary>
    private static void ScrubDanglingReferences(
        ConnectionNode node,
        HashSet<Guid> resolvableCredentialIds,
        HashSet<Guid> resolvableTunnelIds,
        IReadOnlyDictionary<Guid, ConnectionNode> nodesById,
        BackupImportResult result)
    {
        // A protocol value that isn't a defined ProtocolType member can only come from an older
        // backup — SFTP was protocol 2 before it was removed as a standalone session protocol.
        // Migration 0009 reclassifies such rows (2 -> Ssh) in the live DB, but it runs at startup,
        // before an on-demand import, so legacy values would otherwise slip in here and later
        // throw "unknown protocol" on open. Normalize to SSH to match the migration's intent.
        if (node.Protocol is { } protocol && !Enum.IsDefined(protocol))
        {
            result.Warnings.Add(
                $"Node '{node.Name}' uses an unsupported protocol ({(int)protocol}); imported as SSH.");
            node.Protocol = ProtocolType.Ssh;
        }
        if (node.CredentialId is Guid credId && !resolvableCredentialIds.Contains(credId))
        {
            result.Warnings.Add(
                $"Node '{node.Name}' references missing credential {credId}; credential cleared.");
            node.CredentialId = null;
            if (node.CredentialMode != CredentialBindingMode.Inherit)
            {
                node.CredentialMode = CredentialBindingMode.None;
            }
        }
        if (node.RdpGatewayCredentialId is Guid gwCredId && !resolvableCredentialIds.Contains(gwCredId))
        {
            result.Warnings.Add(
                $"Node '{node.Name}' references missing RDP gateway credential {gwCredId}; cleared.");
            node.RdpGatewayCredentialId = null;
        }
        if (node.TunnelConfigId is Guid tunId && !resolvableTunnelIds.Contains(tunId))
        {
            result.Warnings.Add(
                $"Node '{node.Name}' references missing tunnel {tunId}; tunnel cleared.");
            node.TunnelConfigId = null;
        }
        if (node.Kind == NodeKind.Connection)
        {
            var tunnelState = ResolveTunnelImportState(node, nodesById, resolvableTunnelIds);
            if (tunnelState.Enabled && !tunnelState.HasResolvableConfig)
            {
                result.Warnings.Add(
                    $"Node '{node.Name}' had tunneling enabled but no resolvable tunnel config; tunneling disabled.");
                node.TunnelEnabled = false;
            }
        }
    }

    private static (bool Enabled, bool HasResolvableConfig) ResolveTunnelImportState(
        ConnectionNode node,
        IReadOnlyDictionary<Guid, ConnectionNode> nodesById,
        HashSet<Guid> resolvableTunnelIds)
    {
        var current = node;
        var seen = new HashSet<Guid>();
        bool? effectiveTunnelEnabled = null;
        var hasResolvableTunnelConfig = false;

        while (seen.Add(current.Id))
        {
            effectiveTunnelEnabled ??= current.TunnelEnabled;
            if (current.TunnelConfigId is Guid tunId && resolvableTunnelIds.Contains(tunId))
            {
                hasResolvableTunnelConfig = true;
                break;
            }

            if (current.ParentId is not Guid parentId) break;
            if (!nodesById.TryGetValue(parentId, out current)) break;
        }

        return (effectiveTunnelEnabled.GetValueOrDefault(), hasResolvableTunnelConfig);
    }

    /// <summary>
    /// Decide whether to write a secret for <paramref name="id"/>. Always restore for
    /// just-inserted rows. For pre-existing rows, restore only when no secret currently exists
    /// (recovery from partial import). For unknown ids, skip. The <paramref name="isMissing"/>
    /// predicate is responsible for inspecting (and, for byte buffers, zeroing) the value
    /// returned by <paramref name="read"/>.
    /// </summary>
    private static async Task<bool> ShouldRestoreSecretAsync<T>(
        Guid id,
        HashSet<Guid> insertedIds,
        HashSet<Guid> existingIds,
        Func<Guid, Task<T?>> read,
        Func<T?, bool> isMissing,
        Func<Exception, bool>? treatReadFailureAsMissing = null,
        Action<Exception>? onReadFailureTreatedAsMissing = null)
    {
        if (insertedIds.Contains(id)) return true;
        if (!existingIds.Contains(id)) return false;
        T? existing;
        try
        {
            existing = await read(id);
        }
        catch (Exception ex) when (treatReadFailureAsMissing?.Invoke(ex) == true)
        {
            onReadFailureTreatedAsMissing?.Invoke(ex);
            return true;
        }
        return isMissing(existing);
    }

    private static bool IsRecoverableSecretReadFailure(Exception ex) => ex is CryptographicException;

    /// <summary>Strip null entries from a list in place and report how many were removed.
    /// System.Text.Json admits null array elements into a `List&lt;T&gt;` even when T is a non-
    /// nullable reference type, so every import loop would otherwise have to null-check its
    /// iteration variable. Removing them here lets the rest of the code dereference freely.</summary>
    private static int FilterNullsInPlace<T>(List<T> items) where T : class
    {
        var dropped = 0;
        for (var i = items.Count - 1; i >= 0; i--)
        {
            if (items[i] is null)
            {
                items.RemoveAt(i);
                dropped++;
            }
        }
        return dropped;
    }

    /// <summary>Decode a Base64 string from an untrusted backup file. Returns false (rather
    /// than throwing) on null/empty/malformed input so the caller can record a per-entry
    /// warning without aborting the whole import.</summary>
    private static bool TryDecodeBase64(string? input, out byte[] bytes)
    {
        if (string.IsNullOrEmpty(input))
        {
            bytes = Array.Empty<byte>();
            return false;
        }
        try
        {
            bytes = Convert.FromBase64String(input);
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { /* best-effort cleanup */ }
        catch (UnauthorizedAccessException) { }
    }

    private static FileStream OpenBackupReadStream(string path) =>
        new(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            BufferSize = BackupFileBufferSize,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        });

    private static FileStream CreateBackupWriteStream(string path) =>
        new(path, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            BufferSize = BackupFileBufferSize,
            Options = FileOptions.Asynchronous,
        });

    private static void EnsureFileSizeAcceptable(string path)
    {
        // Guard against the dialog picker steering us at a multi-GB .json (accidentally or
        // hostilely). System.Text.Json.DeserializeAsync would otherwise materialize the whole
        // tree and OOM the WinUI process. FileInfo.Length is cheap.
        var info = new FileInfo(path);
        if (!info.Exists) return;
        if (info.Length > MaxBackupFileBytes)
        {
            throw new InvalidDataException(
                $"Backup file is {info.Length:N0} bytes; refusing to read anything larger than " +
                $"{MaxBackupFileBytes:N0} bytes.");
        }
    }

    private static void ValidateEncryption(string? encryption)
    {
        if (string.Equals(encryption, BackupEncryption.None, StringComparison.OrdinalIgnoreCase)
            || string.Equals(encryption, BackupEncryption.AesGcm, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidDataException(
            string.IsNullOrEmpty(encryption)
                ? "Backup file is missing its encryption marker."
                : $"Backup file uses unsupported encryption '{encryption}'.");
    }

    private static void Report(IProgress<BackupProgress>? progress, int percent, string status)
    {
        progress?.Report(new BackupProgress { Percent = percent, Status = status });
    }

    private sealed class NullBitwardenCredentialCacheRepository : IBitwardenCredentialCacheRepository
    {
        public static NullBitwardenCredentialCacheRepository Instance { get; } = new();

        public Task<IReadOnlyList<BitwardenCredentialCacheEntry>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<BitwardenCredentialCacheEntry>>(Array.Empty<BitwardenCredentialCacheEntry>());

        public Task ReplaceFromFullSyncAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            DateTimeOffset syncTimeUtc,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UpsertImportedAsync(
            IReadOnlyList<BitwardenCredentialCacheEntry> entries,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
