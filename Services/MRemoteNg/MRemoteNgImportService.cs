using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Extensions.Logging;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.MRemoteNg;

// Orchestrates the four phases of an mRemoteNG import: Inspect (metadata + password-payload
// presence), VerifyPassword (decrypt the "Protected" verifier), Plan (pure transform of
// the XML into the Wormhole shape — node tree + dedup'd credentials + clear-text passwords), and Commit
// (single SQLite transaction + Credential Manager writes with compensating rollback).
public sealed class MRemoteNgImportService : IMRemoteNgImportService
{
    // mRemoteNG writes the literal string "ThisIsProtected" into the root Protected attribute
    // and re-encrypts it with the same password as connection passwords. Decrypting it back
    // to this constant is how we know we have the right password without ever touching the
    // payload connections.
    public const string ProtectedVerifier = "ThisIsProtected";

    // Soft cap on the warnings list so a pathological file (every leaf undecryptable) can't
    // grow it to thousands of strings retained in memory. Anything past this is counted in
    // the Plan/Result's `DroppedWarningCount` so the user-visible summary still tells the truth.
    private const int WarningSoftCap = 50;

    private readonly IConnectionRepository _connectionRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly ICredentialService _credentialService;
    private readonly ISqliteConnectionFactory _sqliteFactory;
    private readonly ILogger<MRemoteNgImportService> _logger;

    public MRemoteNgImportService(
        IConnectionRepository connectionRepository,
        ICredentialRepository credentialRepository,
        ICredentialService credentialService,
        ISqliteConnectionFactory sqliteFactory,
        ILogger<MRemoteNgImportService> logger)
    {
        _connectionRepository = connectionRepository;
        _credentialRepository = credentialRepository;
        _credentialService = credentialService;
        _sqliteFactory = sqliteFactory;
        _logger = logger;
    }

    public Task<MRemoteNgFileInfo> InspectAsync(string path, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Off the dispatcher: even an attribute-only XmlReader scan does sync file I/O, and
        // we don't want a multi-MB export blocking the UI just to discover its KdfIterations.
        return Task.Run(() => InspectCore(path, scanPasswordPayloads: true, cancellationToken), cancellationToken);
    }

    public Task<bool> VerifyPasswordAsync(string path, string password, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // PBKDF2 with 10k+ iterations is hot CPU; combined with the file scan, this used to
        // freeze the UI per password retry. Push the whole verify off the dispatcher.
        return Task.Run(() =>
        {
            var info = InspectCore(path, scanPasswordPayloads: false, cancellationToken);
            EnsureSupportedEncryption(info, requirePasswordDecryption: true);
            if (string.IsNullOrEmpty(info.Protected)) return false;
            return MRemoteNgCrypto.TryDecryptUtf8(info.Protected, password, info.KdfIterations, out var plain)
                && plain == ProtectedVerifier;
        }, cancellationToken);
    }

    // Lightweight metadata reader: captures root attributes and scans Node attributes via
    // XmlReader, never materializing the full node tree. Previously InspectAsync used the
    // same MRemoteNgXmlReader.Parse path as PlanAsync, which forced a full XDocument.Load
    // even when we only needed five attributes — and VerifyPasswordAsync called InspectAsync
    // INTERNALLY, so each password retry did two full parses. This path is ~100x faster on
    // a 300 KB export.
    private static MRemoteNgFileInfo InspectCore(
        string path,
        bool scanPasswordPayloads,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        if (!File.Exists(path)) throw new FileNotFoundException("File not found.", path);

        cancellationToken.ThrowIfCancellationRequested();
        using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            BufferSize = 64 * 1024,
            Options = FileOptions.SequentialScan,
        });
        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null,
            CloseInput = false,
        };
        using var xr = System.Xml.XmlReader.Create(fs, settings);
        try
        {
            // Advance to the first Element node — the document declaration / whitespace are
            // skipped automatically by MoveToContent.
            if (xr.MoveToContent() != System.Xml.XmlNodeType.Element)
            {
                throw new InvalidDataException("XML document has no root element.");
            }
        }
        catch (System.Xml.XmlException ex)
        {
            throw new InvalidDataException("File is not valid XML.", ex);
        }

        if (xr.LocalName != "Connections" || xr.NamespaceURI != "http://mremoteng.org")
        {
            throw new InvalidDataException(
                "Root element is not <mrng:Connections>. This does not look like an mRemoteNG export.");
        }

        var confVersion = xr.GetAttribute("ConfVersion") ?? string.Empty;
        var encryptionEngine = xr.GetAttribute("EncryptionEngine") ?? string.Empty;
        var blockCipherMode = xr.GetAttribute("BlockCipherMode") ?? string.Empty;
        var @protected = xr.GetAttribute("Protected") ?? string.Empty;
        var fullFileEncryption = string.Equals(
            xr.GetAttribute("FullFileEncryption"), "true", StringComparison.OrdinalIgnoreCase);
        var kdfIterationsRaw = xr.GetAttribute("KdfIterations");
        var kdfIterations = int.TryParse(kdfIterationsRaw, out var n) && n > 0 ? n : 1000;
        var hasPasswordPayloads = false;

        if (scanPasswordPayloads)
        {
            try
            {
                while (xr.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (xr.NodeType != System.Xml.XmlNodeType.Element ||
                        !string.Equals(xr.LocalName, "Node", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (PasswordFieldRequiresDecryption(
                            xr.GetAttribute("Password"),
                            AttributeTrue(xr.GetAttribute("InheritPassword"))))
                    {
                        hasPasswordPayloads = true;
                        break;
                    }
                }
            }
            catch (System.Xml.XmlException ex)
            {
                throw new InvalidDataException("File is not valid XML.", ex);
            }
        }

        return new MRemoteNgFileInfo(
            confVersion, encryptionEngine, blockCipherMode, @protected,
            fullFileEncryption, kdfIterations, hasPasswordPayloads);
    }

    public async Task<MRemoteNgImportPlan> PlanAsync(
        string path,
        string password,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report(new MRemoteNgImportProgress(5, "Reading file..."));

        // Push the entire plan phase off the dispatcher. ReadXmlAsync's XDocument.Load is
        // synchronous-after-the-first-await, Walk's tree traversal + per-leaf decryption
        // (PBKDF2-SHA1 with ~10k iterations each) is CPU-bound, and the repo enumerations
        // run sync Dapper queries — combined, a large export can block the UI thread for
        // hundreds of ms. IProgress<T>.Report still marshals back to the dispatcher via the
        // captured SynchronizationContext, so UI updates continue to work.
        return await Task.Run(() => PlanCoreAsync(path, password, progress, cancellationToken),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<MRemoteNgImportPlan> PlanCoreAsync(
        string path,
        string password,
        IProgress<MRemoteNgImportProgress>? progress,
        CancellationToken cancellationToken)
    {
        var (root, rawRoots, hasPasswordPayloads) = ReadXml(path, cancellationToken);
        EnsureSupportedEncryption(new MRemoteNgFileInfo(
            root.ConfVersion, root.EncryptionEngine, root.BlockCipherMode,
            root.Protected, root.FullFileEncryption, root.KdfIterations,
            hasPasswordPayloads), requirePasswordDecryption: hasPasswordPayloads);

        progress?.Report(new MRemoteNgImportProgress(15, "Decrypting passwords..."));
        cancellationToken.ThrowIfCancellationRequested();

        // Build a flat insertion list in DFS top-down order so foreign-key constraints are
        // always satisfied when we INSERT. The walker also accumulates credential dedup,
        // unsupported-protocol counts, and per-leaf decryption warnings via closures below.
        var orderedNodes = new List<ConnectionNode>();
        var credentials = new List<CredentialProfile>();
        var passwordsByCredentialId = new Dictionary<Guid, string>();
        var credentialFingerprints = new Dictionary<string, Guid>(StringComparer.Ordinal);
        var existingCredentialNames = await CollectExistingCredentialNamesAsync(cancellationToken);
        var assignedCredentialNames = new HashSet<string>(existingCredentialNames, StringComparer.Ordinal);

        var skipped = 0;
        var skippedSamples = new List<string>();
        var warnings = new List<string>();
        // Track how many warnings were silently dropped past the soft cap so SummarizeResult
        // can show an honest count instead of implying the cap IS the total.
        var droppedWarningCount = 0;
        var folderCount = 0;
        var connectionCount = 0;

        // Determine next root-level SortOrder so freshly imported top-level folders sit at the
        // bottom of whatever the user already has. Without this, every imported batch overwrites
        // sort positions of existing roots.
        var existingNodes = await _connectionRepository.GetAllAsync(cancellationToken);
        var maxRootSortOrder = -1;
        foreach (var existingNode in existingNodes)
        {
            if (existingNode.ParentId is null && existingNode.SortOrder > maxRootSortOrder)
            {
                maxRootSortOrder = existingNode.SortOrder;
            }
        }
        var rootSortStart = maxRootSortOrder + 1;

        for (var i = 0; i < rawRoots.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Walk(rawRoots[i], parentId: null, sortOrder: rootSortStart + i);
        }

        progress?.Report(new MRemoteNgImportProgress(25,
            $"Planned {folderCount} folders, {connectionCount} connections, {credentials.Count} credentials."));

        return new MRemoteNgImportPlan(
            orderedNodes,
            credentials,
            passwordsByCredentialId,
            folderCount,
            connectionCount,
            skipped,
            skippedSamples,
            warnings,
            droppedWarningCount);

        void Walk(MRemoteNgRawNode raw, Guid? parentId, int sortOrder)
        {
            // Containers and Connections share the same node shape in mRemoteNG and the same
            // shape in Wormhole — a folder can carry Protocol/Host/Username/CredentialId so
            // that Wormhole's InheritanceResolver picks them up when a leaf has them unset.
            // This preserves mRemoteNG's "Inherit*=true on the leaf, real value on the
            // ancestor" semantics: the leaf writes null where Inherit* was set, and the
            // ancestor folder carries the resolved value to inherit.
            var isContainer = string.Equals(raw.Type, "Container", StringComparison.OrdinalIgnoreCase);
            var isConnection = string.Equals(raw.Type, "Connection", StringComparison.OrdinalIgnoreCase);
            if (!isContainer && !isConnection)
            {
                // Unknown node types (rare; defensive). Skip without complaint.
                return;
            }

            // Protocol on a Container is a default for its children; only fail the import for a
            // leaf with an unsupported protocol. Containers with weird Protocol values (or none)
            // map to a folder with Protocol=null. We keep TWO distinct protocol values:
            //   - `protocol`           — written onto the node (null if InheritProtocol)
            //   - `credentialProtocol` — used for credential creation (always the on-disk
            //                            protocol, so a Connection with InheritProtocol=true
            //                            and its own Password still produces a credential).
            ProtocolType? protocol;
            ProtocolType? credentialProtocol;
            if (TryMapProtocol(raw.Protocol, out var mapped))
            {
                protocol = mapped;
                credentialProtocol = mapped;
            }
            else if (isConnection)
            {
                skipped++;
                if (skippedSamples.Count < 5)
                {
                    var label = string.IsNullOrEmpty(raw.Protocol) ? "(unspecified)" : raw.Protocol;
                    skippedSamples.Add($"{raw.Name}: {label}");
                }
                return;
            }
            else
            {
                protocol = null;
                credentialProtocol = null;
            }

            // mRemoteNG's Inherit* attribute set is "this node pulls from its ancestors at
            // runtime"; the on-disk attribute is often a stale local copy. Under Wormhole's
            // null-means-inherit resolver, set the local field to null whenever Inherit* is
            // true so the ancestor's value is used at connect time.
            var username = raw.InheritUsername ? null : NullIfEmpty(raw.Username);
            var domain = raw.InheritDomain ? null : NullIfEmpty(raw.Domain);
            var host = raw.InheritHostname ? null : NullIfEmpty(raw.Hostname);
            var port = raw.InheritPort ? null : ParseIntOrNull(raw.Port);
            var passwordCipher = PasswordFieldRequiresDecryption(raw.PasswordCipher, raw.InheritPassword)
                ? raw.PasswordCipher
                : string.Empty;
            var resolution = raw.InheritResolution ? null : NullIfEmpty(raw.Resolution);
            if (raw.InheritProtocol) protocol = null;

            string? plaintext = null;
            if (!string.IsNullOrEmpty(passwordCipher))
            {
                if (!MRemoteNgCrypto.TryDecryptUtf8(passwordCipher, password, root.KdfIterations, out var decrypted))
                {
                    // Unreadable Password — possible if the user customized the encryption
                    // password mid-export, or the field is corrupt. Treat as no-credential and
                    // surface via Warnings on the result rather than aborting the whole import.
                    _logger.LogWarning("Could not decrypt password for '{Name}' — leaving credential unset.", raw.Name);
                    if (warnings.Count < WarningSoftCap)
                    {
                        var displayName = string.IsNullOrWhiteSpace(raw.Name) ? "(unnamed)" : raw.Name;
                        warnings.Add($"Could not decrypt password for '{displayName}'; credential left unset.");
                    }
                    else
                    {
                        droppedWarningCount++;
                    }
                }
                else if (decrypted.Length > 0)
                {
                    plaintext = decrypted;
                }
            }

            // Credential creation only happens when we have a plaintext to attach. Containers
            // with their own password become folder nodes whose CredentialId points at a real
            // CredentialProfile, so leaves with InheritPassword=true inherit via the resolver.
            // Use `credentialProtocol` (the on-disk protocol) rather than `protocol` (which
            // may be nulled by InheritProtocol) so a Connection leaf with InheritProtocol=true
            // and its own Password still produces a credential rather than silently losing it.
            Guid? credentialId = null;
            if (plaintext is not null && credentialProtocol is { } resolvedCredentialProtocol)
            {
                var fingerprint = string.Join('\0',
                    username ?? string.Empty,
                    domain ?? string.Empty,
                    plaintext,
                    resolvedCredentialProtocol.ToString());
                if (!credentialFingerprints.TryGetValue(fingerprint, out var existingId))
                {
                    var newId = Guid.NewGuid();
                    var name = AllocateCredentialName(
                        username, host ?? raw.Name, resolvedCredentialProtocol, assignedCredentialNames);
                    credentials.Add(new CredentialProfile
                    {
                        Id = newId,
                        Name = name,
                        Username = username,
                        Domain = domain,
                        Kind = CredentialKind.Password,
                        Protocol = resolvedCredentialProtocol,
                        CreatedAt = DateTime.UtcNow,
                    });
                    passwordsByCredentialId[newId] = plaintext;
                    credentialFingerprints[fingerprint] = newId;
                    credentialId = newId;
                }
                else
                {
                    credentialId = existingId;
                }
            }
            else if (plaintext is not null && credentialProtocol is null)
            {
                // The node has a stored password but no on-disk protocol (Container with no
                // Protocol attribute, or a Connection that somehow lost its mapped protocol).
                // We can't create a CredentialProfile without a Protocol value (it's NOT NULL).
                // Branch the message text so a Connection doesn't get reported as a Folder.
                _logger.LogWarning(
                    "{Kind} '{Name}' has a stored password but no protocol; cannot create credential.",
                    isContainer ? "Container" : "Connection", raw.Name);
                if (warnings.Count < WarningSoftCap)
                {
                    var displayName = string.IsNullOrWhiteSpace(raw.Name) ? "(unnamed)" : raw.Name;
                    var nounLabel = isContainer ? "Folder" : "Connection";
                    warnings.Add($"{nounLabel} '{displayName}' had a password but no protocol; password not imported.");
                }
                else
                {
                    droppedWarningCount++;
                }
            }

            var (screenSize, fullScreen) = MapResolution(resolution);
            // When the node is bound to a credential, the credential's Username/Domain win at
            // connect time. We still write the per-node Username/RdpDomain for two reasons:
            // (1) on Folders, the InheritanceResolver pulls from these directly; (2) on
            // Connections without a credential, they're the only source of identity. The
            // earlier code zeroed Username on credential-bound leaves to avoid drift; we now
            // keep it because the resolver tolerates having both — credentials still take
            // precedence at session-open time via SshCredentialResolver/RdpSessionService.

            var node = new ConnectionNode
            {
                Id = Guid.NewGuid(),
                ParentId = parentId,
                Name = string.IsNullOrWhiteSpace(raw.Name)
                    ? (isContainer ? "Folder" : host ?? "Connection")
                    : raw.Name,
                Kind = isContainer ? NodeKind.Folder : NodeKind.Connection,
                SortOrder = sortOrder,
                Protocol = protocol,
                Host = host,
                Port = port,
                Username = username,
                CredentialId = credentialId,
                RdpDomain = (protocol == ProtocolType.Rdp || protocol is null) ? domain : null,
                RdpScreenSize = (protocol == ProtocolType.Rdp || protocol is null) ? screenSize : null,
                RdpFullScreen = (protocol == ProtocolType.Rdp || protocol is null) ? fullScreen : null,
            };
            orderedNodes.Add(node);
            if (isContainer)
            {
                folderCount++;
                var childSort = 0;
                foreach (var child in raw.Children)
                {
                    Walk(child, node.Id, childSort++);
                }
            }
            else
            {
                connectionCount++;
            }
        }
    }

    public async Task<MRemoteNgImportResult> CommitAsync(
        MRemoteNgImportPlan plan,
        IProgress<MRemoteNgImportProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(plan);

        // Carry the plan's parse-time warnings through to the result so the dialog can show
        // them. Mutable copy in case CommitAsync ever needs to append (it doesn't today).
        var warnings = new List<string>(plan.Warnings);
        // Tracks every credential whose secret we wrote to Credential Manager so a failure
        // mid-commit can sweep them back. The DB rolls back via the tx; secrets can't.
        var writtenSecretIds = new List<Guid>();

        try
        {
            // Push the entire commit phase off the dispatcher: Microsoft.Data.Sqlite is sync
            // under the async surface, and CredentialManager.WriteCredential is a sync P/Invoke
            // wrapped in Task.CompletedTask. Without Task.Run the UI thread blocks for the
            // duration of the loop and the Cancel button can't be pressed.
            return await Task.Run(async () =>
            {
                using var connection = _sqliteFactory.Open();
                using var tx = connection.BeginTransaction();

                progress?.Report(new MRemoteNgImportProgress(30, "Saving credentials..."));

                var now = DateTime.UtcNow;
                foreach (var credential in plan.Credentials)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    credential.CreatedAt = now;
                    try
                    {
                        await connection.ExecuteAsync(new CommandDefinition(@"
                            INSERT INTO CredentialProfiles
                                (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, CreatedAt)
                            VALUES
                                (@Id, @Name, @Username, @Domain, @Kind, @PrivateKeyFileName, @Protocol, @CreatedAt);",
                            credential, transaction: tx, cancellationToken: cancellationToken));
                    }
                    catch (Microsoft.Data.Sqlite.SqliteException ex) when (IsUniqueNameViolation(ex))
                    {
                        // Lost a race with another writer that took our credential name between
                        // Plan and Commit. Translate to a friendlier message; the catch below
                        // will roll the tx back and sweep Credential Manager. If a future
                        // migration adds another UNIQUE index, IsUniqueNameViolation requires
                        // the message to mention the Name column explicitly, so this branch
                        // stays specifically about credential-name collisions.
                        throw new InvalidOperationException(
                            $"A credential named '{credential.Name}' already exists. " +
                            "Another window may have created one while the import dialog was open. " +
                            "Close the dialog and try again.", ex);
                    }

                    if (plan.PasswordsByCredentialId.TryGetValue(credential.Id, out var pwd))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        // Record the compensation entry BEFORE attempting the secret write: if
                        // the OS partially persisted the credential and then threw, the catch
                        // sweep needs to be able to find the orphan id.
                        writtenSecretIds.Add(credential.Id);
                        await _credentialService.StorePasswordAsync(credential.Id, pwd);
                    }
                }

                progress?.Report(new MRemoteNgImportProgress(45, "Saving connections..."));

                // Nodes are in DFS top-down order; ParentId FK is satisfied at every step.
                var total = plan.NodesInInsertOrder.Count;
                var i = 0;
                foreach (var node in plan.NodesInInsertOrder)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    node.CreatedAt = now;
                    node.UpdatedAt = now;
                    await connection.ExecuteAsync(new CommandDefinition(@"
                        INSERT INTO Nodes (
                            Id, ParentId, Name, Kind, SortOrder,
                            Protocol, Host, Port, Username, CredentialId,
                            RdpDomain, RdpScreenSize, RdpFullScreen,
                            SshKeyFileName, SshKnownHostFingerprint,
                            TunnelEnabled, TunnelConfigId,
                            CreatedAt, UpdatedAt
                        ) VALUES (
                            @Id, @ParentId, @Name, @Kind, @SortOrder,
                            @Protocol, @Host, @Port, @Username, @CredentialId,
                            @RdpDomain, @RdpScreenSize, @RdpFullScreen,
                            @SshKeyFileName, @SshKnownHostFingerprint,
                            @TunnelEnabled, @TunnelConfigId,
                            @CreatedAt, @UpdatedAt
                        );", node, transaction: tx, cancellationToken: cancellationToken));

                    i++;
                    // Coalesce progress: reporting every node would flood the dispatcher; ~5
                    // keeps the bar smooth without spamming DispatcherQueue.
                    if (total > 0 && (i % 5 == 0 || i == total))
                    {
                        var pct = 45 + (int)((double)i / total * 50);
                        progress?.Report(new MRemoteNgImportProgress(pct, $"Saving connections ({i}/{total})..."));
                    }
                }

                tx.Commit();
                // The DB rows are now durable; anything else that throws below (tx.Dispose
                // edge cases, progress.Report handler exceptions surfacing late, etc.) must
                // NOT trigger the rollback sweep — that would wipe Credential Manager
                // entries for credentials that are already committed in the DB. Clearing
                // the list here makes the catch-block sweep a no-op past this point.
                writtenSecretIds.Clear();
                progress?.Report(new MRemoteNgImportProgress(100, "Import complete."));

                return new MRemoteNgImportResult(
                    FoldersCreated: plan.FolderCount,
                    ConnectionsCreated: plan.ConnectionCount,
                    CredentialsCreated: plan.Credentials.Count,
                    SkippedUnsupportedProtocols: plan.SkippedUnsupportedProtocolCount,
                    Warnings: warnings,
                    DroppedWarningCount: plan.DroppedWarningCount);
            }, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort sweep of Credential Manager entries we wrote before failing. The DB
            // transaction handles its own rollback via the `using`.
            foreach (var id in writtenSecretIds)
            {
                try { await _credentialService.DeletePasswordAsync(id); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to roll back credential {Id} from Credential Manager.", id);
                }
            }
            throw;
        }
    }

    // SQLite returns generic constraint failures with extended code 2067 for UNIQUE; the
    // helper additionally requires the exception message to reference `CredentialProfiles.Name`
    // so that a future migration adding another UNIQUE index (e.g. on Username) won't make
    // us throw a Name-collision message for a totally different column. SQLite emits the
    // qualified column name in the constraint-failure message ("UNIQUE constraint failed:
    // CredentialProfiles.Name").
    private static bool IsUniqueNameViolation(Microsoft.Data.Sqlite.SqliteException ex)
    {
        if (ex.SqliteErrorCode != 19 /* SQLITE_CONSTRAINT */) return false;
        var isUnique = ex.SqliteExtendedErrorCode == 2067 /* CONSTRAINT_UNIQUE */
                       || ex.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase);
        if (!isUnique) return false;
        return ex.Message.Contains("CredentialProfiles.Name", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<IReadOnlyCollection<string>> CollectExistingCredentialNamesAsync(CancellationToken ct)
    {
        var existing = await _credentialRepository.GetAllAsync(ct);
        var names = new List<string>(existing.Count);
        foreach (var credential in existing)
        {
            names.Add(credential.Name);
        }
        return names;
    }

    private static (MRemoteNgRoot Root, IReadOnlyList<MRemoteNgRawNode> Roots, bool HasPasswordPayloads) ReadXml(
        string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        if (!File.Exists(path)) throw new FileNotFoundException("File not found.", path);

        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            BufferSize = 64 * 1024,
            Options = FileOptions.SequentialScan,
        });
        ct.ThrowIfCancellationRequested();
        // XDocument.Load is synchronous. PlanAsync wraps PlanCoreAsync in Task.Run before this
        // is invoked so large imports don't tie up the dispatcher.
        var root = MRemoteNgXmlReader.Parse(stream, out var roots, out var hasPasswordPayloads);
        return (root, roots, hasPasswordPayloads);
    }

    private static void EnsureSupportedEncryption(MRemoteNgFileInfo info, bool requirePasswordDecryption)
    {
        if (info.FullFileEncryption)
        {
            throw new NotSupportedException(
                "This mRemoteNG export uses full-file encryption, which Wormhole's importer doesn't handle yet. " +
                "Re-export with 'Encrypt Connections File' unchecked.");
        }
        if (!requirePasswordDecryption)
        {
            return;
        }
        if (!string.Equals(info.EncryptionEngine, "AES", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException(
                $"Unsupported encryption engine '{info.EncryptionEngine}'. Only AES is supported.");
        }
        if (!string.Equals(info.BlockCipherMode, "GCM", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException(
                $"Unsupported block cipher mode '{info.BlockCipherMode}'. Only GCM is supported. " +
                "Re-export with a recent mRemoteNG version.");
        }
        if (string.IsNullOrEmpty(info.Protected))
        {
            throw new NotSupportedException(
                "This export has no password verifier (Protected attribute). " +
                "Re-export with a recent mRemoteNG version.");
        }
    }

    private static bool PasswordFieldRequiresDecryption(string? passwordCipher, bool inheritPassword) =>
        !inheritPassword && !string.IsNullOrWhiteSpace(passwordCipher);

    private static bool AttributeTrue(string? raw) =>
        string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase);

    private static bool TryMapProtocol(string raw, out ProtocolType protocol)
    {
        var normalized = raw.AsSpan().Trim();
        if (normalized.Equals("SSH", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("SSH1", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("SSH2", StringComparison.OrdinalIgnoreCase))
        {
            protocol = ProtocolType.Ssh;
            return true;
        }

        if (normalized.Equals("RDP", StringComparison.OrdinalIgnoreCase))
        {
            protocol = ProtocolType.Rdp;
            return true;
        }

        protocol = default;
        return false;
    }

    // mRemoteNG `Resolution` values: "FullScreen", "FitToWindow", or "WxH" like "1920x1080".
    // Wormhole's canonical dynamic mode is "Full connection content"; leave null/null only when
    // nothing was set so InheritanceResolver can pull from an ancestor folder.
    private static (string? ScreenSize, bool? FullScreen) MapResolution(string? resolution)
    {
        if (string.IsNullOrWhiteSpace(resolution)) return (null, null);
        if (resolution.Equals("FullScreen", StringComparison.OrdinalIgnoreCase)) return (RdpScreenSizes.FullConnectionContent, true);
        if (resolution.Equals("FitToWindow", StringComparison.OrdinalIgnoreCase)) return (RdpScreenSizes.FullConnectionContent, false);
        return (resolution, false);
    }

    private static string AllocateCredentialName(
        string? username, string anchor, ProtocolType protocol, HashSet<string> taken)
    {
        var user = Sanitize(username);
        var anch = Sanitize(anchor);
        var stem = string.IsNullOrEmpty(user)
            ? $"mremoteng-{anch}-{protocol.ToString().ToLowerInvariant()}"
            : $"mremoteng-{user}@{anch}";
        if (taken.Add(stem)) return stem;
        for (var n = 2; n < int.MaxValue; n++)
        {
            var candidate = $"{stem}-{n}";
            if (taken.Add(candidate)) return candidate;
        }
        // Pathological fallback; the loop above effectively never runs out.
        return $"{stem}-{Guid.NewGuid():N}";
    }

    private static readonly Regex NameSanitizer = new(@"[^A-Za-z0-9._\-]+", RegexOptions.Compiled);

    private static string Sanitize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        var trimmed = input.Trim();
        var sanitized = NameSanitizer.Replace(trimmed, "-").Trim('-');
        return sanitized.Length > 60 ? sanitized[..60] : sanitized;
    }

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    private static int? ParseIntOrNull(string raw) =>
        int.TryParse(raw, out var n) && n > 0 ? n : null;
}
