using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services.Backup;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BackupServiceTests : IDisposable
{
    // Mirrors the production migrations 0001-0006 plus the tunnel-config schema. Inlined
    // because the test project links sources but can't reach the main assembly's embedded
    // migration resources.
    private const string SchemaSql = @"
        CREATE TABLE Nodes (
            Id                       TEXT     PRIMARY KEY NOT NULL,
            ParentId                 TEXT     NULL REFERENCES Nodes(Id) ON DELETE CASCADE,
            Name                     TEXT     NOT NULL,
            Kind                     INTEGER  NOT NULL,
            SortOrder                INTEGER  NOT NULL DEFAULT 0,
            Protocol                 INTEGER  NULL,
            Host                     TEXT     NULL,
            Port                     INTEGER  NULL,
            Username                 TEXT     NULL,
            CredentialId             TEXT     NULL,
            UseInlinePassword        INTEGER  NULL,
            RdpDomain                TEXT     NULL,
            RdpScreenSize            TEXT     NULL,
            RdpFullScreen            INTEGER  NULL,
            RdpColorDepth            INTEGER  NULL,
            RdpUseAllMonitors        INTEGER  NULL,
            RdpAudioMode             INTEGER  NULL,
            RdpAudioCaptureMode      INTEGER  NULL,
            RdpKeyboardHookMode      INTEGER  NULL,
            RdpRedirectClipboard     INTEGER  NULL,
            RdpRedirectPrinters      INTEGER  NULL,
            RdpRedirectSmartCards    INTEGER  NULL,
            RdpRedirectPorts         INTEGER  NULL,
            RdpRedirectDevices       INTEGER  NULL,
            RdpRedirectDrives        TEXT     NULL,
            RdpConnectionSpeed       INTEGER  NULL,
            RdpDesktopBackground     INTEGER  NULL,
            RdpFontSmoothing         INTEGER  NULL,
            RdpDesktopComposition    INTEGER  NULL,
            RdpWindowDrag            INTEGER  NULL,
            RdpMenuAnimation         INTEGER  NULL,
            RdpVisualStyles          INTEGER  NULL,
            RdpBitmapCaching         INTEGER  NULL,
            RdpAutoReconnect         INTEGER  NULL,
            RdpServerAuthentication  INTEGER  NULL,
            RdpGatewayUsageMethod    INTEGER  NULL,
            RdpGatewayHostname       TEXT     NULL,
            RdpGatewayCredentialId   TEXT     NULL,
            RdpGatewayBypassLocal    INTEGER  NULL,
            RdpGatewayUseSameCreds   INTEGER  NULL,
            RdpUseExternalClient     INTEGER  NULL,
            SshKeyFileName           TEXT     NULL,
            SshKnownHostFingerprint  TEXT     NULL,
            SshAutoSudo              INTEGER  NULL,
            HttpIgnoreCertErrors     INTEGER  NULL,
            TunnelEnabled            INTEGER  NULL,
            TunnelConfigId           TEXT     NULL,
            CreatedAt                TEXT     NOT NULL,
            UpdatedAt                TEXT     NOT NULL
        );
        CREATE INDEX IX_Nodes_ParentId ON Nodes(ParentId);
        CREATE TABLE CredentialProfiles (
            Id                  TEXT     PRIMARY KEY NOT NULL,
            Name                TEXT     NOT NULL,
            Username            TEXT     NULL,
            Domain              TEXT     NULL,
            Kind                INTEGER  NOT NULL,
            PrivateKeyFileName  TEXT     NULL,
            Protocol            INTEGER  NOT NULL DEFAULT 0,
            CreatedAt           TEXT     NOT NULL
        );
        CREATE UNIQUE INDEX UX_CredentialProfiles_Name ON CredentialProfiles(Name);
        CREATE TABLE TunnelConfigs (
            Id         TEXT     PRIMARY KEY NOT NULL,
            Name       TEXT     NOT NULL,
            Kind       INTEGER  NOT NULL,
            CreatedAt  TEXT     NOT NULL,
            UpdatedAt  TEXT     NOT NULL
        );
        CREATE UNIQUE INDEX UX_TunnelConfigs_Name ON TunnelConfigs(Name);";

    private readonly string _scratchDir;

    public BackupServiceTests()
    {
        SqliteTypeHandlers.Register();
        _scratchDir = Path.Combine(Path.GetTempPath(), "wormhole-backup-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratchDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_scratchDir)) Directory.Delete(_scratchDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    private sealed record Env(
        SqliteConnectionFactory Factory,
        ConnectionRepository Connections,
        CredentialRepository Credentials,
        TunnelConfigRepository Tunnels,
        FakeCredentialService Secrets,
        BackupService Service);

    private async Task<Env> CreateEnvAsync()
    {
        var dbPath = Path.Combine(_scratchDir, $"wormhole-{Guid.NewGuid():N}.db");
        var factory = new SqliteConnectionFactory($"Data Source={dbPath}");
        await new MigrationRunner(
            factory, NullLogger<MigrationRunner>.Instance,
            new List<Migration> { new("0001_initial", SchemaSql) }).RunAsync();

        var connections = new ConnectionRepository(factory);
        var credentials = new CredentialRepository(factory);
        var tunnels = new TunnelConfigRepository(factory);
        var secrets = new FakeCredentialService();
        var service = new BackupService(
            connections, credentials, tunnels, secrets,
            NullLogger<BackupService>.Instance);
        return new Env(factory, connections, credentials, tunnels, secrets, service);
    }

    [Fact]
    public async Task ExportImport_PlainJson_RoundTrips()
    {
        var src = await CreateEnvAsync();
        var (folderId, leafId, credId, sshCredId, tunnelId) = await SeedSampleDataAsync(src);

        var path = Path.Combine(_scratchDir, "plain.json");
        var exportResult = await src.Service.ExportAsync(path, password: null);
        Assert.False(exportResult.Encrypted);
        Assert.Equal(2, exportResult.NodeCount);
        Assert.Equal(2, exportResult.CredentialCount);
        Assert.Equal(1, exportResult.TunnelCount);
        Assert.Equal(1, exportResult.PasswordCount);
        Assert.Equal(1, exportResult.PrivateKeyCount);
        Assert.Equal(1, exportResult.TunnelPayloadCount);

        var dst = await CreateEnvAsync();
        var importResult = await dst.Service.ImportAsync(path, password: null);
        Assert.Equal(2, importResult.NodesImported);
        Assert.Equal(0, importResult.NodesSkipped);
        Assert.Equal(2, importResult.CredentialsImported);
        Assert.Equal(1, importResult.TunnelsImported);

        // Verify bit-identical secrets.
        Assert.Equal("hunter2", dst.Secrets.Passwords[credId]);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, dst.Secrets.PrivateKeys[sshCredId]);
        Assert.Equal(new byte[] { 9, 8, 7 }, dst.Secrets.TunnelConfigs[tunnelId]);

        var dstNodes = await dst.Connections.GetAllAsync();
        Assert.Equal(2, dstNodes.Count);
        var dstLeaf = dstNodes.Single(n => n.Id == leafId);
        Assert.Equal(folderId, dstLeaf.ParentId);
        Assert.Equal("server.example.com", dstLeaf.Host);
    }

    [Fact]
    public async Task ExportImport_Encrypted_RoundTrips()
    {
        var src = await CreateEnvAsync();
        await SeedSampleDataAsync(src);

        var path = Path.Combine(_scratchDir, "encrypted.json");
        var exportResult = await src.Service.ExportAsync(path, password: "correct horse battery");
        Assert.True(exportResult.Encrypted);

        // File should not contain plaintext credential bytes anywhere.
        var fileText = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain("hunter2", fileText);
        Assert.DoesNotContain("server.example.com", fileText);

        var dst = await CreateEnvAsync();
        var importResult = await dst.Service.ImportAsync(path, password: "correct horse battery");
        Assert.Equal(2, importResult.NodesImported);
        Assert.Equal(2, importResult.CredentialsImported);
        Assert.Equal(1, importResult.TunnelsImported);
        Assert.Equal(1, importResult.PasswordsImported);
    }

    [Fact]
    public async Task InspectAsync_ReportsEncryption()
    {
        var src = await CreateEnvAsync();
        await SeedSampleDataAsync(src);

        var plainPath = Path.Combine(_scratchDir, "plain.json");
        await src.Service.ExportAsync(plainPath, null);
        var encPath = Path.Combine(_scratchDir, "encrypted.json");
        await src.Service.ExportAsync(encPath, "pwd");

        Assert.False((await src.Service.InspectAsync(plainPath)).Encrypted);
        Assert.True((await src.Service.InspectAsync(encPath)).Encrypted);
    }

    [Fact]
    public async Task ImportAsync_EncryptedWithoutPassword_ThrowsPasswordRequired()
    {
        var src = await CreateEnvAsync();
        await SeedSampleDataAsync(src);
        var path = Path.Combine(_scratchDir, "needs-password.json");
        await src.Service.ExportAsync(path, "pwd");

        var dst = await CreateEnvAsync();
        await Assert.ThrowsAsync<BackupPasswordRequiredException>(
            () => dst.Service.ImportAsync(path, password: null));

        // No partial DB writes.
        Assert.Empty(await dst.Connections.GetAllAsync());
        Assert.Empty(await dst.Credentials.GetAllAsync());
        Assert.Empty(await dst.Tunnels.GetAllAsync());
    }

    [Fact]
    public async Task ImportAsync_WrongPassword_ThrowsBadPasswordAndDoesNotWriteAnything()
    {
        var src = await CreateEnvAsync();
        await SeedSampleDataAsync(src);
        var path = Path.Combine(_scratchDir, "wrong-password.json");
        await src.Service.ExportAsync(path, "real-password");

        var dst = await CreateEnvAsync();
        await Assert.ThrowsAsync<BackupBadPasswordException>(
            () => dst.Service.ImportAsync(path, password: "wrong-password"));

        Assert.Empty(await dst.Connections.GetAllAsync());
        Assert.Empty(await dst.Credentials.GetAllAsync());
        Assert.Empty(await dst.Tunnels.GetAllAsync());
        Assert.Empty(dst.Secrets.Passwords);
    }

    [Fact]
    public async Task ImportAsync_MergeByIdSkipsDuplicatesAndPreservesExistingSecrets()
    {
        var src = await CreateEnvAsync();
        var (folderId, leafId, credId, _, tunnelId) = await SeedSampleDataAsync(src);

        var path = Path.Combine(_scratchDir, "merge.json");
        await src.Service.ExportAsync(path, null);

        var dst = await CreateEnvAsync();
        // Pre-seed the destination with one credential and one tunnel whose IDs match the
        // exported entries. Pre-seed their secrets too — those secrets must NOT be clobbered
        // by the import, because the user may have rotated their password since the backup
        // was taken.
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = credId,
            Name = "preexisting",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
        });
        await dst.Secrets.StorePasswordAsync(credId, "user-rotated-password");
        await dst.Tunnels.AddAsync(new TunnelConfig { Id = tunnelId, Name = "preexisting-tun" });
        await dst.Secrets.StoreTunnelConfigAsync(tunnelId, new byte[] { 0xAA, 0xBB });

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.CredentialsImported);
        Assert.Equal(1, result.CredentialsSkipped);
        Assert.Equal(0, result.TunnelsImported);
        Assert.Equal(1, result.TunnelsSkipped);
        // Existing secrets must be preserved — no overwrite from the backup.
        Assert.Equal("user-rotated-password", dst.Secrets.Passwords[credId]);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, dst.Secrets.TunnelConfigs[tunnelId]);

        // Pre-existing credential metadata is preserved (no overwrite).
        var preserved = await dst.Credentials.GetByIdAsync(credId);
        Assert.NotNull(preserved);
        Assert.Equal("preexisting", preserved!.Name);
    }

    [Fact]
    public async Task ImportAsync_RestoresMissingSecretsForExistingRowsOnReimport()
    {
        // Simulates a partial-import recovery: a previous import wrote credential and tunnel
        // rows but failed/cancelled before secrets were stored. Re-running import must
        // recover by filling in the missing secrets — without this the user is stuck with
        // useless rows until they manually delete and re-import.
        var src = await CreateEnvAsync();
        var (_, _, credId, sshCredId, tunnelId) = await SeedSampleDataAsync(src);
        var path = Path.Combine(_scratchDir, "recovery.json");
        await src.Service.ExportAsync(path, null);

        var dst = await CreateEnvAsync();
        // Pre-seed only the METADATA rows, not the secrets — mirroring the post-crash state.
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = credId,
            Name = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
        });
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = sshCredId,
            Name = "alice-key",
            Kind = CredentialKind.SshKey,
            Protocol = ProtocolType.Ssh,
            PrivateKeyFileName = "id_ed25519",
        });
        await dst.Tunnels.AddAsync(new TunnelConfig { Id = tunnelId, Name = "office-vpn", Kind = TunnelKind.WireGuard });
        Assert.Empty(dst.Secrets.Passwords);
        Assert.Empty(dst.Secrets.PrivateKeys);
        Assert.Empty(dst.Secrets.TunnelConfigs);

        var result = await dst.Service.ImportAsync(path, null);
        // All three rows are skipped (matched-by-Id) but their missing secrets are recovered.
        Assert.Equal(2, result.CredentialsSkipped);
        Assert.Equal(1, result.TunnelsSkipped);
        Assert.Equal(1, result.PasswordsImported);
        Assert.Equal(1, result.PrivateKeysImported);
        Assert.Equal(1, result.TunnelPayloadsImported);
        Assert.Equal("hunter2", dst.Secrets.Passwords[credId]);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, dst.Secrets.PrivateKeys[sshCredId]);
        Assert.Equal(new byte[] { 9, 8, 7 }, dst.Secrets.TunnelConfigs[tunnelId]);
    }

    [Fact]
    public async Task ImportAsync_RepairsCorruptExistingDpapiSecretsOnReimport()
    {
        // If a DPAPI file exists but cannot be unprotected, treat it as repairable from the
        // backup instead of aborting. This mirrors a real-world corrupt key/tunnel blob.
        var src = await CreateEnvAsync();
        var (_, _, _, sshCredId, tunnelId) = await SeedSampleDataAsync(src);
        var path = Path.Combine(_scratchDir, "corrupt-secret-repair.json");
        await src.Service.ExportAsync(path, null);

        var dst = await CreateEnvAsync();
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = sshCredId,
            Name = "alice-key",
            Kind = CredentialKind.SshKey,
            Protocol = ProtocolType.Ssh,
            PrivateKeyFileName = "id_ed25519",
        });
        await dst.Tunnels.AddAsync(new TunnelConfig { Id = tunnelId, Name = "office-vpn", Kind = TunnelKind.WireGuard });
        dst.Secrets.PrivateKeys[sshCredId] = new byte[] { 0xFF };
        dst.Secrets.TunnelConfigs[tunnelId] = new byte[] { 0xEE };
        dst.Secrets.CorruptPrivateKeyIds.Add(sshCredId);
        dst.Secrets.CorruptTunnelConfigIds.Add(tunnelId);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(1, result.PrivateKeysImported);
        Assert.Equal(1, result.TunnelPayloadsImported);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, await dst.Secrets.ReadPrivateKeyAsync(sshCredId));
        Assert.Equal(new byte[] { 9, 8, 7 }, await dst.Secrets.ReadTunnelConfigAsync(tunnelId));
        Assert.Contains(result.Warnings, w => w.Contains("could not be read", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ImportAsync_DoesNotRestoreSecretWhenOrphanCredentialIdHasNoRow()
    {
        // A backup secret entry whose CredentialId is neither in the DB nor in the import
        // payload (e.g., user hand-edited the JSON, or the original credential row was lost)
        // must NOT be written — there's no row to associate it with.
        var dst = await CreateEnvAsync();
        var orphanId = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [],
                "credentials": [],
                "tunnels": [],
                "passwords": [
                  { "credentialId": "{{orphanId}}", "password": "leaked-secret" }
                ],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "orphan-secret.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(0, result.PasswordsImported);
        Assert.False(dst.Secrets.Passwords.ContainsKey(orphanId));
    }

    [Fact]
    public async Task ImportAsync_NameCollisionUsesBinaryCollationLikeSqlite()
    {
        // SQLite's default BINARY collation on the UNIQUE INDEX makes 'alice' and 'ALICE'
        // distinct rows. Our in-memory skip check must match SQLite's view so we don't
        // over-skip rows the DB would happily accept.
        var src = await CreateEnvAsync();
        await src.Credentials.AddAsync(new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "ALICE",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        });
        var path = Path.Combine(_scratchDir, "case-only-differs.json");
        await src.Service.ExportAsync(path, null);

        var dst = await CreateEnvAsync();
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        });

        var result = await dst.Service.ImportAsync(path, null);
        // 'ALICE' should land alongside 'alice' — SQLite would not raise UNIQUE.
        Assert.Equal(1, result.CredentialsImported);
        Assert.Equal(0, result.CredentialsSkipped);
        Assert.Equal(2, (await dst.Credentials.GetAllAsync()).Count);
    }

    [Fact]
    public async Task ImportAsync_DropsNullArrayElementsWithWarning()
    {
        // System.Text.Json admits JSON null into a List<T> as a literal null reference. Every
        // import loop must tolerate that — the fix filters them up-front and warns once.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [null],
                "credentials": [null, { "id": "{{Guid.NewGuid()}}", "name": "alice", "kind": 0, "protocol": 0, "createdAt": "{{DateTime.UtcNow:O}}" }],
                "tunnels": [null],
                "passwords": [null],
                "privateKeys": [null],
                "tunnelPayloads": [null]
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "null-elements.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.CredentialsImported);
        Assert.Contains(result.Warnings, w => w.Contains("null entries", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ImportAsync_RejectsEmptyCiphertext()
    {
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "aes-gcm",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryptedPayload": {
                "kdf": "pbkdf2-sha256",
                "iterations": 600000,
                "saltB64": "AAAAAAAAAAAAAAAAAAAAAA==",
                "nonceB64": "AAAAAAAAAAAAAAAA",
                "ciphertextB64": "",
                "tagB64": "AAAAAAAAAAAAAAAAAAAAAA=="
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "empty-ciphertext.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, "anything"));
    }

    [Fact]
    public async Task ImportAsync_HandlesNullNodeName()
    {
        // Same scenario as null credential name, but on the Nodes table. Nodes.Name is NOT NULL
        // in the schema, so without the in-loop coerce the import would crash on the FK insert.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  { "id": "{{Guid.NewGuid()}}", "name": null, "kind": 1, "sortOrder": 0, "protocol": 0, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "null-node-name.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.NodesImported);
        var node = (await dst.Connections.GetAllAsync()).Single();
        Assert.Equal(string.Empty, node.Name);
    }

    [Fact]
    public async Task ImportAsync_NormalizesUnsupportedProtocolToSsh()
    {
        // A backup written by an older build serialized SFTP connections as protocol 2 (the enum
        // value before SFTP was removed as a standalone session protocol). Migration 0009 repairs
        // such rows in the live DB, but it runs at startup — before an on-demand import — so the
        // import path must reclassify the value itself; otherwise the node imports as the undefined
        // (ProtocolType)2 and throws "unknown protocol" when opened.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  { "id": "{{Guid.NewGuid()}}", "name": "legacy-sftp", "kind": 1, "sortOrder": 0, "protocol": 2, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "legacy-sftp-protocol.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(1, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("unsupported protocol", StringComparison.OrdinalIgnoreCase));
        var node = (await dst.Connections.GetAllAsync()).Single();
        Assert.Equal(ProtocolType.Ssh, node.Protocol);
    }

    [Fact]
    public async Task ImportAsync_BreaksParentChildCycleByRerooting()
    {
        // Two nodes A and B with A.ParentId=B and B.ParentId=A. The topological pass must
        // null one of the ParentIds so AddAsync doesn't hit an FK violation. Without the fix,
        // ordered=[B, A] is inserted and B's reference to A (not yet present) trips the FK.
        var dst = await CreateEnvAsync();
        var aId = Guid.NewGuid();
        var bId = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  { "id": "{{aId}}", "parentId": "{{bId}}", "name": "A", "kind": 1, "sortOrder": 0, "protocol": 0, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" },
                  { "id": "{{bId}}", "parentId": "{{aId}}", "name": "B", "kind": 1, "sortOrder": 1, "protocol": 0, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "cycle.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(2, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("Cycle", StringComparison.OrdinalIgnoreCase));
        // At least one of the two must have had its ParentId nulled; the other can still
        // reference its now-inserted partner.
        var nodes = (await dst.Connections.GetAllAsync()).ToList();
        Assert.Equal(2, nodes.Count);
        Assert.Contains(nodes, n => n.ParentId is null);
    }

    [Fact]
    public async Task ImportAsync_HandlesDuplicateNodeIdsInPayload()
    {
        // Two node entries with the same Id. ToDictionary would have crashed; the TryAdd
        // path must accept the first and warn about the second.
        var dst = await CreateEnvAsync();
        var sharedId = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  { "id": "{{sharedId}}", "name": "first", "kind": 1, "sortOrder": 0, "protocol": 0, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" },
                  { "id": "{{sharedId}}", "name": "second", "kind": 1, "sortOrder": 1, "protocol": 0, "host": "h", "port": 22, "createdAt": "{{DateTime.UtcNow:O}}", "updatedAt": "{{DateTime.UtcNow:O}}" }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "dup-node-id.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("Duplicate node id", StringComparison.OrdinalIgnoreCase));
        Assert.Single(await dst.Connections.GetAllAsync());
    }

    [Fact]
    public async Task ImportAsync_HandlesNullCredentialName()
    {
        // Hostile/hand-edited JSON with "name": null. HashSet<string>.Contains(null) under
        // Ordinal comparer throws ArgumentNullException — the null-coerce guard must skip-or-empty.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [],
                "credentials": [
                  { "id": "{{Guid.NewGuid()}}", "name": null, "kind": 0, "protocol": 0, "createdAt": "{{DateTime.UtcNow:O}}" }
                ],
                "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "null-name.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        // Must not throw ArgumentNullException — coerced name is acceptable.
        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.CredentialsImported);
    }

    [Fact]
    public async Task ImportAsync_RejectsMalformedEnvelopeShape()
    {
        // Encrypted envelope with a 2-byte tag — AesGcm's constructor throws ArgumentException
        // (NOT CryptographicException), so without our explicit length pre-check the raw
        // exception message would leak to the user.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "aes-gcm",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryptedPayload": {
                "kdf": "pbkdf2-sha256",
                "iterations": 600000,
                "saltB64": "AAAAAAAAAAAAAAAAAAAAAA==",
                "nonceB64": "AAAAAAAAAAAAAAAA",
                "ciphertextB64": "AA==",
                "tagB64": "AAA="
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "bad-tag.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, "anything"));
        Assert.Contains("malformed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ImportAsync_RejectsUnknownEncryptionMarker()
    {
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "future-aead",
              "payload": {
                "nodes": [],
                "credentials": [],
                "tunnels": [],
                "passwords": [],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "unknown-encryption.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, null));
        Assert.Contains("unsupported encryption", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("argon2id")]
    [InlineData(null)]
    public async Task ImportAsync_RejectsUnsupportedOrNullEncryptedKdf(string? kdf)
    {
        var dst = await CreateEnvAsync();
        var kdfJson = kdf is null ? "null" : $"\"{kdf}\"";
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "aes-gcm",
              "encryptedPayload": {
                "kdf": {{kdfJson}},
                "iterations": 600000,
                "saltB64": "AAAAAAAAAAAAAAAAAAAAAA==",
                "nonceB64": "AAAAAAAAAAAAAAAA",
                "ciphertextB64": "AA==",
                "tagB64": "AAAAAAAAAAAAAAAAAAAAAA=="
              }
            }
            """;
        var path = Path.Combine(_scratchDir, $"bad-kdf-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, "anything"));
        Assert.Contains("key derivation", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ImportAsync_RejectsNullEncryptedEnvelopeBase64AsMalformed()
    {
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "aes-gcm",
              "encryptedPayload": {
                "kdf": "pbkdf2-sha256",
                "iterations": 600000,
                "saltB64": null,
                "nonceB64": "AAAAAAAAAAAAAAAA",
                "ciphertextB64": "AA==",
                "tagB64": "AAAAAAAAAAAAAAAAAAAAAA=="
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "null-envelope-field.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, "anything"));
        Assert.Contains("malformed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ImportAsync_SkipsCredentialWhoseNameCollidesWithExisting()
    {
        // CredentialProfiles.Name has a UNIQUE index; a backup credential whose Id is new but
        // whose Name matches a locally-renamed credential must be skipped with a warning, not
        // crash the whole import on the SQLite UNIQUE constraint.
        var src = await CreateEnvAsync();
        var srcCred = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        };
        await src.Credentials.AddAsync(srcCred);
        await src.Secrets.StorePasswordAsync(srcCred.Id, "secret");

        var path = Path.Combine(_scratchDir, "name-collision.json");
        await src.Service.ExportAsync(path, null);

        var dst = await CreateEnvAsync();
        // Different Id, same Name — the existing-by-name check must skip.
        await dst.Credentials.AddAsync(new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        });

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(0, result.CredentialsImported);
        Assert.Equal(1, result.CredentialsSkipped);
        Assert.Contains(result.Warnings, w => w.Contains("alice", StringComparison.OrdinalIgnoreCase));
        // Imported password for a skipped credential must NOT clobber the local credential's
        // (which we never stored a password for).
        Assert.Empty(dst.Secrets.Passwords);
    }

    [Fact]
    public async Task ImportAsync_HandlesDuplicateIdsInPayloadWithoutCrashing()
    {
        // A hand-edited or buggy backup file can contain the same credential Id twice. The
        // in-loop tracking sets must mark the first insert as already-present so the second
        // is skipped instead of hitting a SQLite PK violation.
        var dst = await CreateEnvAsync();
        var sharedId = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "none",
              "payload": {
                "nodes": [],
                "credentials": [
                  { "id": "{{sharedId}}", "name": "alice", "kind": 0, "protocol": 0, "createdAt": "{{DateTime.UtcNow:O}}" },
                  { "id": "{{sharedId}}", "name": "alice-dup", "kind": 0, "protocol": 0, "createdAt": "{{DateTime.UtcNow:O}}" }
                ],
                "tunnels": [],
                "passwords": [],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "dup-ids.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.CredentialsImported);
        Assert.Equal(1, result.CredentialsSkipped);
        Assert.Single(await dst.Credentials.GetAllAsync());
    }

    [Fact]
    public async Task ImportAsync_RejectsAstronomicalPbkdf2Iterations()
    {
        // A hostile or corrupted backup file could specify a multi-billion iteration count
        // intended to spin a thread for hours inside PBKDF2. Reject it cleanly.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "aes-gcm",
              "encryptedPayload": {
                "kdf": "pbkdf2-sha256",
                "iterations": 2000000000,
                "saltB64": "AAAAAAAAAAAAAAAAAAAAAA==",
                "nonceB64": "AAAAAAAAAAAAAAAA",
                "ciphertextB64": "AA==",
                "tagB64": "AAAAAAAAAAAAAAAAAAAAAA=="
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "astronomical.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(path, "anything"));
        Assert.Contains("iteration", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportAsync_FailedExportPreservesPreexistingFile()
    {
        var src = await CreateEnvAsync();
        await SeedSampleDataAsync(src);

        // Exercise the real safety contract: a pre-existing valid backup at targetPath must
        // survive a failed export attempt to the same targetPath. The implementation writes
        // to targetPath + ".tmp" first and then File.Move's atomically over the target, so a
        // failure during the .tmp write must NOT touch the original file.
        var targetPath = Path.Combine(_scratchDir, "atomic-target.json");
        var sentinel = "preexisting good backup content — must not be lost";
        await File.WriteAllTextAsync(targetPath, sentinel);

        // Force the .tmp write to fail by occupying that exact name with a directory.
        // File.Create on a path whose name is already a directory throws UnauthorizedAccessException,
        // which routes through the catch -> TryDelete branch. TryDelete will swallow the failure
        // to remove the directory entry. Crucially, File.Move never runs, so targetPath is
        // never touched.
        var tmpPath = targetPath + ".tmp";
        Directory.CreateDirectory(tmpPath);

        await Assert.ThrowsAnyAsync<Exception>(() => src.Service.ExportAsync(targetPath, null));

        // The original target file must be byte-identical to what we wrote before the failed export.
        Assert.True(File.Exists(targetPath));
        Assert.Equal(sentinel, await File.ReadAllTextAsync(targetPath));
        // The .tmp obstacle (directory) is still there — TryDelete only attempts file removal
        // and silently fails on the directory. The point isn't .tmp cleanup; it's that the
        // pre-existing targetPath wasn't truncated/replaced.
        Assert.True(Directory.Exists(tmpPath));
    }

    [Fact]
    public async Task ImportAsync_HandlesNullListField()
    {
        // Round 4: JSON with `"nodes": null` (explicit null OVERRIDES the default initializer
        // — STJ doesn't preserve `new List<T>()`). The coerce-to-empty in ImportAsync must
        // run BEFORE FilterNullsInPlace would NRE on a null list reference.
        var dst = await CreateEnvAsync();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": null,
                "credentials": null,
                "tunnels": null,
                "passwords": null,
                "privateKeys": null,
                "tunnelPayloads": null
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "null-lists.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        // Should not throw — all the null lists are coerced to empty.
        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(0, result.NodesImported);
        Assert.Equal(0, result.CredentialsImported);
    }

    [Fact]
    public async Task ImportAsync_NullsOutDanglingCredentialAndTunnelRefs()
    {
        // Round 4: a node referencing a credential or tunnel that's neither in the local DB
        // nor in the import payload would otherwise survive with a dangling pointer (the
        // schema doesn't FK-enforce these). Scrub-and-warn.
        var dst = await CreateEnvAsync();
        var missingCred = Guid.NewGuid();
        var missingTun = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  {
                    "id": "{{Guid.NewGuid()}}",
                    "name": "danglesvr",
                    "kind": 1,
                    "sortOrder": 0,
                    "protocol": 0,
                    "host": "h",
                    "port": 22,
                    "credentialId": "{{missingCred}}",
                    "tunnelConfigId": "{{missingTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "dangling-refs.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("missing credential", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Warnings, w => w.Contains("missing tunnel", StringComparison.OrdinalIgnoreCase));
        var node = (await dst.Connections.GetAllAsync()).Single();
        Assert.Null(node.CredentialId);
        Assert.Null(node.TunnelConfigId);
    }

    [Fact]
    public async Task ImportAsync_DisablesTunnelWhenEnabledNodeLosesMissingTunnelConfig()
    {
        var dst = await CreateEnvAsync();
        var nodeId = Guid.NewGuid();
        var missingTun = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  {
                    "id": "{{nodeId}}",
                    "name": "vpn-leaf",
                    "kind": 1,
                    "sortOrder": 0,
                    "protocol": 0,
                    "host": "h",
                    "port": 22,
                    "tunnelEnabled": true,
                    "tunnelConfigId": "{{missingTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "missing-enabled-tunnel.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(1, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("tunneling disabled", StringComparison.OrdinalIgnoreCase));
        var node = (await dst.Connections.GetAllAsync()).Single(n => n.Id == nodeId);
        Assert.Equal(false, node.TunnelEnabled);
        Assert.Null(node.TunnelConfigId);
    }

    [Fact]
    public async Task ImportAsync_KeepsEnabledTunnelWhenAncestorProvidesResolvableConfig()
    {
        var dst = await CreateEnvAsync();
        var folderId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        var inheritedTun = Guid.NewGuid();
        var missingTun = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  {
                    "id": "{{folderId}}",
                    "name": "folder",
                    "kind": 0,
                    "sortOrder": 0,
                    "tunnelConfigId": "{{inheritedTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  },
                  {
                    "id": "{{childId}}",
                    "parentId": "{{folderId}}",
                    "name": "vpn-leaf",
                    "kind": 1,
                    "sortOrder": 1,
                    "protocol": 0,
                    "host": "h",
                    "port": 22,
                    "tunnelEnabled": true,
                    "tunnelConfigId": "{{missingTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "credentials": [],
                "tunnels": [
                  {
                    "id": "{{inheritedTun}}",
                    "name": "parent-vpn",
                    "kind": 0,
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "inherited-enabled-tunnel.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(2, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("missing tunnel", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.Warnings, w => w.Contains("tunneling disabled", StringComparison.OrdinalIgnoreCase));
        var child = (await dst.Connections.GetAllAsync()).Single(n => n.Id == childId);
        Assert.Equal(true, child.TunnelEnabled);
        Assert.Null(child.TunnelConfigId);
    }

    [Fact]
    public async Task ImportAsync_DoesNotDisableFolderWhenChildHasOwnResolvableTunnelConfig()
    {
        // A folder can carry TunnelEnabled=true while a child inherits that enabled state and
        // overrides only the TunnelConfigId. If the folder's own config is missing, do not
        // flip the folder to false: that would disable the child's otherwise-valid override.
        var dst = await CreateEnvAsync();
        var folderId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        var missingFolderTun = Guid.NewGuid();
        var childTun = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  {
                    "id": "{{folderId}}",
                    "name": "folder",
                    "kind": 0,
                    "sortOrder": 0,
                    "tunnelEnabled": true,
                    "tunnelConfigId": "{{missingFolderTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  },
                  {
                    "id": "{{childId}}",
                    "parentId": "{{folderId}}",
                    "name": "vpn-leaf",
                    "kind": 1,
                    "sortOrder": 1,
                    "protocol": 0,
                    "host": "h",
                    "port": 22,
                    "tunnelConfigId": "{{childTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "credentials": [],
                "tunnels": [
                  {
                    "id": "{{childTun}}",
                    "name": "child-vpn",
                    "kind": 0,
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "folder-missing-child-valid-tunnel.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(2, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("missing tunnel", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.Warnings, w => w.Contains("tunneling disabled", StringComparison.OrdinalIgnoreCase));
        var nodes = await dst.Connections.GetAllAsync();
        var folder = nodes.Single(n => n.Id == folderId);
        var child = nodes.Single(n => n.Id == childId);
        Assert.Equal(true, folder.TunnelEnabled);
        Assert.Null(folder.TunnelConfigId);
        Assert.Null(child.TunnelEnabled);
        Assert.Equal(childTun, child.TunnelConfigId);

        var resolved = new InheritanceResolver().Resolve(child, nodes.ToDictionary(n => n.Id));
        Assert.True(resolved.TunnelEnabled);
        Assert.Equal(childTun, resolved.TunnelConfigId);
    }

    [Fact]
    public async Task ImportAsync_DisablesChildWhenInheritedTunnelEnabledHasNoResolvableConfig()
    {
        // If a folder loses its tunnel config and a child inherits only TunnelEnabled=true,
        // the child would otherwise resolve to "enabled but no config" and fail at runtime.
        // Disable the connection node itself while leaving the folder's enablement intact for
        // sibling connections that may provide their own TunnelConfigId override.
        var dst = await CreateEnvAsync();
        var folderId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        var missingFolderTun = Guid.NewGuid();
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [
                  {
                    "id": "{{folderId}}",
                    "name": "folder",
                    "kind": 0,
                    "sortOrder": 0,
                    "tunnelEnabled": true,
                    "tunnelConfigId": "{{missingFolderTun}}",
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  },
                  {
                    "id": "{{childId}}",
                    "parentId": "{{folderId}}",
                    "name": "vpn-leaf",
                    "kind": 1,
                    "sortOrder": 1,
                    "protocol": 0,
                    "host": "h",
                    "port": 22,
                    "createdAt": "{{DateTime.UtcNow:O}}",
                    "updatedAt": "{{DateTime.UtcNow:O}}"
                  }
                ],
                "credentials": [], "tunnels": [], "passwords": [], "privateKeys": [], "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "folder-missing-child-inherits-enabled.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);

        Assert.Equal(2, result.NodesImported);
        Assert.Contains(result.Warnings, w => w.Contains("missing tunnel", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Warnings, w => w.Contains("tunneling disabled", StringComparison.OrdinalIgnoreCase));
        var nodes = await dst.Connections.GetAllAsync();
        var folder = nodes.Single(n => n.Id == folderId);
        var child = nodes.Single(n => n.Id == childId);
        Assert.Equal(true, folder.TunnelEnabled);
        Assert.Null(folder.TunnelConfigId);
        Assert.Equal(false, child.TunnelEnabled);

        var resolved = new InheritanceResolver().Resolve(child, nodes.ToDictionary(n => n.Id));
        Assert.False(resolved.TunnelEnabled);
        Assert.Null(resolved.TunnelConfigId);
    }

    [Fact]
    public async Task ImportAsync_RejectsFilesLargerThanCap()
    {
        var dst = await CreateEnvAsync();
        var hugePath = Path.Combine(_scratchDir, "huge.json");
        // 65 MiB of bytes — over the 64 MiB cap. Use SetLength to avoid actually allocating
        // 65 MiB of '0' bytes in test memory.
        using (var fs = File.Create(hugePath))
        {
            fs.SetLength(65L * 1024 * 1024);
        }
        await Assert.ThrowsAsync<InvalidDataException>(
            () => dst.Service.ImportAsync(hugePath, null));
    }

    [Fact]
    public async Task ImportAsync_ReadsExistingMetadataConcurrently()
    {
        var gate = new ConcurrentGetAllGate(expectedStarts: 3);
        var service = new BackupService(
            new BlockingConnectionRepository(gate),
            new BlockingCredentialRepository(gate),
            new BlockingTunnelConfigRepository(gate),
            new FakeCredentialService(),
            NullLogger<BackupService>.Instance);
        var path = Path.Combine(_scratchDir, "empty-import.json");
        await File.WriteAllTextAsync(path, $$"""
            {
              "schemaVersion": 1,
              "encryption": "none",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "payload": {
                "nodes": [],
                "credentials": [],
                "tunnels": [],
                "passwords": [],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """, Encoding.UTF8);

        var importTask = service.ImportAsync(path, null);

        await gate.WaitForAllStartedAsync(TimeSpan.FromSeconds(1));
        gate.Release();
        var result = await importTask;

        Assert.Equal(0, result.NodesImported);
        Assert.Equal(0, result.CredentialsImported);
        Assert.Equal(0, result.TunnelsImported);
    }

    [Fact]
    public async Task ImportAsync_TopologicallyInsertsNodesEvenWhenBackupOrderIsReversed()
    {
        // Build a backup file by hand whose Nodes array deliberately lists the leaf BEFORE
        // its parent folder. A naive in-order insert would fail the ParentId FK; the
        // topological pass must reorder so the folder lands first.
        var dst = await CreateEnvAsync();

        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "Folder",
            Kind = NodeKind.Folder,
            SortOrder = 1,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "Leaf",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "h",
            Port = 22,
            SortOrder = 2,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        // Hand-craft the JSON with leaf first, folder second.
        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "none",
              "payload": {
                "nodes": [
                  {{NodeJson(leaf)}},
                  {{NodeJson(folder)}}
                ],
                "credentials": [],
                "tunnels": [],
                "passwords": [],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "reversed.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(2, result.NodesImported);
        Assert.Empty(result.Warnings);
        var nodes = await dst.Connections.GetAllAsync();
        Assert.Equal(2, nodes.Count);
        Assert.Equal(folder.Id, nodes.Single(n => n.Id == leaf.Id).ParentId);
    }

    [Fact]
    public async Task ImportAsync_OrphanNodeIsImportedAtRootWithWarning()
    {
        // A node whose ParentId references a non-existent parent (and is not present in the
        // backup file) should be re-rooted at null instead of failing the entire import.
        var dst = await CreateEnvAsync();

        var orphan = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = Guid.NewGuid(),
            Name = "Orphan",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "h",
            Port = 22,
            SortOrder = 0,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        var docJson = $$"""
            {
              "schemaVersion": 1,
              "app": "Wormhole",
              "exportedAt": "{{DateTimeOffset.UtcNow:O}}",
              "encryption": "none",
              "payload": {
                "nodes": [{{NodeJson(orphan)}}],
                "credentials": [],
                "tunnels": [],
                "passwords": [],
                "privateKeys": [],
                "tunnelPayloads": []
              }
            }
            """;
        var path = Path.Combine(_scratchDir, "orphan.json");
        await File.WriteAllTextAsync(path, docJson, Encoding.UTF8);

        var result = await dst.Service.ImportAsync(path, null);
        Assert.Equal(1, result.NodesImported);
        Assert.Single(result.Warnings);
        var rerooted = (await dst.Connections.GetAllAsync()).Single();
        Assert.Null(rerooted.ParentId);
    }

    /// <summary>Minimal hand-written JSON object for a ConnectionNode — only the fields
    /// the test cases here care about. Other nullable columns are omitted so the deserializer
    /// fills in default values.</summary>
    private static string NodeJson(ConnectionNode n)
    {
        var parentJson = n.ParentId is null ? "null" : $"\"{n.ParentId}\"";
        var protocolJson = n.Protocol is null ? "null" : ((int)n.Protocol.Value).ToString();
        var portJson = n.Port is null ? "null" : n.Port.Value.ToString();
        var hostJson = n.Host is null ? "null" : $"\"{n.Host}\"";
        return $$"""
            {
              "id": "{{n.Id}}",
              "parentId": {{parentJson}},
              "name": "{{n.Name}}",
              "kind": {{(int)n.Kind}},
              "sortOrder": {{n.SortOrder}},
              "protocol": {{protocolJson}},
              "host": {{hostJson}},
              "port": {{portJson}},
              "createdAt": "{{n.CreatedAt:O}}",
              "updatedAt": "{{n.UpdatedAt:O}}"
            }
            """;
    }

    private sealed class ConcurrentGetAllGate
    {
        private readonly int _expectedStarts;
        private readonly TaskCompletionSource _allStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _started;

        public ConcurrentGetAllGate(int expectedStarts)
        {
            _expectedStarts = expectedStarts;
        }

        public async Task WaitAsync()
        {
            if (Interlocked.Increment(ref _started) == _expectedStarts)
            {
                _allStarted.TrySetResult();
            }
            await _release.Task.ConfigureAwait(false);
        }

        public async Task WaitForAllStartedAsync(TimeSpan timeout)
        {
            var completed = await Task.WhenAny(_allStarted.Task, Task.Delay(timeout)).ConfigureAwait(false);
            if (!ReferenceEquals(completed, _allStarted.Task))
            {
                throw new TimeoutException("Existing metadata reads did not start concurrently.");
            }
            await _allStarted.Task.ConfigureAwait(false);
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class BlockingCredentialRepository : ICredentialRepository
    {
        private readonly ConcurrentGetAllGate _gate;

        public BlockingCredentialRepository(ConcurrentGetAllGate gate) => _gate = gate;

        public async Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            return Array.Empty<CredentialProfile>();
        }

        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<CredentialProfile?>(null);

        public Task AddAsync(CredentialProfile profile, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateAsync(CredentialProfile profile, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class BlockingTunnelConfigRepository : ITunnelConfigRepository
    {
        private readonly ConcurrentGetAllGate _gate;

        public BlockingTunnelConfigRepository(ConcurrentGetAllGate gate) => _gate = gate;

        public async Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            return Array.Empty<TunnelConfig>();
        }

        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<TunnelConfig?>(null);

        public Task AddAsync(TunnelConfig config, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateAsync(TunnelConfig config, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class BlockingConnectionRepository : IConnectionRepository
    {
        private readonly ConcurrentGetAllGate _gate;

        public BlockingConnectionRepository(ConcurrentGetAllGate gate) => _gate = gate;

        public async Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            return Array.Empty<ConnectionNode>();
        }

        public Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(
            Guid tunnelConfigId,
            int limit,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<(Guid Id, string Name)>>(Array.Empty<(Guid Id, string Name)>());

        public Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteManyAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    /// <summary>Seeds a folder + one connection beneath it, two credentials (password +
    /// SSH key), and one tunnel with its DPAPI payload. Returns the IDs so tests can target
    /// specific rows.</summary>
    private static async Task<(Guid folderId, Guid leafId, Guid credId, Guid sshCredId, Guid tunnelId)>
        SeedSampleDataAsync(Env env)
    {
        var passwordCred = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "alice",
            Username = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        };
        await env.Credentials.AddAsync(passwordCred);
        await env.Secrets.StorePasswordAsync(passwordCred.Id, "hunter2");

        var sshKeyCred = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "alice-key",
            Username = "alice",
            Kind = CredentialKind.SshKey,
            Protocol = ProtocolType.Ssh,
            PrivateKeyFileName = "id_ed25519",
            CreatedAt = DateTime.UtcNow,
        };
        await env.Credentials.AddAsync(sshKeyCred);
        await env.Secrets.StorePrivateKeyAsync(sshKeyCred.Id, new byte[] { 1, 2, 3, 4, 5 });

        var tunnel = new TunnelConfig { Id = Guid.NewGuid(), Name = "office-vpn", Kind = TunnelKind.WireGuard };
        await env.Tunnels.AddAsync(tunnel);
        await env.Secrets.StoreTunnelConfigAsync(tunnel.Id, new byte[] { 9, 8, 7 });

        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "Production",
            Kind = NodeKind.Folder,
            SortOrder = 1,
        };
        await env.Connections.AddAsync(folder);

        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "app01",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "server.example.com",
            Port = 22,
            Username = "alice",
            CredentialId = passwordCred.Id,
            TunnelConfigId = tunnel.Id,
            TunnelEnabled = true,
            SortOrder = 2,
        };
        await env.Connections.AddAsync(leaf);

        return (folder.Id, leaf.Id, passwordCred.Id, sshKeyCred.Id, tunnel.Id);
    }
}
