using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services.MRemoteNg;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public class MRemoteNgImportServiceTests : IDisposable
{
    // Mirrors the production migrations 0001-0006 so the test sees the same column shape as
    // a real first-run install. Kept inline because the test project links source files;
    // embedded migration .sql resources from the main assembly aren't reachable here. The
    // RDP* columns must stay in lockstep with ConnectionTreeViewModelTests.SchemaSql or
    // Dapper's SELECT-* in ConnectionRepository.GetAllAsync throws "no such column".
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
        CREATE UNIQUE INDEX UX_CredentialProfiles_Name ON CredentialProfiles(Name);";

    private const string DefaultPassword = "mR3m";
    private const int DefaultIterations = 10000;

    private readonly string _dbPath;
    private readonly string _connectionString;
    private readonly SqliteConnectionFactory _factory;
    private readonly ConnectionRepository _connectionRepo;
    private readonly CredentialRepository _credentialRepo;
    private readonly FakeCredentialService _credentialService;
    private readonly MRemoteNgImportService _service;
    private readonly string _scratchDir;

    public MRemoteNgImportServiceTests()
    {
        SqliteTypeHandlers.Register();
        _dbPath = Path.Combine(Path.GetTempPath(), $"wormhole-mremoteng-{Guid.NewGuid():N}.db");
        _connectionString = $"Data Source={_dbPath}";
        _factory = new SqliteConnectionFactory(_connectionString);
        new MigrationRunner(
            _factory,
            NullLogger<MigrationRunner>.Instance,
            new List<Migration> { new("0001_initial", SchemaSql) }
        ).RunAsync().GetAwaiter().GetResult();

        _connectionRepo = new ConnectionRepository(_factory);
        _credentialRepo = new CredentialRepository(_factory);
        _credentialService = new FakeCredentialService();
        _service = new MRemoteNgImportService(
            _connectionRepo, _credentialRepo, _credentialService, _factory,
            NullLogger<MRemoteNgImportService>.Instance);

        _scratchDir = Path.Combine(Path.GetTempPath(), "wormhole-mremoteng-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratchDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
        if (Directory.Exists(_scratchDir)) Directory.Delete(_scratchDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task VerifyPasswordAsync_DefaultPassword_ReturnsTrueOnFixture()
    {
        var path = WriteFixture(BuildFixtureXml());

        var ok = await _service.VerifyPasswordAsync(path, DefaultPassword);

        Assert.True(ok);
    }

    [Fact]
    public async Task VerifyPasswordAsync_EmptyMasterPassword_ReturnsTrueOnNoPasswordExport()
    {
        // mRemoteNG's "no password" export option produces a Protected attribute encrypted
        // with the empty string. Make sure the crypto path actually verifies empty without
        // tripping any non-null guard.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, string.Empty, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7" />
            """;
        var path = WriteFixture(xml);

        Assert.True(await _service.VerifyPasswordAsync(path, string.Empty));
        Assert.False(await _service.VerifyPasswordAsync(path, DefaultPassword));
    }

    [Fact]
    public async Task PlanAndCommit_NoPasswordExport_ImportsConnectionsAndCredentials()
    {
        // End-to-end: a file exported with the empty master password should plan and commit
        // cleanly, decrypting the per-connection Password fields with the same empty key.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, string.Empty, DefaultIterations);
        var sshPwd = MRemoteNgCryptoTests.Encrypt("plain-secret", string.Empty, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="leaf" Type="Connection" Protocol="SSH2" Hostname="h"
                      Username="alice" Password="{{sshPwd}}" />
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, string.Empty));

        Assert.Equal(1, result.ConnectionsCreated);
        Assert.Equal(1, result.CredentialsCreated);
        var cred = (await _credentialRepo.GetAllAsync()).Single();
        Assert.Equal("plain-secret", _credentialService.Passwords[cred.Id]);
    }

    [Fact]
    public async Task PlanAndCommit_NoPasswordPayloads_WithCustomProtectedVerifier_ImportsConnectionsWithoutCredentials()
    {
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, "custom-master", DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="Top" Type="Container" Protocol="SSH2" Password="   ">
                    <Node Name="leaf-a" Type="Connection" Protocol="SSH2" Hostname="h-a"
                          Username="alice" Password="" />
                    <Node Name="leaf-b" Type="Connection" Protocol="SSH2" Hostname="h-b"
                          Username="bob" Password="ignored-inherited-value" InheritPassword="true" />
                </Node>
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var info = await _service.InspectAsync(path);
        Assert.False(info.HasPasswordPayloads);
        Assert.False(await _service.VerifyPasswordAsync(path, DefaultPassword));

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(1, result.FoldersCreated);
        Assert.Equal(2, result.ConnectionsCreated);
        Assert.Equal(0, result.CredentialsCreated);
        Assert.Empty(await _credentialRepo.GetAllAsync());
        Assert.Empty(_credentialService.Passwords);
    }

    [Fact]
    public async Task PlanAndCommit_NoPasswordPayloads_AllowsMissingProtectedVerifier()
    {
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine=""
                BlockCipherMode="" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="" ConfVersion="2.7">
                <Node Name="leaf" Type="Connection" Protocol="SSH2" Hostname="h"
                      Username="alice" Password="" />
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var info = await _service.InspectAsync(path);
        Assert.False(info.HasPasswordPayloads);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(1, result.ConnectionsCreated);
        Assert.Equal(0, result.CredentialsCreated);
        Assert.Empty(_credentialService.Passwords);
    }

    [Fact]
    public async Task VerifyPasswordAsync_WrongPassword_ReturnsFalse()
    {
        var path = WriteFixture(BuildFixtureXml());

        var ok = await _service.VerifyPasswordAsync(path, "wrong");

        Assert.False(ok);
    }

    [Fact]
    public async Task VerifyPasswordAsync_DoesNotMutateDatabase()
    {
        var path = WriteFixture(BuildFixtureXml());

        await _service.VerifyPasswordAsync(path, "wrong");

        Assert.Empty(await _connectionRepo.GetAllAsync());
        Assert.Empty(await _credentialRepo.GetAllAsync());
    }

    [Fact]
    public async Task PlanAndCommit_PersistsHierarchyAndCredentials()
    {
        var path = WriteFixture(BuildFixtureXml());

        var plan = await _service.PlanAsync(path, DefaultPassword);
        var result = await _service.CommitAsync(plan);

        Assert.Equal(2, result.FoldersCreated);  // "Top" + "Inner"
        Assert.Equal(2, result.ConnectionsCreated);  // ssh + rdp leaves (VNC skipped)
        Assert.Equal(1, result.SkippedUnsupportedProtocols);
        // Two leaves with the same credentials (alice/dom/pwd, SSH) and (bob/ACME/pwd, RDP) so
        // they don't dedupe — different protocols. Result should be 2 credentials.
        Assert.Equal(2, result.CredentialsCreated);

        var nodes = await _connectionRepo.GetAllAsync();
        Assert.Equal(4, nodes.Count);  // 2 folders + 2 connections

        // Hierarchy: "Top" is a root folder, "Inner" is its child, "leaf-ssh" is under Top,
        // "leaf-rdp" is under Inner.
        var top = Assert.Single(nodes, n => n.Name == "Top");
        Assert.Null(top.ParentId);
        Assert.Equal(NodeKind.Folder, top.Kind);
        var inner = Assert.Single(nodes, n => n.Name == "Inner");
        Assert.Equal(top.Id, inner.ParentId);
        var ssh = Assert.Single(nodes, n => n.Name == "leaf-ssh");
        Assert.Equal(top.Id, ssh.ParentId);
        Assert.Equal(ProtocolType.Ssh, ssh.Protocol);
        Assert.Equal("ssh.example.com", ssh.Host);
        var rdp = Assert.Single(nodes, n => n.Name == "leaf-rdp");
        Assert.Equal(inner.Id, rdp.ParentId);
        Assert.Equal(ProtocolType.Rdp, rdp.Protocol);
        Assert.Equal("ACME", rdp.RdpDomain);
        Assert.Equal("1920x1080", rdp.RdpScreenSize);

        // Credential profiles created, and the passwords are written to the fake credential
        // manager. The node references its credential, not an inline Username (credentials win).
        var credentials = await _credentialRepo.GetAllAsync();
        Assert.Equal(2, credentials.Count);
        var sshCred = credentials.Single(c => c.Protocol == ProtocolType.Ssh);
        Assert.Equal("alice", sshCred.Username);
        Assert.Equal(ssh.CredentialId, sshCred.Id);
        Assert.True(_credentialService.Passwords.ContainsKey(sshCred.Id));
        Assert.Equal("secret-alice", _credentialService.Passwords[sshCred.Id]);
    }

    [Fact]
    public async Task Commit_DedupsCredentialsByFingerprint()
    {
        // Two SSH leaves with identical user/domain/password — should produce ONE credential.
        var xml = BuildXml(
            ("Folder", "Container", Array.Empty<NodeAttr>()),
            ("a", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "SSH2"),
                NodeAttr.Make("Hostname", "h1"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", MRemoteNgCryptoTests.Encrypt("sharedpwd", DefaultPassword, DefaultIterations)),
            }),
            ("b", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "SSH2"),
                NodeAttr.Make("Hostname", "h2"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", MRemoteNgCryptoTests.Encrypt("sharedpwd", DefaultPassword, DefaultIterations)),
            }));
        var path = WriteFixture(xml);

        var plan = await _service.PlanAsync(path, DefaultPassword);
        var result = await _service.CommitAsync(plan);

        Assert.Equal(2, result.ConnectionsCreated);
        Assert.Equal(1, result.CredentialsCreated);
        var leaves = (await _connectionRepo.GetAllAsync())
            .Where(n => n.Kind == NodeKind.Connection)
            .ToList();
        Assert.NotNull(leaves[0].CredentialId);
        Assert.Equal(leaves[0].CredentialId, leaves[1].CredentialId);
    }

    [Fact]
    public async Task Commit_DifferentProtocolsKeepCredentialsSeparate()
    {
        // Same user/password but different protocols (SSH vs RDP) — must NOT dedupe because
        // CredentialProfile.Protocol is single-valued. The Wormhole resolver wouldn't be able
        // to attach one cred row to two protocols.
        var pwd = MRemoteNgCryptoTests.Encrypt("sharedpwd", DefaultPassword, DefaultIterations);
        var xml = BuildXml(
            ("a", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "SSH2"),
                NodeAttr.Make("Hostname", "h1"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", pwd),
            }),
            ("b", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "RDP"),
                NodeAttr.Make("Hostname", "h2"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", pwd),
            }));
        var path = WriteFixture(xml);

        var plan = await _service.PlanAsync(path, DefaultPassword);
        var result = await _service.CommitAsync(plan);

        Assert.Equal(2, result.CredentialsCreated);
    }

    [Fact]
    public async Task Commit_EmptyPasswordYieldsNoCredentialAndPreservesUsernameInline()
    {
        var xml = BuildXml(
            ("a", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "SSH2"),
                NodeAttr.Make("Hostname", "h1"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", ""),
            }));
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(0, result.CredentialsCreated);
        var leaf = (await _connectionRepo.GetAllAsync()).Single();
        Assert.Null(leaf.CredentialId);
        // Without a credential to take it from, Username has to live on the node itself —
        // otherwise the session resolver has nothing to feed SSH on connect.
        Assert.Equal("alice", leaf.Username);
    }

    [Fact]
    public async Task Commit_UnsupportedProtocolSkippedAndReported()
    {
        var xml = BuildXml(
            ("a", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "VNC"),
                NodeAttr.Make("Hostname", "h1"),
            }));
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(0, result.ConnectionsCreated);
        Assert.Equal(1, result.SkippedUnsupportedProtocols);
        Assert.Empty(await _connectionRepo.GetAllAsync());
    }

    [Fact]
    public async Task Commit_RollsBackSecretsOnCancellation()
    {
        var xml = BuildXml(
            ("a", "Connection", new[]
            {
                NodeAttr.Make("Protocol", "SSH2"),
                NodeAttr.Make("Hostname", "h1"),
                NodeAttr.Make("Username", "alice"),
                NodeAttr.Make("Password", MRemoteNgCryptoTests.Encrypt("secret", DefaultPassword, DefaultIterations)),
            }));
        var path = WriteFixture(xml);

        var plan = await _service.PlanAsync(path, DefaultPassword);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _service.CommitAsync(plan, cancellationToken: cts.Token));

        // Database rolled back; no nodes / no credentials.
        Assert.Empty(await _connectionRepo.GetAllAsync());
        Assert.Empty(await _credentialRepo.GetAllAsync());
        // Compensating sweep cleared any Credential Manager entry we wrote — passwords map empty.
        Assert.Empty(_credentialService.Passwords);
    }

    [Fact]
    public async Task Inspect_RejectsFullFileEncryption()
    {
        var xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="10000" FullFileEncryption="true"
                Protected="X" ConfVersion="2.7"></mrng:Connections>
            """;
        var path = WriteFixture(xml);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            _service.VerifyPasswordAsync(path, DefaultPassword));
    }

    [Fact]
    public async Task Inspect_RejectsNonGcmBlockCipher()
    {
        var xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="CBC" KdfIterations="10000" FullFileEncryption="false"
                Protected="X" ConfVersion="2.6"></mrng:Connections>
            """;
        var path = WriteFixture(xml);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            _service.VerifyPasswordAsync(path, DefaultPassword));
    }

    [Fact]
    public async Task Commit_ImportsAtRootSortOrderAfterExistingNodes()
    {
        // Pre-seed an existing root folder so we can prove the importer appends rather than
        // overlapping SortOrder.
        await _connectionRepo.AddAsync(new ConnectionNode
        {
            Name = "Existing",
            Kind = NodeKind.Folder,
            SortOrder = 0,
        });

        var path = WriteFixture(BuildFixtureXml());

        await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        var roots = (await _connectionRepo.GetAllAsync())
            .Where(n => n.ParentId is null)
            .OrderBy(n => n.SortOrder)
            .ToList();
        // "Existing" stays at 0; the imported "Top" folder gets >0 so the user's prior layout
        // is preserved.
        Assert.Equal("Existing", roots[0].Name);
        Assert.True(roots[1].SortOrder > roots[0].SortOrder);
    }

    [Fact]
    public async Task Commit_InheritedFieldsBecomeNullSoResolverCanWalkAncestors()
    {
        // Per the import service mapping: Inherit*="true" + non-empty local value should still
        // null out the local field so Wormhole's InheritanceResolver walks the parent chain.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="Top" Type="Container" Protocol="SSH2" Username="alice">
                    <Node Name="leaf" Type="Connection" Protocol="SSH2" Hostname="h"
                        Username="stale-local-value" InheritUsername="true" Password="" />
                </Node>
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        var leaf = (await _connectionRepo.GetAllAsync()).Single(n => n.Name == "leaf");
        // We dropped the local Username because the Inherit flag was set.
        Assert.Null(leaf.Username);
    }

    [Fact]
    public async Task Commit_ContainerPasswordBecomesFolderLevelCredential()
    {
        // Regression: a Container with its own Username/Password used to map to a bare
        // folder, silently dropping the credential. With the fix, the folder node carries
        // the credential so Wormhole's InheritanceResolver hands it to children at connect time.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var folderPwd = MRemoteNgCryptoTests.Encrypt("folder-secret", DefaultPassword, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="Top" Type="Container" Protocol="SSH2" Username="admin" Password="{{folderPwd}}">
                    <Node Name="leaf-a" Type="Connection" Protocol="SSH2" Hostname="h-a"
                          Username="stale" InheritUsername="true" Password="" InheritPassword="true" />
                    <Node Name="leaf-b" Type="Connection" Protocol="SSH2" Hostname="h-b"
                          Username="stale" InheritUsername="true" Password="" InheritPassword="true" />
                </Node>
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(1, result.CredentialsCreated);
        var top = (await _connectionRepo.GetAllAsync()).Single(n => n.Name == "Top");
        Assert.Equal(NodeKind.Folder, top.Kind);
        // The folder node now carries the credential id that the leaves inherit through.
        Assert.NotNull(top.CredentialId);
        // Leaves still have CredentialId=null so the resolver walks up to the folder.
        var leaves = (await _connectionRepo.GetAllAsync()).Where(n => n.Kind == NodeKind.Connection).ToList();
        Assert.Equal(2, leaves.Count);
        Assert.All(leaves, l => Assert.Null(l.CredentialId));
        // The cleartext password landed in the fake credential manager under the folder's id.
        Assert.Equal("folder-secret", _credentialService.Passwords[top.CredentialId!.Value]);
    }

    [Fact]
    public async Task Commit_DecryptionFailureSurfacesAsWarning()
    {
        // A leaf whose Password is base64-shaped but won't decrypt with the chosen master key
        // (e.g. password rotated mid-export). The import should NOT abort; it should record
        // a per-leaf warning and complete with CredentialId=null on that leaf.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        // Encrypt with a DIFFERENT password so decryption with DefaultPassword fails the GCM tag.
        var unreadablePwd = MRemoteNgCryptoTests.Encrypt("ignored", "different-master", DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="brokenleaf" Type="Connection" Protocol="SSH2" Hostname="h"
                      Username="alice" Password="{{unreadablePwd}}" />
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(1, result.ConnectionsCreated);
        Assert.Equal(0, result.CredentialsCreated);
        Assert.NotEmpty(result.Warnings);
        Assert.Contains(result.Warnings, w => w.Contains("brokenleaf", StringComparison.OrdinalIgnoreCase));
        var leaf = (await _connectionRepo.GetAllAsync()).Single();
        Assert.Null(leaf.CredentialId);
    }

    [Fact]
    public async Task Commit_LeafWithInheritProtocolKeepsPasswordAndUsesParentProtocol()
    {
        // Regression: a Connection leaf with InheritProtocol=true AND its own Password used
        // to lose the password silently (because protocol was nulled BEFORE the credential
        // creation check) and emit a misleading "Folder X had a password" warning. The fix
        // splits the on-disk protocol (used for credential creation) from the persisted
        // node-level protocol (nulled to honor inheritance).
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var leafPwd = MRemoteNgCryptoTests.Encrypt("leaf-secret", DefaultPassword, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="Top" Type="Container" Protocol="SSH2">
                    <Node Name="leaf" Type="Connection" Protocol="SSH2" InheritProtocol="true"
                          Hostname="h" Username="alice" Password="{{leafPwd}}" />
                </Node>
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        // The leaf's own password produced a credential — NOT silently dropped anymore.
        Assert.Equal(1, result.CredentialsCreated);
        Assert.Empty(result.Warnings);  // no misleading "Folder ... had a password" warning
        var leaf = (await _connectionRepo.GetAllAsync()).Single(n => n.Name == "leaf");
        // Node-level Protocol is null because InheritProtocol=true; the resolver picks up
        // SSH from the "Top" folder ancestor at connect time.
        Assert.Null(leaf.Protocol);
        Assert.NotNull(leaf.CredentialId);
        Assert.Equal("leaf-secret", _credentialService.Passwords[leaf.CredentialId!.Value]);
    }

    [Fact]
    public async Task Commit_WarningsAboveSoftCapAreCountedInDroppedWarningCount()
    {
        // Build an XML with many leaves whose passwords decrypt-fail under our master key.
        // We need > 50 to exceed the soft cap; build 60.
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var unreadablePwd = MRemoteNgCryptoTests.Encrypt("x", "different-master", DefaultIterations);
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.Append($"<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" EncryptionEngine=\"AES\" ")
          .Append($"BlockCipherMode=\"GCM\" KdfIterations=\"{DefaultIterations}\" FullFileEncryption=\"false\" ")
          .AppendLine($"Protected=\"{verifier}\" ConfVersion=\"2.7\">");
        for (var i = 0; i < 60; i++)
        {
            sb.AppendLine($"<Node Name=\"leaf-{i}\" Type=\"Connection\" Protocol=\"SSH2\" Hostname=\"h\" " +
                          $"Username=\"u\" Password=\"{unreadablePwd}\" />");
        }
        sb.AppendLine("</mrng:Connections>");
        var path = WriteFixture(sb.ToString());

        var result = await _service.CommitAsync(await _service.PlanAsync(path, DefaultPassword));

        Assert.Equal(60, result.ConnectionsCreated);
        Assert.Equal(0, result.CredentialsCreated);
        Assert.True(result.Warnings.Count <= 50, "Warnings list should be soft-capped");
        Assert.Equal(60 - result.Warnings.Count, result.DroppedWarningCount);
    }

    [Fact]
    public async Task Commit_UniqueCredentialNameCollisionGivesFriendlyError()
    {
        // Pre-seed a credential whose name matches what the importer will mint, then run an
        // import that would generate that exact name. The CommitAsync should translate the
        // SQLite UNIQUE constraint violation into a clearer message.
        await _credentialRepo.AddAsync(new CredentialProfile
        {
            Name = "mremoteng-alice@h",
            Username = "alice",
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        });

        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var pwd = MRemoteNgCryptoTests.Encrypt("secret", DefaultPassword, DefaultIterations);
        var xml = $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="{{DefaultIterations}}"
                FullFileEncryption="false" Protected="{{verifier}}" ConfVersion="2.7">
                <Node Name="conn" Type="Connection" Protocol="SSH2" Hostname="h"
                      Username="alice" Password="{{pwd}}" />
            </mrng:Connections>
            """;
        var path = WriteFixture(xml);

        // Plan succeeds — the existing name is in `assignedCredentialNames` so the importer
        // mints a NON-colliding name like `mremoteng-alice@h-2`. There's no actual collision
        // in steady state; the friendly message only fires when ANOTHER writer races. Simulate
        // by manually inserting AFTER planning. (Plan reads existing names BEFORE Commit.)
        var plan = await _service.PlanAsync(path, DefaultPassword);
        // Manually insert a row with the planned name to force a collision.
        var plannedCred = plan.Credentials.Single();
        await _credentialRepo.AddAsync(new CredentialProfile
        {
            Name = plannedCred.Name,
            Kind = CredentialKind.Password,
            Protocol = ProtocolType.Ssh,
            CreatedAt = DateTime.UtcNow,
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => _service.CommitAsync(plan));
        Assert.Contains("already exists", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PlanAsync_RejectsExcessiveNestingDepth()
    {
        var path = WriteFixture(BuildDeeplyNestedXml(MRemoteNgXmlReader.MaxNestingDepth + 1));

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => _service.PlanAsync(path, DefaultPassword));

        Assert.Contains("nesting depth exceeds", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PlanAsync_MaxSupportedNestingDepth_DoesNotOverflow()
    {
        var path = WriteFixture(BuildDeeplyNestedXml(MRemoteNgXmlReader.MaxNestingDepth));

        var plan = await _service.PlanAsync(path, DefaultPassword);

        Assert.Equal(MRemoteNgXmlReader.MaxNestingDepth, plan.FolderCount);
        Assert.Equal(0, plan.ConnectionCount);
    }

    private string WriteFixture(string xml)
    {
        var path = Path.Combine(_scratchDir, Guid.NewGuid() + ".xml");
        File.WriteAllText(path, xml, Encoding.UTF8);
        return path;
    }

    // Standard fixture: one Top container holding an SSH leaf and an Inner subfolder; Inner
    // holds an RDP leaf; the export root also contains an unsupported VNC leaf so the skip
    // path is exercised in the same run. Encrypted with the mRemoteNG default password.
    private static string BuildFixtureXml()
    {
        var sshPwd = MRemoteNgCryptoTests.Encrypt("secret-alice", DefaultPassword, DefaultIterations);
        var rdpPwd = MRemoteNgCryptoTests.Encrypt("secret-bob", DefaultPassword, DefaultIterations);
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);

        return $"""
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Test"
                EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="{DefaultIterations}"
                FullFileEncryption="false" Protected="{verifier}" ConfVersion="2.7">
                <Node Name="Top" Type="Container">
                    <Node Name="leaf-ssh" Type="Connection" Protocol="SSH2" Hostname="ssh.example.com" Port="22" Username="alice" Domain="" Password="{sshPwd}" />
                    <Node Name="Inner" Type="Container">
                        <Node Name="leaf-rdp" Type="Connection" Protocol="RDP" Hostname="rdp.example.com" Port="3389" Username="bob" Domain="ACME" Password="{rdpPwd}" Resolution="1920x1080" />
                    </Node>
                </Node>
                <Node Name="leaf-vnc" Type="Connection" Protocol="VNC" Hostname="vnc.example.com" />
            </mrng:Connections>
            """;
    }

    // Builds a flat (no nesting) mRemoteNG-style XML wrapping each tuple as a sibling Node.
    private static string BuildXml(params (string Name, string Type, NodeAttr[] Attrs)[] flatNodes)
    {
        var verifier = MRemoteNgCryptoTests.Encrypt(
            MRemoteNgImportService.ProtectedVerifier, DefaultPassword, DefaultIterations);
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine($"<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" EncryptionEngine=\"AES\" " +
                      $"BlockCipherMode=\"GCM\" KdfIterations=\"{DefaultIterations}\" " +
                      $"FullFileEncryption=\"false\" Protected=\"{verifier}\" ConfVersion=\"2.7\">");
        foreach (var (name, type, attrs) in flatNodes)
        {
            sb.AppendLine($"  <Node Name=\"{name}\" Type=\"{type}\" {FormatAttrs(attrs)} />");
        }
        sb.AppendLine("</mrng:Connections>");
        return sb.ToString();
    }

    private static string BuildDeeplyNestedXml(int depth)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine($"<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" EncryptionEngine=\"AES\" " +
                      $"BlockCipherMode=\"GCM\" KdfIterations=\"{DefaultIterations}\" " +
                      "FullFileEncryption=\"false\" Protected=\"\" ConfVersion=\"2.7\">");
        for (var i = 0; i < depth; i++)
        {
            sb.AppendLine($"<Node Name=\"Folder {i}\" Type=\"Container\">");
        }
        for (var i = 0; i < depth; i++)
        {
            sb.AppendLine("</Node>");
        }
        sb.AppendLine("</mrng:Connections>");
        return sb.ToString();
    }

    private static string FormatAttrs(NodeAttr[] attrs) =>
        string.Join(" ", attrs.Select(a => $"{a.Name}=\"{a.Value}\""));

    private readonly record struct NodeAttr(string Name, string Value)
    {
        public static NodeAttr Make(string name, string value) => new(name, value);
    }
}
