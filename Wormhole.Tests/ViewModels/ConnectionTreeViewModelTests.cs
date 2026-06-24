using System.Collections.Specialized;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class ConnectionTreeViewModelTests : IDisposable
{
    private static readonly string[] ExpectedSortOrderAbc = { "A", "B", "C" };
    private static readonly string[] ExpectedReorderBca = { "B", "C", "A" };
    private static readonly string[] ExpectedReorderCab = { "C", "A", "B" };
    private const int DeepTreeDepth = 5000;
    private static readonly string[] ExpectedReorderAdbc = { "A", "D", "B", "C" };
    private static readonly string[] ExpectedParentSibling = { "Parent", "Sibling" };

    // Inlined from Data/Migrations/0001_initial.sql + 0003_add_tunnel_config.sql + 0003_rdp_extras.sql
    // + 0004_rdp_use_external_client.sql: the test project links source files rather than
    // referencing the main assembly, so embedded .sql resources are not available. Keep the
    // column set in sync with ConnectionRepository's SELECT/INSERT/UPDATE.
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
            CredentialMode           INTEGER  NULL,
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
            SerialBaudRate           INTEGER  NULL,
            SerialDataBits           INTEGER  NULL,
            SerialStopBits           INTEGER  NULL,
            SerialParity             INTEGER  NULL,
            SerialFlowControl        INTEGER  NULL,
            HttpIgnoreCertErrors     INTEGER  NULL,
            TunnelEnabled            INTEGER  NULL,
            TunnelConfigId           TEXT     NULL,
            CreatedAt                TEXT     NOT NULL,
            UpdatedAt                TEXT     NOT NULL
        );
        CREATE INDEX IX_Nodes_ParentId ON Nodes(ParentId);
        CREATE TABLE TunnelConfigs (
            Id         TEXT     PRIMARY KEY NOT NULL,
            Name       TEXT     NOT NULL,
            Kind       INTEGER  NOT NULL,
            CreatedAt  TEXT     NOT NULL,
            UpdatedAt  TEXT     NOT NULL
        );
        CREATE UNIQUE INDEX UX_TunnelConfigs_Name ON TunnelConfigs(Name);";

    private readonly string _dbPath;
    private readonly string _connectionString;
    private readonly SqliteConnectionFactory _factory;
    private readonly ConnectionRepository _repo;

    public ConnectionTreeViewModelTests()
    {
        SqliteTypeHandlers.Register();
        _dbPath = Path.Combine(Path.GetTempPath(), $"wormhole-vmtest-{Guid.NewGuid():N}.db");
        _connectionString = $"Data Source={_dbPath}";
        _factory = new SqliteConnectionFactory(_connectionString);
        new MigrationRunner(
            _factory,
            NullLogger<MigrationRunner>.Instance,
            new List<Migration> { new("0001_initial", SchemaSql) }
        ).RunAsync().GetAwaiter().GetResult();
        _repo = new ConnectionRepository(_factory);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private ConnectionTreeViewModel CreateVm(
        FakeDialogService? dialog = null,
        FakeCredentialService? creds = null,
        FakeCredentialRepository? credRepo = null,
        IConnectionRepository? repository = null)
    {
        var vm = new ConnectionTreeViewModel(
            repository ?? _repo,
            new InheritanceResolver(),
            new NullSessionTabFactory(),
            dialog ?? new FakeDialogService(),
            creds ?? new FakeCredentialService(),
            credRepo ?? new FakeCredentialRepository(),
            NullLogger<ConnectionTreeViewModel>.Instance);
        // Tests assert synchronously after assigning SearchText; disable the production
        // 120ms debounce so the filter walk runs inline rather than on a scheduled
        // continuation. Production code uses the default delay.
        vm.SearchDebounceDelay = TimeSpan.Zero;
        return vm;
    }

    private static ConnectionNode MakeConnectionDraft(string name, ProtocolType protocol, string host, int? port, string? username)
        => new()
        {
            Kind = NodeKind.Connection,
            Name = name,
            Protocol = protocol,
            Host = host,
            Port = port,
            Username = username,
        };

    [Fact]
    public async Task AddFolder_AtRoot_PersistsAndAppears()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Linux" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddFolderCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal("Linux", row.Name);
        Assert.Null(row.ParentId);
        Assert.Equal(NodeKind.Folder, row.Kind);
        Assert.Single(vm.Roots);
    }

    [Fact]
    public async Task ImportFromMRemoteNg_NoResult_DoesNotRefresh()
    {
        // Pre-populate the DB out-of-band so we can assert the tree was NOT reloaded.
        await _repo.AddAsync(new ConnectionNode { Name = "Existing", Kind = NodeKind.Folder });
        var dialog = new FakeDialogService { MRemoteNgImportResult = null };
        var vm = CreateVm(dialog);

        await vm.ImportFromMRemoteNgCommand.ExecuteAsync(null);

        Assert.Equal(1, dialog.MRemoteNgImportPromptCount);
        // Tree never refreshed because the dialog returned null (user closed without committing),
        // so the seeded node isn't visible in Roots.
        Assert.Empty(vm.Roots);
    }

    [Fact]
    public async Task ImportFromMRemoteNg_WithResult_TriggersRefresh()
    {
        // Pre-populate again — the difference here is that the dialog returns a non-null
        // result, so the command should call RefreshAsync and the seeded node appears.
        await _repo.AddAsync(new ConnectionNode { Name = "Imported", Kind = NodeKind.Folder });
        var dialog = new FakeDialogService
        {
            MRemoteNgImportResult = new MRemoteNgImportResult(1, 0, 0, 0, Array.Empty<string>()),
        };
        var vm = CreateVm(dialog);

        await vm.ImportFromMRemoteNgCommand.ExecuteAsync(null);

        Assert.Equal(1, dialog.MRemoteNgImportPromptCount);
        Assert.Single(vm.Roots);
        Assert.Equal("Imported", vm.Roots[0].Name);
    }

    [Fact]
    public async Task AddFolder_RightClickedOnFolder_NestsUnderIt()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parentVm = vm.Roots.Single();

        dialog.TextPromptResult = "Child";
        await vm.AddFolderCommand.ExecuteAsync(parentVm);

        var child = (await _repo.GetAllAsync()).Single(n => n.Name == "Child");
        Assert.Equal(parentVm.Node.Id, child.ParentId);
    }

    [Fact]
    public async Task AddFolder_RightClickedOnConnection_CreatesAsSibling()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parentId = vm.Roots.Single().Node.Id;

        dialog.EditConnectionResult = MakeConnectionDraft("leaf", ProtocolType.Ssh, "h", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());
        var leafVm = vm.Roots.Single().Children.Single();

        dialog.TextPromptResult = "Sibling";
        await vm.AddFolderCommand.ExecuteAsync(leafVm);

        var sibling = (await _repo.GetAllAsync()).Single(n => n.Name == "Sibling");
        Assert.Equal(parentId, sibling.ParentId);
    }

    [Fact]
    public async Task AddConnection_PopulatesProtocolHostPortUsername()
    {
        var dialog = new FakeDialogService
        {
            EditConnectionResult = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "example.com", 2222, "daniel"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal(NodeKind.Connection, row.Kind);
        Assert.Equal("prod-web", row.Name);
        Assert.Equal(ProtocolType.Ssh, row.Protocol);
        Assert.Equal("example.com", row.Host);
        Assert.Equal(2222, row.Port);
        Assert.Equal("daniel", row.Username);
    }

    [Fact]
    public async Task AddConnection_WithCredentialId_PersistsCredentialId()
    {
        var credentialId = Guid.NewGuid();
        var draft = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "example.com", 22, null);
        draft.CredentialId = credentialId;
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal(credentialId, row.CredentialId);
    }

    [Fact]
    public async Task Edit_AssignsCredentialId_PersistsToDb()
    {
        var dialog = new FakeDialogService
        {
            EditConnectionResult = MakeConnectionDraft("prod", ProtocolType.Ssh, "host", 22, "alice"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);

        var credentialId = Guid.NewGuid();
        var nextDraft = MakeConnectionDraft("prod", ProtocolType.Ssh, "host", 22, null);
        nextDraft.CredentialId = credentialId;
        dialog.EditConnectionResult = nextDraft;
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal(credentialId, row.CredentialId);
    }

    [Theory]
    [InlineData(ProtocolType.Ssh, 22)]
    [InlineData(ProtocolType.Rdp, 3389)]
    public async Task AddConnection_InlinePassword_StoresSecretUnderNodeId(ProtocolType protocol, int port)
    {
        var draft = MakeConnectionDraft("inline", protocol, "host", port, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "s3cret";
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        // The DB row carries only the flag; the secret lives in Credential Manager keyed by the
        // node Id (here the in-memory FakeCredentialService).
        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.True(row.UseInlinePassword);
        Assert.Equal("s3cret", creds.Passwords[row.Id]);
    }

    [Theory]
    [InlineData(ProtocolType.Ssh, 22)]
    [InlineData(ProtocolType.Rdp, 3389)]
    public async Task AddConnection_InlinePasswordBlank_DoesNotStoreEmptySecret(ProtocolType protocol, int port)
    {
        // Inline mode with a blank password: the flag persists, but no empty Credential Manager
        // entry is written (an empty secret would yield no useful inline auth and fail the connect;
        // the session credential resolver instead prompts when the secret is absent).
        var draft = MakeConnectionDraft("inline", protocol, "host", port, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "";
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.True(row.UseInlinePassword);
        Assert.False(creds.Passwords.ContainsKey(row.Id));
    }

    [Theory]
    [InlineData(ProtocolType.Ssh, 22)]
    [InlineData(ProtocolType.Rdp, 3389)]
    public async Task Edit_InlinePasswordCleared_PurgesStoredSecret(ProtocolType protocol, int port)
    {
        var draft = MakeConnectionDraft("inline", protocol, "host", port, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "s3cret";
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);
        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal("s3cret", creds.Passwords[row.Id]);

        // Still inline, but the password field was cleared → the stale secret must be removed.
        var next = MakeConnectionDraft("inline", protocol, "host", port, "root");
        next.UseInlinePassword = true;
        next.PendingInlinePassword = "";
        dialog.EditConnectionResult = next;
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.False(creds.Passwords.ContainsKey(row.Id));
    }

    [Fact]
    public async Task Edit_SwitchingInlineOff_DeletesStoredSecret()
    {
        var draft = MakeConnectionDraft("inline", ProtocolType.Ssh, "host", 22, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "s3cret";
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);
        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal("s3cret", creds.Passwords[row.Id]);

        // Re-edit, switching to a saved credential (inline off) — the stale secret must be purged.
        var credId = Guid.NewGuid();
        var next = MakeConnectionDraft("inline", ProtocolType.Ssh, "host", 22, "root");
        next.CredentialId = credId;
        dialog.EditConnectionResult = next;
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.False(creds.Passwords.ContainsKey(row.Id));
        var updated = Assert.Single(await _repo.GetAllAsync());
        Assert.False(updated.UseInlinePassword ?? false);
        Assert.Equal(credId, updated.CredentialId);
    }

    [Fact]
    public async Task Delete_Connection_PurgesInlineSecret()
    {
        var draft = MakeConnectionDraft("inline", ProtocolType.Ssh, "host", 22, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "s3cret";
        var dialog = new FakeDialogService { EditConnectionResult = draft };
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);
        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.True(creds.Passwords.ContainsKey(row.Id));

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Empty(await _repo.GetAllAsync());
        Assert.False(creds.Passwords.ContainsKey(row.Id));
    }

    [Fact]
    public async Task Delete_Folder_PurgesNestedConnectionInlineSecret()
    {
        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        // A folder containing an inline-password connection.
        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parentVm = vm.Roots.Single();

        var draft = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", 22, "root");
        draft.UseInlinePassword = true;
        draft.PendingInlinePassword = "s3cret";
        dialog.EditConnectionResult = draft;
        await vm.AddConnectionCommand.ExecuteAsync(parentVm);

        var connection = (await _repo.GetAllAsync()).Single(n => n.Kind == NodeKind.Connection);
        Assert.Equal("s3cret", creds.Passwords[connection.Id]);

        // Deleting the FOLDER cascades the DB rows; it must ALSO purge the descendant connection's
        // inline secret (keyed by the connection's node Id), not just the clicked node.
        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Empty(await _repo.GetAllAsync());
        Assert.False(creds.Passwords.ContainsKey(connection.Id));
    }

    [Fact]
    public async Task Delete_MultipleSelectedNodes_CanonicalizesAncestorsAndPurgesInlineSecrets()
    {
        var parent = new ConnectionNode { Kind = NodeKind.Folder, Name = "Parent", SortOrder = 0 };
        var child = MakeConnectionDraft("child", ProtocolType.Ssh, "child.example.com", 22, "alice");
        child.ParentId = parent.Id;
        child.UseInlinePassword = true;
        var leaf = MakeConnectionDraft("leaf", ProtocolType.Ssh, "leaf.example.com", 22, "bob");
        leaf.SortOrder = 1;
        leaf.UseInlinePassword = true;

        await _repo.AddAsync(parent);
        await _repo.AddAsync(child);
        await _repo.AddAsync(leaf);

        var repo = new CountingConnectionRepository(_repo);
        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[child.Id] = "child-secret";
        creds.Passwords[leaf.Id] = "leaf-secret";
        var vm = CreateVm(dialog, creds, repository: repo);
        await vm.RefreshAsync();

        var parentVm = vm.Roots.Single(r => r.Name == "Parent");
        var childVm = parentVm.Children.Single();
        var leafVm = vm.Roots.Single(r => r.Name == "leaf");
        vm.SetSelectedNodes(new[] { parentVm, childVm, leafVm });

        await vm.DeleteCommand.ExecuteAsync(null);

        Assert.Equal(1, dialog.ConfirmCount);
        Assert.Equal(new[] { parent.Id, leaf.Id }, repo.LastDeleteManyIds);
        Assert.Empty(await _repo.GetAllAsync());
        Assert.False(creds.Passwords.ContainsKey(child.Id));
        Assert.False(creds.Passwords.ContainsKey(leaf.Id));
    }

    [Fact]
    public async Task ShowCredentials_ConnectionWithStoredPassword_RevealsViaDialog()
    {
        var credentialId = Guid.NewGuid();
        var node = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "host", 22, "alice");
        node.CredentialId = credentialId;
        await _repo.AddAsync(node);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "s3cret";
        var credRepo = new FakeCredentialRepository(
            new CredentialProfile { Id = credentialId, Kind = CredentialKind.Password });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        await vm.ShowCredentialsCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("s3cret", dialog.LastShownSecret);
        Assert.Equal("alice", dialog.LastShownUsername);
        Assert.Equal("Password", dialog.LastShownSecretLabel);
    }

    [Fact]
    public async Task ShowCredentials_SshKeyCredential_LabelsSecretAsKeyPassphrase()
    {
        var credentialId = Guid.NewGuid();
        var node = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "host", 22, "alice");
        node.CredentialId = credentialId;
        await _repo.AddAsync(node);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "key-passphrase";
        var credRepo = new FakeCredentialRepository(
            new CredentialProfile { Id = credentialId, Kind = CredentialKind.SshKey });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        await vm.ShowCredentialsCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("key-passphrase", dialog.LastShownSecret);
        Assert.Equal("Key passphrase", dialog.LastShownSecretLabel);
    }

    [Fact]
    public async Task ShowCredentials_ConnectionWithInlinePassword_RevealsViaDialog()
    {
        var node = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "host", 22, "alice");
        node.UseInlinePassword = true;
        await _repo.AddAsync(node);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[node.Id] = "inline-secret";
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        await vm.ShowCredentialsCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("inline-secret", dialog.LastShownSecret);
        Assert.Equal("alice", dialog.LastShownUsername);
        Assert.Equal("Password", dialog.LastShownSecretLabel);
    }

    [Fact]
    public async Task ShowCredentials_InlinePasswordOverridesInheritedSavedCredential()
    {
        var inheritedCredentialId = Guid.NewGuid();
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", CredentialId = inheritedCredentialId };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "host", 22, "alice");
        child.ParentId = folder.Id;
        child.UseInlinePassword = true;
        await _repo.AddAsync(child);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[inheritedCredentialId] = "inherited-secret";
        creds.Passwords[child.Id] = "inline-secret";
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single();
        await vm.ShowCredentialsCommand.ExecuteAsync(childVm);

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("inline-secret", dialog.LastShownSecret);
        Assert.NotEqual("inherited-secret", dialog.LastShownSecret);
    }

    [Fact]
    public async Task ShowCredentials_ConnectionInheritsCredentialFromFolder_RevealsInheritedPassword()
    {
        var credentialId = Guid.NewGuid();
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", CredentialId = credentialId };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "host", 22, "alice");
        child.ParentId = folder.Id;
        child.CredentialId = null;
        await _repo.AddAsync(child);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "inherited-pw";
        var credRepo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
        });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single();
        await vm.ShowCredentialsCommand.ExecuteAsync(childVm);

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("inherited-pw", dialog.LastShownSecret);
    }

    [Fact]
    public async Task ShowCredentials_VncConnectionInheritsNonVncCredential_DoesNotRevealSecret()
    {
        var credentialId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "ssh-folder",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credentialId,
        };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("console", ProtocolType.Vnc, "kvm.example.com", 5900, username: null);
        child.ParentId = folder.Id;
        await _repo.AddAsync(child);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "ssh-secret";
        var credRepo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
            Username = "ssh-user",
        });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single();
        await vm.ShowCredentialsCommand.ExecuteAsync(childVm);

        Assert.Equal(0, dialog.ShowCredentialsCount);
        Assert.NotEqual("ssh-secret", dialog.LastShownSecret);
    }

    [Fact]
    public async Task ShowCredentials_SshConnectionInheritsVncCredential_DoesNotRevealSecret()
    {
        var credentialId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "shared",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credentialId,
        };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "host", 22, "alice");
        child.ParentId = folder.Id;
        await _repo.AddAsync(child);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "vnc-secret";
        var credRepo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Protocol = ProtocolType.Vnc,
            Kind = CredentialKind.Password,
        });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single();
        await vm.ShowCredentialsCommand.ExecuteAsync(childVm);

        Assert.Equal(0, dialog.ShowCredentialsCount);
        Assert.NotEqual("vnc-secret", dialog.LastShownSecret);
    }

    [Fact]
    public async Task ShowCredentials_InheritedCredentialUsesCredentialUsernameWhenProfileHasNone()
    {
        var root = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "all",
            Username = "root-user",
        };
        await _repo.AddAsync(root);

        var credentialId = Guid.NewGuid();
        var closest = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            ParentId = root.Id,
            Name = "prod",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credentialId,
        };
        await _repo.AddAsync(closest);

        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "host", 22, username: null);
        child.ParentId = closest.Id;
        child.CredentialMode = CredentialBindingMode.Inherit;
        await _repo.AddAsync(child);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "inherited-pw";
        var credRepo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Kind = CredentialKind.Password,
            Username = "credential-user",
        });
        var vm = CreateVm(dialog, creds, credRepo);
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single().Children.Single();
        await vm.ShowCredentialsCommand.ExecuteAsync(childVm);

        Assert.Equal(1, dialog.ShowCredentialsCount);
        Assert.Equal("inherited-pw", dialog.LastShownSecret);
        Assert.Equal("credential-user", dialog.LastShownUsername);
    }

    [Fact]
    public async Task Host_ConnectionWithOwnHost_ReturnsOwnHost()
    {
        var node = MakeConnectionDraft("web", ProtocolType.Ssh, "10.0.0.5", 22, "alice");
        await _repo.AddAsync(node);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        Assert.Equal("10.0.0.5", vm.Roots.Single().Host);
    }

    [Fact]
    public async Task Host_ConnectionInheritsHostFromFolder_ResolvesInheritedHost()
    {
        // The hover tooltip must show the effective host, so a connection whose own Host is
        // null but whose ancestor folder carries one (mRemoteNG import shape) still surfaces
        // the host it would actually connect to — matching InheritanceResolver's host rule.
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", Host = "bastion.example.com" };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "ignored", 22, "alice");
        child.ParentId = folder.Id;
        child.Host = null;
        await _repo.AddAsync(child);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var childVm = vm.Roots.Single().Children.Single();
        Assert.Equal("bastion.example.com", childVm.Host);
    }

    [Fact]
    public async Task Host_ConnectionWithBlankOwnHost_IsNullDespiteAncestorHost()
    {
        // InheritanceResolver uses null-only inheritance (host ??= current.Host) then rejects
        // a blank result, so a connection whose own Host is blank can't actually open even if
        // an ancestor has one. The tooltip must mirror that and stay silent rather than
        // advertise the ancestor's host.
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", Host = "bastion.example.com" };
        await _repo.AddAsync(folder);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "ignored", 22, "alice");
        child.ParentId = folder.Id;
        child.Host = "   ";
        await _repo.AddAsync(child);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        Assert.Null(vm.Roots.Single().Children.Single().Host);
    }

    [Fact]
    public async Task Host_FolderNode_IsNull()
    {
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", Host = "bastion.example.com" };
        await _repo.AddAsync(folder);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        // Folders never show a host tooltip even when they carry a host for inheritance.
        Assert.Null(vm.Roots.Single().Host);
    }

    [Fact]
    public async Task ShowCredentials_ConnectionWithoutCredential_DoesNotRevealSecret()
    {
        var node = MakeConnectionDraft("keyonly", ProtocolType.Ssh, "host", 22, "alice");
        node.CredentialId = null;
        await _repo.AddAsync(node);

        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.ShowCredentialsCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(0, dialog.ShowCredentialsCount);
    }

    [Fact]
    public async Task ShowCredentials_OnFolder_IsNoOp()
    {
        var credentialId = Guid.NewGuid();
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "prod", CredentialId = credentialId };
        await _repo.AddAsync(folder);

        var dialog = new FakeDialogService();
        var creds = new FakeCredentialService();
        creds.Passwords[credentialId] = "should-not-show";
        var vm = CreateVm(dialog, creds);
        await vm.RefreshAsync();

        await vm.ShowCredentialsCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(0, dialog.ShowCredentialsCount);
    }

    [Fact]
    public async Task Duplicate_Connection_CopiesFieldsWithSuffix()
    {
        var credentialId = Guid.NewGuid();
        var gatewayCredentialId = Guid.NewGuid();
        var tunnelId = Guid.NewGuid();
        var node = MakeConnectionDraft("prod-web", ProtocolType.Rdp, "host.example.com", 3389, "alice");
        node.CredentialId = credentialId;
        node.RdpGatewayCredentialId = gatewayCredentialId;
        node.TunnelConfigId = tunnelId;
        node.TunnelEnabled = true;
        await _repo.AddAsync(node);

        var vm = CreateVm();
        await vm.RefreshAsync();

        await vm.DuplicateCommand.ExecuteAsync(vm.Roots.Single());

        var rows = await _repo.GetAllAsync();
        Assert.Equal(2, rows.Count);
        var copy = rows.Single(r => r.Id != node.Id);
        Assert.Equal("prod-web (copy)", copy.Name);
        Assert.Equal(node.ParentId, copy.ParentId);
        Assert.Equal(ProtocolType.Rdp, copy.Protocol);
        Assert.Equal("host.example.com", copy.Host);
        Assert.Equal(3389, copy.Port);
        Assert.Equal("alice", copy.Username);
        Assert.Equal(credentialId, copy.CredentialId);
        // Shared-pool credential/tunnel references are reused by design (see the Duplicate command).
        Assert.Equal(gatewayCredentialId, copy.RdpGatewayCredentialId);
        Assert.Equal(tunnelId, copy.TunnelConfigId);
        Assert.True(copy.TunnelEnabled);
        // The copy is appended after its source rather than colliding with its sort order.
        Assert.True(copy.SortOrder > node.SortOrder);
        Assert.Equal(2, vm.Roots.Count);
    }

    [Fact]
    public async Task Duplicate_NestedConnection_StaysInSameFolder()
    {
        // Seed the folder + child directly (like the sibling Duplicate tests) rather than
        // driving the add commands — this test only cares that a duplicate keeps a non-null parent.
        var folder = new ConnectionNode { Kind = NodeKind.Folder, Name = "Parent" };
        await _repo.AddAsync(folder);
        var leaf = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", 22, "alice");
        leaf.ParentId = folder.Id;
        await _repo.AddAsync(leaf);

        var vm = CreateVm();
        await vm.RefreshAsync();
        var folderVm = vm.Roots.Single();

        await vm.DuplicateCommand.ExecuteAsync(folderVm.Children.Single());

        var copy = (await _repo.GetAllAsync()).Single(n => n.Name == "leaf (copy)");
        Assert.Equal(folder.Id, copy.ParentId);
        Assert.Equal(2, folderVm.Children.Count);
    }

    [Fact]
    public async Task Duplicate_Connection_ClearsSshHostFingerprint()
    {
        // The duplicate is a new identity meant to be repointed at a different host, so it must
        // start unpinned and TOFU-pin on first connect. Carrying the source's pin over would make
        // SshHostKeyValidator.Decide return Mismatch for a different host and reject the connect.
        var node = MakeConnectionDraft("ssh-box", ProtocolType.Ssh, "host", 22, "alice");
        node.SshKnownHostFingerprint = "SHA256:original-pin";
        await _repo.AddAsync(node);

        var vm = CreateVm();
        await vm.RefreshAsync();

        await vm.DuplicateCommand.ExecuteAsync(vm.Roots.Single());

        var rows = await _repo.GetAllAsync();
        Assert.Null(rows.Single(r => r.Id != node.Id).SshKnownHostFingerprint);
        // The source's own pin is untouched.
        Assert.Equal("SHA256:original-pin", rows.Single(r => r.Id == node.Id).SshKnownHostFingerprint);
    }

    [Fact]
    public async Task Duplicate_OnFolder_IsNoOp()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Linux" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        await vm.DuplicateCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Single(await _repo.GetAllAsync());
    }

    [Fact]
    public async Task AddConnection_NullPortAndUsername_StoredAsNull()
    {
        var dialog = new FakeDialogService
        {
            EditConnectionResult = MakeConnectionDraft("host-only", ProtocolType.Rdp, "vm.example.com", null, null),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Null(row.Port);
        Assert.Null(row.Username);
    }

    [Fact]
    public async Task AddFolder_AssignsAscendingSortOrderAmongSiblings()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        foreach (var name in new[] { "A", "B", "C" })
        {
            dialog.TextPromptResult = name;
            await vm.AddFolderCommand.ExecuteAsync(null);
        }

        var rows = (await _repo.GetAllAsync()).OrderBy(r => r.SortOrder).ToList();
        Assert.Equal(ExpectedSortOrderAbc, rows.Select(r => r.Name));
        Assert.True(rows[0].SortOrder < rows[1].SortOrder);
        Assert.True(rows[1].SortOrder < rows[2].SortOrder);
    }

    [Fact]
    public async Task RefreshAsync_PopulatesRootsWithHierarchy()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parentVm = vm.Roots.Single();

        dialog.EditConnectionResult = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(parentVm);

        var root = Assert.Single(vm.Roots);
        Assert.Equal("Parent", root.Name);
        var child = Assert.Single(root.Children);
        Assert.Equal("leaf", child.Name);
        Assert.Equal(NodeKind.Connection, child.Kind);
    }

    [Fact]
    public async Task RefreshAsync_InitialLoadBulkReplacesRootLevel()
    {
        await _repo.AddAsync(new ConnectionNode { Kind = NodeKind.Folder, Name = "A", SortOrder = 0 });
        await _repo.AddAsync(new ConnectionNode { Kind = NodeKind.Folder, Name = "B", SortOrder = 1 });
        await _repo.AddAsync(new ConnectionNode { Kind = NodeKind.Folder, Name = "C", SortOrder = 2 });

        var vm = CreateVm();
        var addEvents = 0;
        var resetEvents = 0;
        vm.Roots.CollectionChanged += (_, args) =>
        {
            if (args.Action == NotifyCollectionChangedAction.Add) addEvents++;
            if (args.Action == NotifyCollectionChangedAction.Reset) resetEvents++;
        };

        await vm.RefreshAsync();

        Assert.Equal(0, addEvents);
        Assert.Equal(1, resetEvents);
        Assert.Equal(ExpectedSortOrderAbc, vm.Roots.Select(r => r.Name));
    }

    [Fact]
    public async Task RefreshAsync_PreservesExpandedAndSelectedNodes()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);

        dialog.EditConnectionResult = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        var parentVm = vm.Roots.Single();
        parentVm.IsExpanded = true;
        vm.SelectedNode = parentVm.Children.Single();

        dialog.TextPromptResult = "Sibling";
        await vm.AddFolderCommand.ExecuteAsync(null);

        var rebuiltParent = vm.Roots.Single(r => r.Name == "Parent");
        Assert.True(rebuiltParent.IsExpanded);
        Assert.NotNull(vm.SelectedNode);
        Assert.Equal("leaf", vm.SelectedNode!.Name);
    }

    [Fact]
    public async Task AddFolder_CancelledDialog_DoesNotPersist()
    {
        var dialog = new FakeDialogService { TextPromptResult = null };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddFolderCommand.ExecuteAsync(null);

        Assert.Empty(await _repo.GetAllAsync());
        Assert.Empty(vm.Roots);
    }

    [Fact]
    public async Task AddConnection_CancelledDialog_DoesNotPersist()
    {
        var dialog = new FakeDialogService { EditConnectionResult = null };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddConnectionCommand.ExecuteAsync(null);

        Assert.Empty(await _repo.GetAllAsync());
    }

    [Fact]
    public async Task PersistTreeStructure_ConnectionMovedOutOfFolder_UpdatesParentToNull()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Linux";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.EditConnectionResult = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        var folder = vm.Roots.Single();
        var connection = folder.Children.Single();
        folder.Children.Remove(connection);
        vm.Roots.Add(connection);

        await vm.PersistTreeStructureAsync();

        var rows = await _repo.GetAllAsync();
        Assert.Null(rows.Single(r => r.Name == "prod-web").ParentId);
    }

    [Fact]
    public async Task PersistTreeStructure_FolderMovedIntoAnotherFolder_UpdatesParent()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "A";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.TextPromptResult = "B";
        await vm.AddFolderCommand.ExecuteAsync(null);

        var a = vm.Roots.Single(r => r.Name == "A");
        var b = vm.Roots.Single(r => r.Name == "B");

        vm.Roots.Remove(b);
        a.Children.Add(b);

        await vm.PersistTreeStructureAsync();

        var bRow = (await _repo.GetAllAsync()).Single(r => r.Name == "B");
        Assert.Equal(a.Node.Id, bRow.ParentId);
    }

    [Fact]
    public async Task PersistTreeStructure_MoveIntoFolderWithHost_RefreshesInheritedHostTooltip()
    {
        // Drag-drop mutates ParentId in place without reassigning Node, so the computed Host
        // tooltip (one-way x:Bind) must be re-raised — including for descendants whose own
        // ParentId is unchanged but whose inherited host changes because an ancestor moved.
        var gateway = new ConnectionNode { Kind = NodeKind.Folder, Name = "gateway", Host = "g-host" };
        await _repo.AddAsync(gateway);
        var group = new ConnectionNode { Kind = NodeKind.Folder, Name = "group" };
        await _repo.AddAsync(group);
        var child = MakeConnectionDraft("web", ProtocolType.Ssh, "ignored", 22, "alice");
        child.ParentId = group.Id;
        child.Host = null;
        await _repo.AddAsync(child);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var gatewayVm = vm.Roots.Single(r => r.Name == "gateway");
        var groupVm = vm.Roots.Single(r => r.Name == "group");
        var childVm = groupVm.Children.Single();
        Assert.Null(childVm.Host); // no host anywhere up the chain yet

        var hostRaised = 0;
        childVm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(TreeNodeViewModel.Host)) hostRaised++;
        };

        // Move "group" (and its child) under "gateway", which carries the inherited host.
        vm.Roots.Remove(groupVm);
        gatewayVm.Children.Add(groupVm);
        await vm.PersistTreeStructureAsync();

        Assert.Equal("g-host", childVm.Host);
        Assert.True(hostRaised > 0, "Host PropertyChanged should fire for the moved subtree.");
    }

    [Fact]
    public async Task PersistTreeStructure_ReorderSiblings_UpdatesSortOrder()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        foreach (var name in new[] { "A", "B", "C" })
        {
            dialog.TextPromptResult = name;
            await vm.AddFolderCommand.ExecuteAsync(null);
        }

        var a = vm.Roots[0];
        vm.Roots.RemoveAt(0);
        vm.Roots.Add(a);

        await vm.PersistTreeStructureAsync();

        var rows = (await _repo.GetAllAsync()).OrderBy(r => r.SortOrder).ToList();
        Assert.Equal(ExpectedReorderBca, rows.Select(r => r.Name));
    }

    [Fact]
    public async Task PersistTreeStructure_MultipleRootEntriesMovedIntoFolder_UpdatesParentsAndPreservesSubtree()
    {
        var target = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Target",
            SortOrder = 0,
            Host = "gateway.example.com",
        };
        var group = new ConnectionNode { Kind = NodeKind.Folder, Name = "Group", SortOrder = 1 };
        var nested = MakeConnectionDraft("nested", ProtocolType.Ssh, "ignored", 22, "alice");
        nested.ParentId = group.Id;
        nested.SortOrder = 0;
        nested.Host = null;
        var leaf = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", 22, "bob");
        leaf.SortOrder = 2;

        await _repo.AddAsync(target);
        await _repo.AddAsync(group);
        await _repo.AddAsync(nested);
        await _repo.AddAsync(leaf);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var targetVm = vm.Roots.Single(r => r.Name == "Target");
        var groupVm = vm.Roots.Single(r => r.Name == "Group");
        var leafVm = vm.Roots.Single(r => r.Name == "leaf");
        var nestedVm = groupVm.Children.Single();
        Assert.Null(nestedVm.Host);

        vm.Roots.Remove(groupVm);
        vm.Roots.Remove(leafVm);
        targetVm.Children.Add(groupVm);
        targetVm.Children.Add(leafVm);

        await vm.PersistTreeStructureAsync();

        var rows = await _repo.GetAllAsync();
        Assert.Equal(target.Id, rows.Single(r => r.Name == "Group").ParentId);
        Assert.Equal(target.Id, rows.Single(r => r.Name == "leaf").ParentId);
        Assert.Equal(group.Id, rows.Single(r => r.Name == "nested").ParentId);
        Assert.Equal(0, rows.Single(r => r.Name == "Group").SortOrder);
        Assert.Equal(1, rows.Single(r => r.Name == "leaf").SortOrder);
        Assert.Equal("gateway.example.com", nestedVm.Host);
    }

    [Fact]
    public async Task PersistTreeStructure_MultipleRootEntriesReorderedTogether_UpdatesSortOrder()
    {
        foreach (var (name, order) in new[] { ("A", 0), ("B", 1), ("C", 2), ("D", 3) })
        {
            await _repo.AddAsync(new ConnectionNode
            {
                Kind = NodeKind.Folder,
                Name = name,
                SortOrder = order,
            });
        }

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var b = vm.Roots.Single(r => r.Name == "B");
        var c = vm.Roots.Single(r => r.Name == "C");
        vm.Roots.Remove(b);
        vm.Roots.Remove(c);
        vm.Roots.Add(b);
        vm.Roots.Add(c);

        await vm.PersistTreeStructureAsync();

        var rows = (await _repo.GetAllAsync()).Where(r => r.ParentId is null).OrderBy(r => r.SortOrder).ToList();
        Assert.Equal(ExpectedReorderAdbc, rows.Select(r => r.Name));
    }

    [Fact]
    public async Task ShouldRejectDragSelection_RejectsAncestorAndDescendantPayloadOnly()
    {
        var parent = new ConnectionNode { Kind = NodeKind.Folder, Name = "Parent", SortOrder = 0 };
        var child = MakeConnectionDraft("child", ProtocolType.Ssh, "child.example.com", 22, "alice");
        child.ParentId = parent.Id;
        var sibling = MakeConnectionDraft("sibling", ProtocolType.Ssh, "sibling.example.com", 22, "bob");
        sibling.SortOrder = 1;

        await _repo.AddAsync(parent);
        await _repo.AddAsync(child);
        await _repo.AddAsync(sibling);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var parentVm = vm.Roots.Single(r => r.Name == "Parent");
        var childVm = parentVm.Children.Single();
        var siblingVm = vm.Roots.Single(r => r.Name == "sibling");

        Assert.True(vm.ShouldRejectDragSelection(new[] { parentVm, childVm }));
        Assert.False(vm.ShouldRejectDragSelection(new[] { parentVm, siblingVm }));
        Assert.False(vm.ShouldRejectDragSelection(new[] { childVm, siblingVm }));
    }

    [Fact]
    public async Task PersistTreeStructure_InvalidMultiDrop_RevertsAndKeepsDb()
    {
        var parent = new ConnectionNode { Kind = NodeKind.Folder, Name = "Parent", SortOrder = 0 };
        var child = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Child",
            ParentId = parent.Id,
            SortOrder = 0,
        };
        var sibling = new ConnectionNode { Kind = NodeKind.Folder, Name = "Sibling", SortOrder = 1 };
        await _repo.AddAsync(parent);
        await _repo.AddAsync(child);
        await _repo.AddAsync(sibling);

        var vm = CreateVm(new FakeDialogService());
        await vm.RefreshAsync();

        var parentVm = vm.Roots.Single(r => r.Name == "Parent");
        var childVm = parentVm.Children.Single();
        var siblingVm = vm.Roots.Single(r => r.Name == "Sibling");
        vm.SetSelectedNodes(new[] { parentVm, siblingVm });

        vm.Roots.Remove(parentVm);
        vm.Roots.Remove(siblingVm);
        childVm.Children.Add(parentVm);
        childVm.Children.Add(siblingVm);

        await vm.PersistTreeStructureAsync();

        var rows = await _repo.GetAllAsync();
        Assert.Null(rows.Single(r => r.Name == "Parent").ParentId);
        Assert.Null(rows.Single(r => r.Name == "Sibling").ParentId);
        Assert.Equal(parent.Id, rows.Single(r => r.Name == "Child").ParentId);
        Assert.Equal(ExpectedParentSibling, vm.Roots.Select(r => r.Name));
        Assert.Equal("Child", vm.Roots.Single(r => r.Name == "Parent").Children.Single().Name);
    }

    [Fact]
    public async Task PersistTreeStructure_FolderDroppedIntoOwnChild_RevertsAndKeepsDb()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parent = vm.Roots.Single();
        dialog.TextPromptResult = "Child";
        await vm.AddFolderCommand.ExecuteAsync(parent);
        var child = vm.Roots.Single().Children.Single();

        vm.Roots.Remove(parent);
        child.Children.Add(parent);
        Assert.Empty(vm.Roots);

        await vm.PersistTreeStructureAsync();

        var rows = await _repo.GetAllAsync();
        var parentRow = rows.Single(r => r.Name == "Parent");
        var childRow = rows.Single(r => r.Name == "Child");
        Assert.Null(parentRow.ParentId);
        Assert.Equal(parentRow.Id, childRow.ParentId);
        Assert.Single(vm.Roots);
        Assert.Equal("Parent", vm.Roots.Single().Name);
        Assert.Equal("Child", vm.Roots.Single().Children.Single().Name);
    }

    [Fact]
    public async Task Edit_FolderRename_UpdatesName()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Linux" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        dialog.TextPromptResult = "Servers";
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal("Servers", (await _repo.GetAllAsync()).Single().Name);
    }

    [Fact]
    public async Task Edit_ConnectionUpdates_PersistsAllFields()
    {
        var dialog = new FakeDialogService
        {
            EditConnectionResult = MakeConnectionDraft("prod-web", ProtocolType.Ssh, "old.example.com", 22, "old"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);

        dialog.EditConnectionResult = MakeConnectionDraft("prod-web-2", ProtocolType.Rdp, "new.example.com", 3389, "alice");
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal("prod-web-2", row.Name);
        Assert.Equal(ProtocolType.Rdp, row.Protocol);
        Assert.Equal("new.example.com", row.Host);
        Assert.Equal(3389, row.Port);
        Assert.Equal("alice", row.Username);
    }

    [Fact]
    public async Task Edit_CancelledDialog_DoesNotChange()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        dialog.TextPromptResult = null;
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal("F", (await _repo.GetAllAsync()).Single().Name);
    }

    [Fact]
    public async Task Delete_Leaf_RemovesRow()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Empty(await _repo.GetAllAsync());
        Assert.Empty(vm.Roots);
    }

    [Fact]
    public async Task Delete_FolderWithChildren_CascadesAtTheDbLayer()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.EditConnectionResult = MakeConnectionDraft("leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Empty(await _repo.GetAllAsync());
    }

    [Fact]
    public async Task Delete_Cancelled_KeepsNode()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F", ConfirmResult = false };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Single(await _repo.GetAllAsync());
    }

    [Fact]
    public async Task RefreshAsync_PreservesTreeNodeViewModelIdentity()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);
        var vmBefore = vm.Roots.Single();

        await vm.RefreshAsync();

        Assert.Same(vmBefore, vm.Roots.Single());
    }

    [Fact]
    public async Task RefreshAsync_ReordersExistingRootNodesWithoutReplacingViewModels()
    {
        var a = new ConnectionNode { Kind = NodeKind.Folder, Name = "A", SortOrder = 0 };
        var b = new ConnectionNode { Kind = NodeKind.Folder, Name = "B", SortOrder = 1 };
        var c = new ConnectionNode { Kind = NodeKind.Folder, Name = "C", SortOrder = 2 };
        await _repo.AddAsync(a);
        await _repo.AddAsync(b);
        await _repo.AddAsync(c);

        var vm = CreateVm();
        await vm.RefreshAsync();
        var beforeByName = vm.Roots.ToDictionary(node => node.Name);

        c.SortOrder = 0;
        a.SortOrder = 1;
        b.SortOrder = 2;
        await _repo.UpdateManyAsync(new[] { a, b, c });

        await vm.RefreshAsync();

        Assert.Equal(ExpectedReorderCab, vm.Roots.Select(node => node.Name));
        Assert.Same(beforeByName["C"], vm.Roots[0]);
        Assert.Same(beforeByName["A"], vm.Roots[1]);
        Assert.Same(beforeByName["B"], vm.Roots[2]);
    }

    [Fact]
    public async Task OpenConnectionAsync_UsesLoadedSnapshotWithoutReloadingRepository()
    {
        await _repo.AddAsync(MakeConnectionDraft("prod-web", ProtocolType.Ssh, "host", null, "alice"));
        var countingRepo = new CountingConnectionRepository(_repo);
        var tabs = new CapturingSessionTabFactory();
        var vm = new ConnectionTreeViewModel(
            countingRepo,
            new InheritanceResolver(),
            tabs,
            new FakeDialogService(),
            new FakeCredentialService(),
            new FakeCredentialRepository(),
            NullLogger<ConnectionTreeViewModel>.Instance);
        vm.SearchDebounceDelay = TimeSpan.Zero;
        await vm.RefreshAsync();
        countingRepo.GetAllCallCount = 0;

        await vm.OpenConnectionCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(0, countingRepo.GetAllCallCount);
        Assert.NotNull(tabs.LastOpened);
        Assert.Equal("host", tabs.LastOpened!.Host);
        Assert.Equal("alice", tabs.LastOpened.Username);
    }

    [Fact]
    public async Task Edit_RaisesNameAndGlyphPropertyChangedOnExistingVm()
    {
        var dialog = new FakeDialogService { TextPromptResult = "old" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);
        var nodeVm = vm.Roots.Single();
        var changed = new List<string>();
        nodeVm.PropertyChanged += (_, e) => changed.Add(e.PropertyName!);

        dialog.TextPromptResult = "new";
        await vm.EditCommand.ExecuteAsync(nodeVm);

        Assert.Same(nodeVm, vm.Roots.Single());
        Assert.Equal("new", nodeVm.Name);
        Assert.Contains(nameof(TreeNodeViewModel.Name), changed);
    }

    [Fact]
    public async Task RefreshAsync_DroppedSelectedNode_ClearsSelection()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);
        vm.SelectedNode = vm.Roots.Single();

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Null(vm.SelectedNode);
    }

    [Fact]
    public async Task PersistTreeStructure_NoMovement_DoesNothing()
    {
        var dialog = new FakeDialogService { TextPromptResult = "F" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        var beforeUpdated = (await _repo.GetAllAsync()).Single().UpdatedAt;

        await vm.PersistTreeStructureAsync();

        var afterUpdated = (await _repo.GetAllAsync()).Single().UpdatedAt;
        Assert.Equal(beforeUpdated, afterUpdated);
    }

    [Fact]
    public async Task Edit_RepositoryFailure_RevertsInMemoryName()
    {
        var failing = new ThrowOnUpdateRepository(_repo);
        var dialog = new FakeDialogService { TextPromptResult = "original" };
        var vm = new ConnectionTreeViewModel(
            failing,
            new InheritanceResolver(),
            new NullSessionTabFactory(),
            dialog,
            new FakeCredentialService(),
            new FakeCredentialRepository(),
            NullLogger<ConnectionTreeViewModel>.Instance);
        vm.SearchDebounceDelay = TimeSpan.Zero;
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        failing.ThrowNext = true;
        dialog.TextPromptResult = "renamed";
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal("original", vm.Roots.Single().Name);
        Assert.Equal("original", (await _repo.GetAllAsync()).Single().Name);
    }

    [Fact]
    public async Task SearchText_EmptyByDefault_AllNodesVisible()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(string.Empty, vm.SearchText);
        var parent = vm.Roots.Single();
        Assert.True(parent.IsVisible);
        Assert.True(parent.Children.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_MatchesConnectionByName_OnlyThatBranchVisible()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Servers";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.TextPromptResult = "Other";
        await vm.AddFolderCommand.ExecuteAsync(null);

        var servers = vm.Roots.Single(r => r.Name == "Servers");
        var other = vm.Roots.Single(r => r.Name == "Other");

        dialog.EditConnectionResult = MakeConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(servers);
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(other);

        vm.SearchText = "prod";

        Assert.True(servers.IsVisible);
        Assert.True(servers.Children.Single().IsVisible);
        Assert.False(other.IsVisible);
        Assert.False(other.Children.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_MatchesNestedConnection_AutoExpandsAncestorFolder()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parent = vm.Roots.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(parent);

        Assert.False(parent.IsExpanded);

        vm.SearchText = "prod";

        Assert.True(parent.IsExpanded);
        Assert.True(parent.IsVisible);
        Assert.True(parent.Children.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_MatchesFolderName_ShowsAndExpandsFolderWithChildren()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Linux";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var folder = vm.Roots.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "alpha", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(folder);
        dialog.EditConnectionResult = MakeConnectionDraft(
            "beta", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(folder);

        Assert.False(folder.IsExpanded);

        vm.SearchText = "Lin";

        Assert.True(folder.IsVisible);
        Assert.True(folder.IsExpanded);
        Assert.All(folder.Children, child => Assert.True(child.IsVisible));
    }

    [Fact]
    public async Task SearchText_FolderNameMatchCleared_RestoresCollapsedState()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Linux";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var folder = vm.Roots.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "alpha", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(folder);

        Assert.False(folder.IsExpanded);

        vm.SearchText = "Lin";
        Assert.True(folder.IsExpanded);

        vm.SearchText = string.Empty;
        Assert.False(folder.IsExpanded);
    }

    [Fact]
    public async Task SearchText_FolderNameMatch_DoesNotExpandDescendantFolders()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Linux";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parent = vm.Roots.Single();
        dialog.TextPromptResult = "Nested";
        await vm.AddFolderCommand.ExecuteAsync(parent);
        var child = parent.Children.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(child);

        vm.SearchText = "Linux";

        Assert.True(parent.IsExpanded);
        Assert.False(child.IsExpanded);
        Assert.True(child.IsVisible);
        Assert.True(child.Children.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_CaseInsensitive()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Linux" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        vm.SearchText = "LINUX";

        Assert.True(vm.Roots.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_Cleared_RestoresPriorExpandedState()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parent = vm.Roots.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(parent);

        // User left the folder collapsed before searching.
        Assert.False(parent.IsExpanded);

        // Search force-expands the parent so the matching child is visible.
        vm.SearchText = "leaf";
        Assert.True(parent.IsExpanded);

        // Clearing the search must restore the prior collapsed state.
        vm.SearchText = string.Empty;
        Assert.False(parent.IsExpanded);
        Assert.True(parent.IsVisible);
        Assert.True(parent.Children.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_NoMatches_AllNodesHidden()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        vm.SearchText = "zzz-no-match-zzz";

        var parent = vm.Roots.Single();
        Assert.False(parent.IsVisible);
        Assert.False(parent.Children.Single().IsVisible);
    }

    [Fact]
    public async Task RefreshAsync_WhileFiltered_ReappliesFilterToNewNodes()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);

        vm.SearchText = "prod";

        // Adding a connection triggers RefreshAsync internally. The new node must be
        // evaluated against the live filter, not appear with its default IsVisible=true.
        dialog.EditConnectionResult = MakeConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        var parent = vm.Roots.Single();
        Assert.True(parent.IsVisible);
        Assert.True(parent.Children.Single(c => c.Name == "prod-web").IsVisible);

        // And an unrelated new connection added under the same filter must stay hidden.
        dialog.EditConnectionResult = MakeConnectionDraft(
            "other", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(parent);

        Assert.False(parent.Children.Single(c => c.Name == "other").IsVisible);
    }

    [Fact]
    public async Task SearchText_WhitespaceOnly_TreatsAsEmpty()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Item" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        vm.SearchText = "   ";

        Assert.True(vm.Roots.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_LeadingTrailingSpaces_MatchTrimmedQuery()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Linux" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        vm.SearchText = "  Lin  ";

        Assert.True(vm.Roots.Single().IsVisible);
    }

    [Fact]
    public async Task SearchText_NestedMatchAndClear_RestoresEveryAncestorExpansion()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);
        var parent = vm.Roots.Single();
        dialog.TextPromptResult = "Child";
        await vm.AddFolderCommand.ExecuteAsync(parent);
        var child = parent.Children.Single();
        dialog.EditConnectionResult = MakeConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(child);

        Assert.False(parent.IsExpanded);
        Assert.False(child.IsExpanded);

        vm.SearchText = "leaf";
        Assert.True(parent.IsExpanded);
        Assert.True(child.IsExpanded);

        vm.SearchText = string.Empty;
        Assert.False(parent.IsExpanded);
        Assert.False(child.IsExpanded);
    }

    [Fact]
    public async Task SearchText_DeepTree_DoesNotOverflowAndRestoresExpansion()
    {
        await SeedDeepTreeAsync(DeepTreeDepth, "needle-leaf");
        var vm = CreateVm();
        await vm.RefreshAsync();

        var root = vm.Roots.Single();
        var leaf = GetDeepestNode(root);
        Assert.Equal(NodeKind.Connection, leaf.Kind);
        AssertNoFoldersExpanded(root);

        vm.SearchText = "needle";

        Assert.True(root.IsVisible);
        Assert.True(leaf.IsVisible);
        AssertAllFoldersExpanded(root);

        vm.SearchText = string.Empty;

        Assert.True(root.IsVisible);
        Assert.True(leaf.IsVisible);
        AssertNoFoldersExpanded(root);
    }

    [Fact]
    public async Task ExpandCollapseAll_DeepTree_DoesNotOverflow()
    {
        await SeedDeepTreeAsync(DeepTreeDepth, "leaf");
        var vm = CreateVm();
        await vm.RefreshAsync();

        var root = vm.Roots.Single();

        vm.ExpandAllCommand.Execute(null);
        AssertAllFoldersExpanded(root);

        vm.CollapseAllCommand.Execute(null);
        AssertNoFoldersExpanded(root);
    }

    [Fact]
    public async Task Delete_DeepTreeCountsDescendantsWithoutOverflow()
    {
        await SeedDeepTreeAsync(DeepTreeDepth, "leaf");
        var dialog = new RecordingConfirmDialogService { ConfirmResult = false };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.DeleteCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Contains($"{DeepTreeDepth} nested items", dialog.LastConfirmMessage);
    }

    [Fact]
    public async Task Delete_DeepTreeCanonicalizesSelectedDescendantWithoutOverflow()
    {
        await SeedDeepTreeAsync(DeepTreeDepth, "leaf");
        var dialog = new RecordingConfirmDialogService { ConfirmResult = false };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        var root = vm.Roots.Single();
        var leaf = GetDeepestNode(root);
        vm.SetSelectedNodes(new[] { root, leaf });

        await vm.DeleteCommand.ExecuteAsync(null);

        Assert.Equal(1, dialog.ConfirmCount);
        Assert.Contains($"{DeepTreeDepth} nested items", dialog.LastConfirmMessage);
    }

    [Fact]
    public async Task AddFolder_WithTunnel_PersistsTunnelFields()
    {
        var tunnelId = Guid.NewGuid();
        var dialog = new FakeDialogService
        {
            EditFolderResult = new ConnectionNode
            {
                Kind = NodeKind.Folder,
                Name = "Production",
                TunnelEnabled = true,
                TunnelConfigId = tunnelId,
            },
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddFolderCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal("Production", row.Name);
        Assert.Equal(NodeKind.Folder, row.Kind);
        Assert.True(row.TunnelEnabled);
        Assert.Equal(tunnelId, row.TunnelConfigId);
    }

    [Fact]
    public async Task AddFolder_WithCredential_PersistsCredentialFields()
    {
        var credentialId = Guid.NewGuid();
        var dialog = new FakeDialogService
        {
            EditFolderResult = new ConnectionNode
            {
                Kind = NodeKind.Folder,
                Name = "Production",
                CredentialMode = CredentialBindingMode.Saved,
                CredentialId = credentialId,
                Username = "admin",
            },
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.AddFolderCommand.ExecuteAsync(null);

        var row = Assert.Single(await _repo.GetAllAsync());
        Assert.Equal("Production", row.Name);
        Assert.Equal(NodeKind.Folder, row.Kind);
        Assert.Equal(CredentialBindingMode.Saved, row.CredentialMode);
        Assert.Equal(credentialId, row.CredentialId);
        Assert.Equal("admin", row.Username);
    }

    [Fact]
    public async Task Edit_FolderTunnelChange_PersistsTunnelFields()
    {
        // Start from a folder with no tunnel, then assign one via the editor and confirm both
        // tunnel fields land in the DB. This is the bug the folder editor was added to fix —
        // the inheritance resolver already walks folder TunnelEnabled/TunnelConfigId, but
        // before this dialog there was no way for the user to set them.
        var dialog = new FakeDialogService { TextPromptResult = "Production" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        var tunnelId = Guid.NewGuid();
        dialog.EditFolderResult = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Production",
            TunnelEnabled = true,
            TunnelConfigId = tunnelId,
        };
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.True(row.TunnelEnabled);
        Assert.Equal(tunnelId, row.TunnelConfigId);
    }

    [Fact]
    public async Task Edit_FolderCredentialChange_PersistsCredentialFields()
    {
        var dialog = new FakeDialogService { TextPromptResult = "Production" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddFolderCommand.ExecuteAsync(null);

        var credentialId = Guid.NewGuid();
        dialog.EditFolderResult = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Production",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credentialId,
            Username = "admin",
        };
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal(CredentialBindingMode.Saved, row.CredentialMode);
        Assert.Equal(credentialId, row.CredentialId);
        Assert.Equal("admin", row.Username);
    }

    [Fact]
    public async Task Edit_FolderRename_PreservesInheritedDefaultsOnFolder()
    {
        // Regression for codex PR review: folders carry inheritance defaults for their
        // descendants (mRemoteNG import populates Protocol / Host / Username / CredentialId
        // / RdpDomain on container nodes — see MRemoteNgImportService.Walk). The folder
        // editor only writes Name + tunnel, so a rename MUST round-trip every other field
        // untouched. Pre-fix, DialogService.EditFolderAsync used CloneIdentityFrom and
        // silently nulled all of them.
        var credentialId = Guid.NewGuid();
        var seed = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Linux Servers",
            Protocol = ProtocolType.Ssh,
            Host = "bastion.example.com",
            Port = 2222,
            Username = "admin",
            CredentialId = credentialId,
            CredentialMode = CredentialBindingMode.Saved,
            RdpDomain = "CORP",
        };
        await _repo.AddAsync(seed);

        var dialog = new FakeDialogService { TextPromptResult = "Linux Production" };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal("Linux Production", row.Name);
        // The inheritance defaults must survive the rename — otherwise descendants
        // that resolved through this folder lose their config.
        Assert.Equal(ProtocolType.Ssh, row.Protocol);
        Assert.Equal("bastion.example.com", row.Host);
        Assert.Equal(2222, row.Port);
        Assert.Equal("admin", row.Username);
        Assert.Equal(credentialId, row.CredentialId);
        Assert.Equal(CredentialBindingMode.Saved, row.CredentialMode);
        Assert.Equal("CORP", row.RdpDomain);
    }

    private async Task SeedDeepTreeAsync(int folderDepth, string leafName)
    {
        var now = DateTime.UtcNow;
        var nodes = new List<ConnectionNode>(folderDepth + 1);
        Guid? parentId = null;

        for (var i = 0; i < folderDepth; i++)
        {
            var node = new ConnectionNode
            {
                Id = Guid.NewGuid(),
                ParentId = parentId,
                Name = $"Folder {i:D4}",
                Kind = NodeKind.Folder,
                SortOrder = 0,
                CreatedAt = now,
                UpdatedAt = now,
            };
            nodes.Add(node);
            parentId = node.Id;
        }

        nodes.Add(new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = parentId,
            Name = leafName,
            Kind = NodeKind.Connection,
            SortOrder = 0,
            Protocol = ProtocolType.Ssh,
            Host = "host",
            CreatedAt = now,
            UpdatedAt = now,
        });

        using var connection = _factory.Open();
        using var tx = connection.BeginTransaction();
        await connection.ExecuteAsync(@"
            INSERT INTO Nodes (
                Id, ParentId, Name, Kind, SortOrder,
                Protocol, Host, CreatedAt, UpdatedAt
            ) VALUES (
                @Id, @ParentId, @Name, @Kind, @SortOrder,
                @Protocol, @Host, @CreatedAt, @UpdatedAt
            );", nodes, transaction: tx);
        tx.Commit();
    }

    private static TreeNodeViewModel GetDeepestNode(TreeNodeViewModel root)
    {
        var current = root;
        while (current.Children.Count > 0)
        {
            current = current.Children[0];
        }
        return current;
    }

    private static void AssertAllFoldersExpanded(TreeNodeViewModel root) =>
        AssertFolderExpansion(root, expanded: true);

    private static void AssertNoFoldersExpanded(TreeNodeViewModel root) =>
        AssertFolderExpansion(root, expanded: false);

    private static void AssertFolderExpansion(TreeNodeViewModel root, bool expanded)
    {
        var stack = new Stack<TreeNodeViewModel>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            if (node.Kind == NodeKind.Folder)
            {
                Assert.Equal(expanded, node.IsExpanded);
            }

            for (var i = node.Children.Count - 1; i >= 0; i--)
            {
                stack.Push(node.Children[i]);
            }
        }
    }

    private sealed class ThrowOnUpdateRepository : IConnectionRepository
    {
        private readonly IConnectionRepository _inner;
        public bool ThrowNext { get; set; }

        public ThrowOnUpdateRepository(IConnectionRepository inner) => _inner = inner;

        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(System.Threading.CancellationToken ct = default)
            => _inner.GetAllAsync(ct);
        public Task<ConnectionNode?> GetByIdAsync(Guid id, System.Threading.CancellationToken ct = default)
            => _inner.GetByIdAsync(id, ct);
        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(Guid tunnelConfigId, int limit, System.Threading.CancellationToken ct = default)
            => _inner.GetByTunnelConfigIdAsync(tunnelConfigId, limit, ct);
        public Task AddAsync(ConnectionNode node, System.Threading.CancellationToken ct = default)
            => _inner.AddAsync(node, ct);
        public Task UpdateAsync(ConnectionNode node, System.Threading.CancellationToken ct = default)
        {
            if (ThrowNext) { ThrowNext = false; throw new InvalidOperationException("simulated"); }
            return _inner.UpdateAsync(node, ct);
        }
        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, System.Threading.CancellationToken ct = default)
            => _inner.UpdateManyAsync(nodes, ct);
        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, System.Threading.CancellationToken ct = default)
            => _inner.UpdateHostFingerprintAsync(nodeId, fingerprint, ct);
        public Task DeleteAsync(Guid id, System.Threading.CancellationToken ct = default)
            => _inner.DeleteAsync(id, ct);
        public Task DeleteManyAsync(IReadOnlyCollection<Guid> ids, System.Threading.CancellationToken ct = default)
            => _inner.DeleteManyAsync(ids, ct);
    }

    private sealed class CountingConnectionRepository : IConnectionRepository
    {
        private readonly IConnectionRepository _inner;
        public int GetAllCallCount { get; set; }
        public IReadOnlyList<Guid> LastDeleteManyIds { get; private set; } = Array.Empty<Guid>();

        public CountingConnectionRepository(IConnectionRepository inner) => _inner = inner;

        public async Task<IReadOnlyList<ConnectionNode>> GetAllAsync(System.Threading.CancellationToken ct = default)
        {
            GetAllCallCount++;
            return await _inner.GetAllAsync(ct);
        }

        public Task<ConnectionNode?> GetByIdAsync(Guid id, System.Threading.CancellationToken ct = default)
            => _inner.GetByIdAsync(id, ct);
        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(Guid tunnelConfigId, int limit, System.Threading.CancellationToken ct = default)
            => _inner.GetByTunnelConfigIdAsync(tunnelConfigId, limit, ct);
        public Task AddAsync(ConnectionNode node, System.Threading.CancellationToken ct = default)
            => _inner.AddAsync(node, ct);
        public Task UpdateAsync(ConnectionNode node, System.Threading.CancellationToken ct = default)
            => _inner.UpdateAsync(node, ct);
        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, System.Threading.CancellationToken ct = default)
            => _inner.UpdateManyAsync(nodes, ct);
        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, System.Threading.CancellationToken ct = default)
            => _inner.UpdateHostFingerprintAsync(nodeId, fingerprint, ct);
        public Task DeleteAsync(Guid id, System.Threading.CancellationToken ct = default)
            => _inner.DeleteAsync(id, ct);
        public async Task DeleteManyAsync(IReadOnlyCollection<Guid> ids, System.Threading.CancellationToken ct = default)
        {
            LastDeleteManyIds = ids.ToArray();
            await _inner.DeleteManyAsync(ids, ct);
        }
    }

    private sealed class RecordingConfirmDialogService : FakeDialogService
    {
        public string? LastConfirmMessage { get; private set; }

        public override Task<bool> ConfirmAsync(
            string title,
            string message,
            string primaryText = "Yes",
            string closeText = "No")
        {
            LastConfirmMessage = message;
            return base.ConfirmAsync(title, message, primaryText, closeText);
        }
    }

    private sealed class NullSessionTabFactory : ISessionTabFactory
    {
        public void Open(ConnectionProfile profile) { /* tests don't exercise tab opening */ }
    }

    private sealed class CapturingSessionTabFactory : ISessionTabFactory
    {
        public ConnectionProfile? LastOpened { get; private set; }

        public void Open(ConnectionProfile profile) => LastOpened = profile;
    }
}
