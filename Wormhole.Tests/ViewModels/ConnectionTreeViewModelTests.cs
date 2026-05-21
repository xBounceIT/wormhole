using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class ConnectionTreeViewModelTests : IDisposable
{
    // Inlined from Data/Migrations/0001_initial.sql: the test project links source files
    // rather than referencing the main assembly, so the embedded .sql is not available.
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
            RdpDomain                TEXT     NULL,
            RdpScreenSize            TEXT     NULL,
            RdpFullScreen            INTEGER  NULL,
            SshKeyFileName           TEXT     NULL,
            SshKnownHostFingerprint  TEXT     NULL,
            CreatedAt                TEXT     NOT NULL,
            UpdatedAt                TEXT     NOT NULL
        );
        CREATE INDEX IX_Nodes_ParentId ON Nodes(ParentId);";

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
        // Scoped pool clear so other tests' connections aren't disturbed; required on
        // Windows to release the file lock before delete.
        SqliteConnection.ClearPool(new SqliteConnection(_connectionString));
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private ConnectionTreeViewModel CreateVm(FakeDialogService? dialog = null) => new(
        _repo,
        new InheritanceResolver(),
        new NullSessionTabFactory(),
        dialog ?? new FakeDialogService(),
        NullLogger<ConnectionTreeViewModel>.Instance);

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

        dialog.ConnectionPromptResult = new NewConnectionDraft("leaf", ProtocolType.Ssh, "h", null, null);
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
            ConnectionPromptResult = new NewConnectionDraft(
                "prod-web", ProtocolType.Ssh, "example.com", 2222, "daniel"),
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
        var dialog = new FakeDialogService
        {
            ConnectionPromptResult = new NewConnectionDraft(
                "prod-web", ProtocolType.Ssh, "example.com", 22, null, credentialId),
        };
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
            ConnectionPromptResult = new NewConnectionDraft(
                "prod", ProtocolType.Ssh, "host", 22, "alice"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);

        var credentialId = Guid.NewGuid();
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "prod", ProtocolType.Ssh, "host", 22, null, credentialId);
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal(credentialId, row.CredentialId);
    }

    [Fact]
    public async Task AddConnection_NullPortAndUsername_StoredAsNull()
    {
        var dialog = new FakeDialogService
        {
            ConnectionPromptResult = new NewConnectionDraft(
                "host-only", ProtocolType.Rdp, "vm.example.com", null, null),
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
        Assert.Equal(new[] { "A", "B", "C" }, rows.Select(r => r.Name));
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

        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(parentVm);

        var root = Assert.Single(vm.Roots);
        Assert.Equal("Parent", root.Name);
        var child = Assert.Single(root.Children);
        Assert.Equal("leaf", child.Name);
        Assert.Equal(NodeKind.Connection, child.Kind);
    }

    [Fact]
    public async Task RefreshAsync_PreservesExpandedAndSelectedNodes()
    {
        var dialog = new FakeDialogService();
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();

        dialog.TextPromptResult = "Parent";
        await vm.AddFolderCommand.ExecuteAsync(null);

        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        // Re-fetch from Roots: each refresh rebuilds TreeNodeViewModel instances.
        var parentVm = vm.Roots.Single();
        parentVm.IsExpanded = true;
        vm.SelectedNode = parentVm.Children.Single();

        // Force another full Roots rebuild.
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
        var dialog = new FakeDialogService { ConnectionPromptResult = null };
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        // Simulate the drag: pull the connection out of the folder and into Roots.
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

        // Drag B into A.
        vm.Roots.Remove(b);
        a.Children.Add(b);

        await vm.PersistTreeStructureAsync();

        var bRow = (await _repo.GetAllAsync()).Single(r => r.Name == "B");
        Assert.Equal(a.Node.Id, bRow.ParentId);
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

        // Move A to the end (drag past C).
        var a = vm.Roots[0];
        vm.Roots.RemoveAt(0);
        vm.Roots.Add(a);

        await vm.PersistTreeStructureAsync();

        var rows = (await _repo.GetAllAsync()).OrderBy(r => r.SortOrder).ToList();
        Assert.Equal(new[] { "B", "C", "A" }, rows.Select(r => r.Name));
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

        // The catastrophic drop: TreeView removes Parent from Roots and attaches it under
        // Child, so the resulting cycle is disconnected from Roots (Roots is now empty).
        vm.Roots.Remove(parent);
        child.Children.Add(parent);
        Assert.Empty(vm.Roots);

        await vm.PersistTreeStructureAsync();

        // DB untouched; in-memory tree restored from the DB.
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
            ConnectionPromptResult = new NewConnectionDraft(
                "prod-web", ProtocolType.Ssh, "old.example.com", 22, "old"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);

        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "prod-web-2", ProtocolType.Rdp, "new.example.com", 3389, "alice");
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        var row = (await _repo.GetAllAsync()).Single();
        Assert.Equal("prod-web-2", row.Name);
        Assert.Equal(ProtocolType.Rdp, row.Protocol);
        Assert.Equal("new.example.com", row.Host);
        Assert.Equal(3389, row.Port);
        Assert.Equal("alice", row.Username);
    }

    [Fact]
    public async Task Edit_ConnectionUnchanged_DoesNotWrite()
    {
        var dialog = new FakeDialogService
        {
            ConnectionPromptResult = new NewConnectionDraft(
                "prod", ProtocolType.Ssh, "host", 22, "alice"),
        };
        var vm = CreateVm(dialog);
        await vm.RefreshAsync();
        await vm.AddConnectionCommand.ExecuteAsync(null);
        var before = (await _repo.GetAllAsync()).Single().UpdatedAt;

        // Re-submit identical values.
        await vm.EditCommand.ExecuteAsync(vm.Roots.Single());

        Assert.Equal(before, (await _repo.GetAllAsync()).Single().UpdatedAt);
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "leaf", ProtocolType.Ssh, "host", null, null);
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
            NullLogger<ConnectionTreeViewModel>.Instance);
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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

        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(servers);
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "alpha", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(folder);
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "alpha", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(folder);

        Assert.False(folder.IsExpanded);

        vm.SearchText = "Lin";
        Assert.True(folder.IsExpanded);

        vm.SearchText = string.Empty;
        Assert.False(folder.IsExpanded);
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
            "prod-web", ProtocolType.Ssh, "host", null, null);
        await vm.AddConnectionCommand.ExecuteAsync(vm.Roots.Single());

        var parent = vm.Roots.Single();
        Assert.True(parent.IsVisible);
        Assert.True(parent.Children.Single(c => c.Name == "prod-web").IsVisible);

        // And an unrelated new connection added under the same filter must stay hidden.
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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
        dialog.ConnectionPromptResult = new NewConnectionDraft(
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

    private sealed class ThrowOnUpdateRepository : IConnectionRepository
    {
        private readonly IConnectionRepository _inner;
        public bool ThrowNext { get; set; }

        public ThrowOnUpdateRepository(IConnectionRepository inner) => _inner = inner;

        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(System.Threading.CancellationToken ct = default)
            => _inner.GetAllAsync(ct);
        public Task<ConnectionNode?> GetByIdAsync(Guid id, System.Threading.CancellationToken ct = default)
            => _inner.GetByIdAsync(id, ct);
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
    }

    private sealed class NullSessionTabFactory : ISessionTabFactory
    {
        public void Open(ConnectionProfile profile) { /* tests don't exercise tab opening */ }
    }

    private sealed class FakeDialogService : IDialogService
    {
        public string? TextPromptResult { get; set; }
        public NewConnectionDraft? ConnectionPromptResult { get; set; }
        public bool ConfirmResult { get; set; } = true;

        public Task ShowMessageAsync(string title, string message) => Task.CompletedTask;
        public Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No")
            => Task.FromResult(ConfirmResult);
        public Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "")
            => Task.FromResult(TextPromptResult);
        public Task<NewConnectionDraft?> PromptForConnectionAsync(NewConnectionDraft? initial = null)
            => Task.FromResult(ConnectionPromptResult);
        public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null)
            => Task.FromResult<CredentialDraft?>(null);
        public Task<string?> PromptPasswordAsync(string title, string message)
            => Task.FromResult<string?>(null);
    }
}
