using Wormhole.Models;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SessionTabViewModelTests
{
    [Fact]
    public void Initialize_WithParentFolderName_PrefixesTitle()
    {
        var vm = new TestSessionTab();

        vm.Initialize(CreateProfile() with { ParentFolderName = "prod" });

        Assert.Equal("prod / web-1", vm.Title);
    }

    [Fact]
    public void Initialize_WithoutParentFolderName_UsesConnectionName()
    {
        var vm = new TestSessionTab();

        vm.Initialize(CreateProfile());

        Assert.Equal("web-1", vm.Title);
    }

    [Fact]
    public void UpdateProfile_ReplacesProfileAndRefreshesTitle()
    {
        var vm = new TestSessionTab();
        var initial = CreateProfile(name: "old-name", host: "old-host");
        var updated = CreateProfile(name: "new-name", host: "new-host") with
        {
            NodeId = initial.NodeId,
            ParentFolderName = "prod",
        };
        var changed = new List<string?>();
        vm.Initialize(initial);
        vm.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        vm.UpdateProfile(updated);

        Assert.Same(updated, vm.Profile);
        Assert.Equal("prod / new-name", vm.Title);
        Assert.Contains(nameof(SessionTabViewModel.Title), changed);
        Assert.Contains(nameof(SessionTabViewModel.Profile), changed);
    }

    [Fact]
    public void UpdateProfile_UsesHostWhenNameIsEmpty()
    {
        var vm = new TestSessionTab();
        vm.Initialize(CreateProfile(name: "old-name", host: "old-host"));

        vm.UpdateProfile(CreateProfile(name: string.Empty, host: "fallback-host"));

        Assert.Equal("fallback-host", vm.Title);
    }

    [Fact]
    public void MarshalToUi_ActionException_IsReportedAndDoesNotEscape()
    {
        var vm = new TestSessionTab();
        var exception = new InvalidOperationException("simulated dispatch failure");

        vm.Dispatch(() => throw exception);

        Assert.Same(exception, vm.DispatchedException);
    }

    private static ConnectionProfile CreateProfile() =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = "web-1",
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            Port = 22,
        };

    private sealed class TestSessionTab : SessionTabViewModel
    {
        public Exception? DispatchedException { get; private set; }

        public override ProtocolType Protocol => ProtocolType.Ssh;

        public void Dispatch(Action action) => MarshalToUi(action);

        protected override void OnDispatchedException(Exception ex) => DispatchedException = ex;
    }

    private static ConnectionProfile CreateProfile(string name, string host) =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = name,
            Protocol = ProtocolType.Ssh,
            Host = host,
            Port = 22,
        };
}
