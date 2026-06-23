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
    public void UpdateProfile_RefreshesTitle()
    {
        var vm = new TestSessionTab();
        vm.Initialize(CreateProfile());

        vm.UpdateProfile(CreateProfile() with
        {
            ParentFolderName = "prod",
            Name = "web-2",
            Host = "web-2.prod",
        });

        Assert.Equal("prod / web-2", vm.Title);
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
}
