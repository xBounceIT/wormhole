using Wormhole.Models;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SessionTabViewModelTests
{
    [Fact]
    public void MarshalToUi_ActionException_IsReportedAndDoesNotEscape()
    {
        var vm = new TestSessionTab();
        var exception = new InvalidOperationException("simulated dispatch failure");

        vm.Dispatch(() => throw exception);

        Assert.Same(exception, vm.DispatchedException);
    }

    private sealed class TestSessionTab : SessionTabViewModel
    {
        public Exception? DispatchedException { get; private set; }

        public override ProtocolType Protocol => ProtocolType.Ssh;

        public void Dispatch(Action action) => MarshalToUi(action);

        protected override void OnDispatchedException(Exception ex) => DispatchedException = ex;
    }
}
