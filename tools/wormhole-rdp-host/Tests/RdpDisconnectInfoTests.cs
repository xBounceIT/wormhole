using System.Runtime.InteropServices;
using Microsoft.CSharp.RuntimeBinder;
using Wormhole.Interop.Rdp;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpDisconnectInfoTests
{
    private const int RpcDisconnected = unchecked((int)0x80010108);

    [Fact]
    public void DisconnectInfo_ReadsTheNativeReasonAndDescriptionTogether()
    {
        var control = new DisconnectControl { Reason = 12 };

        var info = RdpHostForm.ReadDisconnectInfo(control, 1032);

        Assert.Equal((12, "Native description."), info);
        Assert.Equal((1032u, 12u), control.DescriptionArguments);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(7)]
    public void DisconnectInfo_PreservesTheReadReasonWhenDescriptionFails(int extendedReason)
    {
        Exception[] failures =
        [
            Marshal.GetExceptionForHR(RpcDisconnected)!,
            new RuntimeBinderException("Method unavailable."),
            new InvalidCastException(),
            new InvalidOperationException(),
            new ObjectDisposedException("control"),
        ];
        foreach (var failure in failures)
        {
            var control = new DisconnectControl { Reason = extendedReason, DescriptionFailure = failure };

            var info = RdpHostForm.ReadDisconnectInfo(control, 1032);

            Assert.Equal((extendedReason, "Disconnect reason 1032."), info);
        }
    }

    [Fact]
    public void DisconnectInfo_UsesNoInfoWhenTheNativeReasonCannotBeRead()
    {
        var control = new DisconnectControl { ReasonFailure = Marshal.GetExceptionForHR(RpcDisconnected) };

        var info = RdpHostForm.ReadDisconnectInfo(control, 2308);

        Assert.Equal((0, "Disconnect reason 2308."), info);
        Assert.Null(control.DescriptionArguments);
    }

    [Fact]
    public void DisconnectInfo_ToleratesMissingControlsAndMembers()
    {
        Assert.Equal((0, "Disconnect reason 3."), RdpHostForm.ReadDisconnectInfo(null, 3));
        Assert.Equal((0, "Disconnect reason 3."), RdpHostForm.ReadDisconnectInfo(new object(), 3));
    }

    public sealed class DisconnectControl
    {
        public int Reason { get; init; }
        public Exception? ReasonFailure { get; init; }
        public Exception? DescriptionFailure { get; init; }
        public (uint Code, uint Extended)? DescriptionArguments { get; private set; }

        public int ExtendedDisconnectReason => ReasonFailure is { } failure ? throw failure : Reason;

        public string GetErrorDescription(uint code, uint extended)
        {
            DescriptionArguments = (code, extended);
            if (DescriptionFailure is { } failure) throw failure;
            return "Native description.";
        }
    }
}
