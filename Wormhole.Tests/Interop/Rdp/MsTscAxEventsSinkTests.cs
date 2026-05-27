using System;
using Wormhole.Interop.Rdp;
using Xunit;

namespace Wormhole.Tests.Interop.Rdp;

public sealed class MsTscAxEventsSinkTests
{
    [Fact]
    public void Safe_HandlerFaultAndDiagnosticFault_DoNotEscapeComDispatch()
    {
        var sink = new MsTscAxEventsSink((_, _) => throw new InvalidOperationException("diagnostic failure"));
        sink.Connected += () => throw new InvalidOperationException("handler failure");

        var ex = Record.Exception(() => sink.OnConnected());

        Assert.Null(ex);
    }
}
