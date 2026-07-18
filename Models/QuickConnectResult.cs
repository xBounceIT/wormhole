namespace Wormhole.Models;

/// <summary>
/// Accepted Quick Connect editor values. The optional password is deliberately kept separate
/// from both <see cref="ConnectionNode"/> and <see cref="ConnectionProfile"/> so it can be moved
/// directly into the process-local transient credential store.
/// </summary>
public sealed class QuickConnectResult
{
    public QuickConnectResult(ConnectionNode node, string? password)
    {
        Node = node;
        Password = password;
    }

    public ConnectionNode Node { get; }

    [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
    public string? Password { get; }

    public override string ToString() => $"QuickConnectResult {{ NodeId = {Node.Id}, Password = <redacted> }}";
}
