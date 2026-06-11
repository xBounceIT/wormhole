using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// UI-thread-aware confirmation prompt surfaced mid-connect when a tunnel provider hits a TLS
/// server-certificate validation failure the user may legitimately want to override — appliance
/// captive portals routinely present factory/self-signed certificates that no public CA vouches
/// for. The provider runs on a background thread (TunnelManager.EstablishAsync); the
/// implementation is responsible for marshaling onto the UI dispatcher.
///
/// Returns true when the user explicitly chooses to trust the server and continue, false when
/// they decline/dismiss. Throws <see cref="System.OperationCanceledException"/> only when
/// <paramref name="cancellationToken"/> fires — a user-decline is not an exception, it returns
/// false.
/// </summary>
public interface ITlsTrustPromptService
{
    /// <summary>
    /// The accept-action label implementations must put on the confirm button. Providers reference
    /// it verbatim in prompt/error copy ("choose \"Trust and connect\"…"), so keeping it here is
    /// what stops the on-screen button and that copy from drifting apart.
    /// </summary>
    const string AcceptButtonLabel = "Trust and connect";

    /// <param name="title">Dialog title; should name the tunnel so concurrent connects are distinguishable.</param>
    /// <param name="message">Full explanation: what failed, what trusting means, and that the choice is persisted.</param>
    Task<bool> ConfirmTrustAsync(string title, string message, CancellationToken cancellationToken);
}
