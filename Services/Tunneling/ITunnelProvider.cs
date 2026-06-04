using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

public interface ITunnelProvider
{
    TunnelKind Kind { get; }

    /// <summary>
    /// Establishes the tunnel. <paramref name="progress"/> (optional) receives coarse
    /// <see cref="TunnelProgress"/> reports — authenticating, downloading config, starting the
    /// tunnel — that the connecting overlay surfaces as a live sub-status. Reports are best-effort;
    /// providers emit only the phases that apply to their flow.
    /// </summary>
    Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null);
}
