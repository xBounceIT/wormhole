using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Resolves a <see cref="ConnectionProfile"/>'s tunnel config and dispatches to the matching
/// <see cref="ITunnelProvider"/>.
///
/// <para>Tunnels are shared per <see cref="TunnelConfig"/>: every <see cref="EstablishAsync"/> call
/// returns a lease over one ref-counted instance per config id, so multiple connections routed through
/// the same saved VPN reuse a single live tunnel (and a single OTP prompt — concurrent establishes for
/// the same config coalesce into one provider establishment). The caller disposes its lease when the
/// session ends, exactly as if it owned the tunnel; the real instance is torn down when the last lease
/// is released. A tunnel that reports <see cref="TunnelState.Failed"/>/<see cref="TunnelState.Closed"/>,
/// or whose config row was edited since it came up (<see cref="TunnelConfig.UpdatedAt"/>), is not handed
/// out again — the next connect establishes fresh while outstanding leases drain the old instance.</para>
/// </summary>
public sealed class TunnelManager
{
    private readonly Dictionary<TunnelKind, ITunnelProvider> _providers;
    private readonly ITunnelConfigRepository _configs;
    private readonly ICredentialService _credentials;
    private readonly ILogger<TunnelManager> _logger;

    // Shared-tunnel pool. Invariant (under _poolGate): every entry in _pool has RefCount >= 1 —
    // a release that hits zero evicts the entry in the same lock section, so joiners never see an
    // orphaned or abandoned entry.
    private readonly object _poolGate = new();
    private readonly Dictionary<Guid, SharedEntry> _pool = new();

    public TunnelManager(
        IEnumerable<ITunnelProvider> providers,
        ITunnelConfigRepository configs,
        ICredentialService credentials,
        ILogger<TunnelManager> logger)
    {
        // Group rather than ToDictionary so a duplicate registration (two providers claiming
        // the same TunnelKind) surfaces an actionable message instead of the raw
        // "An item with the same key has already been added." from ToDictionary.
        var byKind = new Dictionary<TunnelKind, ITunnelProvider>();
        foreach (var provider in providers)
        {
            if (byKind.TryGetValue(provider.Kind, out var existing))
            {
                throw new InvalidOperationException(
                    $"Multiple ITunnelProvider implementations registered for {provider.Kind}: " +
                    $"'{existing.GetType().FullName}' and '{provider.GetType().FullName}'. Register exactly one per kind.");
            }
            byKind[provider.Kind] = provider;
        }
        _providers = byKind;
        _configs = configs;
        _credentials = credentials;
        _logger = logger;
    }

    /// <summary>
    /// Returns a lease over the shared tunnel for the given profile's config — establishing it if no
    /// live one exists — or <c>null</c> when the profile is not configured to use a tunnel. The caller
    /// must dispose the returned lease when its session ends; the underlying tunnel is closed when the
    /// last lease over it is released. <paramref name="progress"/> (optional) receives the establishment
    /// phases so the connecting overlay can surface them (a caller joining an in-flight establishment
    /// gets the current phase replayed; a caller reusing an already-live tunnel gets a "reusing" report).
    /// <paramref name="cancellationToken"/> cancels only this caller's wait — a shared establishment is
    /// aborted only when every connection waiting on it has cancelled.
    /// </summary>
    public async Task<ITunnelInstance?> EstablishAsync(
        ConnectionProfile profile,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!profile.TunnelEnabled) return null;

        // The config read below is fast, but reporting Preparing up front gives the overlay an
        // immediate sub-status instead of an empty gap before the next report.
        progress?.Report(new TunnelProgress(TunnelPhase.Preparing));
        if (profile.TunnelConfigId is null)
        {
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has TunnelEnabled=true but no TunnelConfigId set on itself or any ancestor.");
        }

        var configId = profile.TunnelConfigId.Value;
        var config = await _configs.GetByIdAsync(configId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Tunnel config {configId} for connection '{profile.Name}' was not found.");

        return await LeaseSharedAsync(config, cancellationToken, progress).ConfigureAwait(false);
    }

    // === Shared pool ====================================================

    private sealed class SharedEntry : IDisposable
    {
        public SharedEntry(Guid configId, DateTime configUpdatedAt, ILogger<TunnelManager> logger)
        {
            ConfigId = configId;
            ConfigUpdatedAt = configUpdatedAt;
            Progress = new FanOutProgress(configId, logger);
        }

        public Guid ConfigId { get; }
        // Snapshot of the config row's UpdatedAt when this entry was created. Every save in the
        // tunnel editor bumps the row (even payload-only edits), so a mismatch on a later establish
        // means the user changed the config and the pooled tunnel no longer reflects it.
        public DateTime ConfigUpdatedAt { get; }
        // Cancels the provider establishment. Cancelled only when the last waiter gives up.
        // The token's wait handle can be materialized by provider/library code, so the source is
        // disposed after the provider returns. Cancel and Dispose are serialized here because
        // CancellationTokenSource.Dispose racing CancellationTokenSource.Cancel is not safe.
        private readonly object _establishCtsGate = new();
        private CancellationTokenSource? _establishCts = new();
        private int _activeEstablishCancels;
        private bool _disposeEstablishCtsRequested;
        public FanOutProgress Progress { get; }
        public Task<ITunnelInstance> EstablishTask { get; set; } = null!;
        // Leases handed out + callers still awaiting the establishment. Guarded by _poolGate.
        public int RefCount;
        // Set (under _poolGate) only after the provider establishment succeeded AND at least one
        // waiter is still around to own the result. Null while establishing or after failure.
        public ITunnelInstance? Instance;

        public CancellationToken EstablishToken
        {
            get
            {
                lock (_establishCtsGate)
                {
                    return (_establishCts ?? throw new ObjectDisposedException(nameof(SharedEntry))).Token;
                }
            }
        }

        public void CancelEstablishment()
        {
            CancellationTokenSource? source;
            lock (_establishCtsGate)
            {
                source = _establishCts;
                if (source is null) return;
                _activeEstablishCancels++;
            }

            try
            {
                source.Cancel();
            }
            finally
            {
                CancellationTokenSource? toDispose = null;
                lock (_establishCtsGate)
                {
                    _activeEstablishCancels--;
                    if (_activeEstablishCancels == 0 && _disposeEstablishCtsRequested)
                    {
                        toDispose = TakeEstablishCtsForDisposeLocked();
                    }
                }
                toDispose?.Dispose();
            }
        }

        public void DisposeEstablishmentCancellation()
        {
            CancellationTokenSource? toDispose = null;
            lock (_establishCtsGate)
            {
                _disposeEstablishCtsRequested = true;
                toDispose = TakeEstablishCtsForDisposeLocked();
            }
            toDispose?.Dispose();
        }

        public void Dispose() => DisposeEstablishmentCancellation();

        private CancellationTokenSource? TakeEstablishCtsForDisposeLocked()
        {
            if (_activeEstablishCancels != 0) return null;
            var source = _establishCts;
            _establishCts = null;
            return source;
        }
    }

    private async Task<ITunnelInstance> LeaseSharedAsync(
        TunnelConfig config,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress)
    {
        // Loop: a reused tunnel that fails the liveness probe below is evicted and the next
        // iteration establishes fresh. Terminates because a created entry always breaks out.
        while (true)
        {
            SharedEntry? entry = null;
            bool reusedLive = false;
            lock (_poolGate)
            {
                if (_pool.TryGetValue(config.Id, out var existing))
                {
                    // Stale: the config row was edited after this tunnel came up — hand out the edited
                    // settings to new connections. Dead: the tunnel reported Failed/Closed (sidecar
                    // died) but its owners haven't released it yet. Either way evict so a fresh entry
                    // is built below; outstanding leases keep draining the old instance and the last
                    // release still disposes it.
                    var stale = existing.ConfigUpdatedAt != config.UpdatedAt;
                    var dead = existing.Instance is { State: TunnelState.Failed or TunnelState.Closed };
                    if (stale || dead)
                    {
                        _pool.Remove(config.Id);
                    }
                    else
                    {
                        existing.RefCount++;
                        reusedLive = existing.Instance is not null;
                        entry = existing;
                    }
                }

                if (entry is null)
                {
                    entry = new SharedEntry(config.Id, config.UpdatedAt, _logger) { RefCount = 1 };
                    // Task.Run so no provider/secret work executes while holding the gate; assigned inside
                    // the lock so a concurrent joiner can never observe a null EstablishTask.
                    var newEntry = entry;
                    entry.EstablishTask = Task.Run(() => EstablishSharedCoreAsync(newEntry, config), CancellationToken.None);
                    _pool[config.Id] = entry;
                    // If every waiter cancels away, nobody is left to await the establishment — observe
                    // its outcome so an establish failure can't surface as an unobserved task exception.
                    // (Safe under the gate: awaiting the just-started task only registers a continuation.)
                    _ = ObserveSilentlyAsync(entry.EstablishTask);
                }
            }

            // From here on this caller holds a ref: every exit path must either return a lease that
            // carries the release, or go through ReleaseAsync. Progress callbacks run inside the try
            // for that reason — a throwing sink must not leak the ref (and they stay off _poolGate).
            var sinkAttached = false;
            try
            {
                if (reusedLive)
                {
                    // A dead sidecar process is not observable through State (nothing flips a live
                    // instance to Failed today) — probe the loopback SOCKS listener before handing
                    // the tunnel out. On failure: evict so new connects establish fresh, drop our
                    // ref, and retry; outstanding leases drain the dead instance as usual.
                    // Probing assumes every pooled instance exposes a loopback SOCKS endpoint —
                    // true for all current providers, which wrap a sidecar SOCKS listener. An
                    // instance with a null Socks5Endpoint is reused UNPROBED; if a non-SOCKS
                    // ITunnelInstance is ever added, promote this to an instance-level health check.
                    if (entry.Instance?.Socks5Endpoint is { } socks &&
                        !await IsLoopbackEndpointAliveAsync(socks, cancellationToken).ConfigureAwait(false))
                    {
                        _logger.LogWarning(
                            "Shared {Kind} tunnel '{Name}' failed its liveness probe; establishing a fresh tunnel.",
                            config.Kind, config.Name);
                        lock (_poolGate) EvictLocked(entry);
                        await ReleaseAsync(entry).ConfigureAwait(false);
                        continue;
                    }

                    _logger.LogInformation(
                        "Reusing established {Kind} tunnel '{Name}' for another connection.", config.Kind, config.Name);
                    progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel, "Reusing the active VPN tunnel…"));
                }
                else if (progress is not null)
                {
                    // Hook this caller's overlay into the shared establishment's progress stream
                    // (AddSink replays the latest phase, so a report raced before this line isn't lost).
                    entry.Progress.AddSink(progress);
                    sinkAttached = true;
                }

                var instance = await entry.EstablishTask.WaitAsync(cancellationToken).ConfigureAwait(false);
                // Providers only report during establishment — drop the sink so the pool entry
                // (alive as long as any lease is) doesn't pin this session's overlay/view-model.
                if (sinkAttached) entry.Progress.RemoveSink(progress!);
                return new BorrowedTunnelInstance(instance, onDispose: () => ReleaseAsync(entry));
            }
            catch
            {
                // This caller is out — cancelled its own wait, or the shared establishment failed.
                // Drop its ref; ReleaseAsync aborts the establishment if it was the last one waiting.
                if (sinkAttached) entry.Progress.RemoveSink(progress!);
                await ReleaseAsync(entry).ConfigureAwait(false);
                throw;
            }
        }
    }

    /// <summary>
    /// Cheap health check for a pooled tunnel: can we still open a TCP connection to its loopback
    /// SOCKS listener? A crashed sidecar tears the listener down with it, so connect-refused (or a
    /// hung accept — loopback accepts are otherwise instant) means the tunnel is gone even though
    /// nothing ever transitioned its State.
    /// </summary>
    private static async Task<bool> IsLoopbackEndpointAliveAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken)
                .AsTask().WaitAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async ValueTask ReleaseAsync(SharedEntry entry)
    {
        ITunnelInstance? toDispose = null;
        SharedEntry? toCancel = null;
        lock (_poolGate)
        {
            entry.RefCount--;
            if (entry.RefCount > 0) return;
            EvictLocked(entry);
            if (entry.Instance is not null)
            {
                toDispose = entry.Instance;
                entry.Instance = null;
            }
            else
            {
                // Still establishing (or already failed): abort the establishment. The establish
                // core disposes any instance it ends up producing once it sees RefCount == 0.
                toCancel = entry;
            }
        }

        toCancel?.CancelEstablishment();

        if (toDispose is not null)
        {
            _logger.LogInformation(
                "Closing shared tunnel for config {ConfigId} — last connection using it closed.", entry.ConfigId);
            await DisposeInstanceSilentlyAsync(toDispose, entry.ConfigId).ConfigureAwait(false);
        }
    }

    private async ValueTask DisposeInstanceSilentlyAsync(ITunnelInstance instance, Guid configId)
    {
        try { await instance.DisposeAsync().ConfigureAwait(false); }
        catch (Exception ex) { _logger.LogWarning(ex, "Tunnel dispose failed for config {ConfigId}.", configId); }
    }

    private void EvictLocked(SharedEntry entry)
    {
        if (_pool.TryGetValue(entry.ConfigId, out var current) && ReferenceEquals(current, entry))
        {
            _pool.Remove(entry.ConfigId);
        }
    }

    private async Task<ITunnelInstance> EstablishSharedCoreAsync(SharedEntry entry, TunnelConfig config)
    {
        try
        {
            var instance = await EstablishViaProviderAsync(config, entry.EstablishToken, entry.Progress)
                .ConfigureAwait(false);

            bool orphaned;
            lock (_poolGate)
            {
                orphaned = entry.RefCount == 0;
                // A dead-but-not-yet-released instance is filtered out at lease time (the pool-hit
                // State check + liveness probe in LeaseSharedAsync) — that is the only place the
                // pool is consulted, so no eager StateChanged-driven eviction is needed.
                if (!orphaned) entry.Instance = instance;
            }
            if (orphaned)
            {
                // Every waiter cancelled while the provider was establishing (the release that hit
                // zero already evicted the entry). Nobody owns the result — close it.
                await DisposeInstanceSilentlyAsync(instance, config.Id).ConfigureAwait(false);
                throw new OperationCanceledException(
                    "Tunnel establishment abandoned — every connection waiting on it cancelled.");
            }
            return instance;
        }
        catch
        {
            // Establishment failed (or was abandoned): make sure the next connect starts fresh.
            // A no-op when the zero-ref release already evicted the entry.
            lock (_poolGate) EvictLocked(entry);
            throw;
        }
        finally
        {
            entry.DisposeEstablishmentCancellation();
        }
    }

    /// <summary>
    /// Broadcasts provider progress reports to every connection waiting on the same shared
    /// establishment, replaying the latest report to late joiners so their overlay shows the
    /// current phase instead of a blank detail until the next one.
    /// </summary>
    private sealed class FanOutProgress : IProgress<TunnelProgress>
    {
        private readonly Guid _configId;
        private readonly object _gate = new();
        private readonly List<IProgress<TunnelProgress>> _sinks = new();
        private readonly ILogger<TunnelManager> _logger;
        private TunnelProgress? _last;

        public FanOutProgress(Guid configId, ILogger<TunnelManager> logger)
        {
            _configId = configId;
            _logger = logger;
        }

        public void AddSink(IProgress<TunnelProgress> sink)
        {
            TunnelProgress? replay;
            lock (_gate)
            {
                _sinks.Add(sink);
                replay = _last;
            }
            if (replay is not null) ReportToSink(sink, replay);
        }

        public void RemoveSink(IProgress<TunnelProgress> sink)
        {
            lock (_gate) _sinks.Remove(sink);
        }

        public void Report(TunnelProgress value)
        {
            IProgress<TunnelProgress>[] sinks;
            lock (_gate)
            {
                _last = value;
                sinks = _sinks.ToArray();
            }
            foreach (var sink in sinks) ReportToSink(sink, value);
        }

        private void ReportToSink(IProgress<TunnelProgress> sink, TunnelProgress value)
        {
            try
            {
                sink.Report(value);
            }
            catch (Exception ex)
            {
                RemoveSink(sink);
                _logger.LogWarning(
                    ex,
                    "Tunnel progress sink failed while reporting {Phase} for config {ConfigId}; removing it from fan-out.",
                    value.Phase,
                    _configId);
            }
        }
    }

    /// <summary>
    /// Establishes a specific saved tunnel config without requiring a connection profile. Used by
    /// settings-page diagnostics; the caller owns and must dispose the returned instance. This path
    /// deliberately bypasses the shared pool: a test must prove the tunnel can actually come up, so
    /// reusing (or registering with) a live shared instance would defeat its purpose.
    /// </summary>
    public async Task<ITunnelInstance> EstablishConfigAsync(
        TunnelConfig config,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(config);

        progress?.Report(new TunnelProgress(TunnelPhase.Preparing));
        return await EstablishViaProviderAsync(config, cancellationToken, progress).ConfigureAwait(false);
    }

    /// <summary>Single establish path shared by the pool and the diagnostics bypass: resolve the
    /// provider, read the DPAPI secret, dispatch.</summary>
    private async Task<ITunnelInstance> EstablishViaProviderAsync(
        TunnelConfig config,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress)
    {
        if (!_providers.TryGetValue(config.Kind, out var provider))
        {
            throw new InvalidOperationException(
                $"No tunnel provider is registered for kind '{config.Kind}'.");
        }

        var secret = await _credentials.ReadTunnelConfigAsync(config.Id).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Tunnel secret blob for config {config.Id} is missing on disk.");

        _logger.LogInformation("Establishing {Kind} tunnel '{Name}'.", config.Kind, config.Name);

        return await provider.EstablishAsync(config, secret, cancellationToken, progress).ConfigureAwait(false);
    }

    private static async Task ObserveSilentlyAsync(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch { /* outcome surfaces to waiters via EstablishTask; nothing else to do here */ }
    }
}
