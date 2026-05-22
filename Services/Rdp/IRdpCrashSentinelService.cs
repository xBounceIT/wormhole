using Wormhole.Models;

namespace Wormhole.Services.Rdp;

/// <summary>
/// Persistent breadcrumb for "embedded RDP connect is in flight right now". The motivating
/// case is the AAD WAM delay-load crash (SEH 0xC06D007F): the OCX delay-loads broker DLLs
/// 2–4 seconds into the handshake and the process dies in native code below any managed
/// frame, so neither <c>Application.UnhandledException</c> nor <c>AppDomain.UnhandledException</c>
/// catches it. On the next launch we read the sentinel, conclude the previous run died
/// mid-handshake on that profile, and force <see cref="ConnectionNode.RdpUseExternalClient"/>
/// = true so the user doesn't crash again on retry.
///
/// The sentinel is also useful for non-AAD native crashes during RDP connect (e.g. a corrupt
/// mstscax build, an ActiveX P/Invoke that AVs) — the heuristic "you crashed during an RDP
/// connect, route through mstsc.exe" is the right safe-by-default response either way.
/// </summary>
public interface IRdpCrashSentinelService
{
    /// <summary>
    /// Atomically write a sentinel record naming this profile as the in-flight attempt.
    /// Overwrites any prior sentinel — the assumption is that the most recent embedded
    /// connect is the one whose status will determine the next clear/orphan outcome.
    /// </summary>
    Task MarkConnectInFlightAsync(Guid nodeId, string host, CancellationToken cancellationToken = default);

    /// <summary>
    /// Delete the sentinel if present. Idempotent — safe to call from terminal-status hooks
    /// that may fire repeatedly during teardown. Call when the embedded session reaches a
    /// known-stable state: Connected (handshake survived the WAM danger zone), Failed (managed
    /// failure surfaced cleanly), or Disconnected (orderly teardown).
    /// </summary>
    Task ClearAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Read-and-delete the sentinel at app startup. Returns null when no orphan is present
    /// (the previous run terminated cleanly) or when the file exists but is malformed
    /// (the latter is logged + deleted defensively). Use the returned record to auto-flag
    /// the offending profile so the user doesn't repeat the crash.
    /// </summary>
    Task<RdpCrashRecord?> TryClaimOrphanAsync(CancellationToken cancellationToken = default);
}

/// <summary>Sentinel payload. Keep this DTO compatible across versions — older payloads must
/// still deserialise on upgrade. New fields go at the end with defaults.</summary>
public sealed record RdpCrashRecord(Guid NodeId, string Host, DateTimeOffset StartedAtUtc);
