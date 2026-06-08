using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Catches a user re-submitting the SAME Stormshield one-time code before their authenticator's TOTP
/// window has rolled. This is the trap a cold-start cache-miss creates: the first connect spends the code on
/// the HTTPS profile download and aborts with "reconnect with a NEW code", but the authenticator is still
/// displaying the just-spent code for the rest of its ~30s window — so an immediate retry sends a code the
/// firewall already consumed and gets a flat <c>AUTH_FAILED</c> (and may trip a server-side lockout). The
/// guard rejects that identical re-entry locally, with guidance to wait for a fresh code, instead of burning
/// a firewall round-trip on a code that cannot succeed.
///
/// <para>State is in-memory only (the owning <see cref="StormshieldTunnelProvider"/> is a singleton), scoped
/// per tunnel, and short-lived: only the most-recently-accepted code is remembered, only its SHA-256 is kept
/// (never the code itself, never logged), and it is honoured only inside <see cref="DefaultReuseWindow"/>.</para>
///
/// <para>Wrap the real <see cref="IOtpPromptService"/> via <see cref="Wrap"/> for a given tunnel; the returned
/// decorator throws <see cref="StormshieldOtpReusedException"/> when the user re-enters a code that was recorded
/// as SPENT, inside the window. The guard records nothing on its own — the provider calls <see cref="Record"/>
/// only once a code is actually consumed (today: a successful config download), so a code that was prompted but
/// never spent (e.g. the download failed before the firewall saw it) never blocks a legitimate retry. A
/// genuinely new code (the next TOTP window) is always accepted.</para>
/// </summary>
internal sealed class StormshieldOtpReuseGuard
{
    // > one 30s TOTP step plus the previous-window skew most servers tolerate, so an immediate retry that
    // reuses a code still "live" on the authenticator is caught; a fresh code a window later is never blocked.
    // The false-positive risk (a genuinely new code that happens to equal the last one) is ~1e-6 per pair.
    internal static readonly TimeSpan DefaultReuseWindow = TimeSpan.FromSeconds(90);

    private readonly TimeSpan _reuseWindow;
    private readonly Func<DateTimeOffset> _clock;
    // Guarded by _gate: Record (write) and CheckReuse (read) must not race on the same key. Maps a tunnel to
    // the SHA-256 of its last definitively-spent code plus when it was spent.
    private readonly Dictionary<Guid, (byte[] Hash, DateTimeOffset At)> _recent = new();
    private readonly object _gate = new();

    public StormshieldOtpReuseGuard()
        : this(DefaultReuseWindow, static () => DateTimeOffset.UtcNow)
    {
    }

    // Test ctor: a controllable reuse window + clock so the window logic is unit-testable without real time.
    internal StormshieldOtpReuseGuard(TimeSpan reuseWindow, Func<DateTimeOffset> clock)
    {
        _reuseWindow = reuseWindow;
        _clock = clock;
    }

    /// <summary>
    /// Returns an <see cref="IOtpPromptService"/> that delegates to <paramref name="inner"/> and then CHECKS the
    /// entered code against this tunnel's last-spent code — throwing <see cref="StormshieldOtpReusedException"/>
    /// on a within-window reuse. It does NOT record; recording is the caller's explicit <see cref="Record"/> call
    /// once the code is actually spent.
    /// </summary>
    public IOtpPromptService Wrap(IOtpPromptService inner, Guid tunnelId) => new GuardedPrompt(this, inner, tunnelId);

    /// <summary>
    /// Remember a code that was DEFINITIVELY spent — the firewall consumed it (today: a successful Stormshield
    /// config download on a cache miss). A later within-window prompt of the same code for this tunnel is then
    /// rejected by the wrapped prompt. Recording only on a confirmed spend means a code that was prompted but
    /// never consumed (download error, transport failure, etc.) is never remembered, so it can't block a
    /// still-valid retry — the firewall stays the authority on those.
    /// </summary>
    public void Record(Guid tunnelId, string code)
    {
        var trimmed = code.Trim();
        if (trimmed.Length == 0)
            return;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(trimmed));
        lock (_gate) { _recent[tunnelId] = (hash, _clock()); }
    }

    // Throws StormshieldOtpReusedException when `code` matches this tunnel's last-spent code within the window.
    // The dictionary read is under _gate; the throw is constructed outside the lock.
    private void CheckReuse(Guid tunnelId, string code)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        bool reused;
        lock (_gate)
        {
            reused = _recent.TryGetValue(tunnelId, out var prior)
                && _clock() - prior.At < _reuseWindow
                && CryptographicOperations.FixedTimeEquals(prior.Hash, hash);
        }
        if (reused)
        {
            throw new StormshieldOtpReusedException(
                "That one-time code was just used. Wait until your authenticator shows a NEW code, then reconnect.");
        }
    }

    private sealed class GuardedPrompt : IOtpPromptService
    {
        private readonly StormshieldOtpReuseGuard _guard;
        private readonly IOtpPromptService _inner;
        private readonly Guid _tunnelId;

        public GuardedPrompt(StormshieldOtpReuseGuard guard, IOtpPromptService inner, Guid tunnelId)
        {
            _guard = guard;
            _inner = inner;
            _tunnelId = tunnelId;
        }

        public async Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken)
        {
            var code = await _inner.PromptAsync(title, subtitle, cancellationToken).ConfigureAwait(false);
            if (code is null)
                return null; // user dismissed — nothing to guard; upstream maps null to a deliberate cancel

            // Match the trimming the caller applies before use (and Record uses), so "123456" and "123456 "
            // compare equal; skip the check for an empty code (the caller's own empty-code check handles it).
            var trimmed = code.Trim();
            if (trimmed.Length == 0)
                return code;

            _guard.CheckReuse(_tunnelId, trimmed); // throws StormshieldOtpReusedException on a within-window reuse
            return code;
        }
    }
}

/// <summary>
/// Thrown when the user re-enters the one-time code that was just spent (on a profile download or a prior
/// data-plane attempt) before a new code is available — see <see cref="StormshieldOtpReuseGuard"/>. Its
/// <see cref="Exception.Message"/> is user-facing and carries the "wait for a new code" guidance. Derives from
/// <see cref="TunnelRecoverableNoticeException"/> so the session view-models and the tunnel-test dialog render
/// it as a green success/info notice (titled "One-time code already used") with a Reconnect affordance — the
/// same treatment as <see cref="StormshieldConfigRefreshedException"/>, not a red error.
/// </summary>
internal sealed class StormshieldOtpReusedException : TunnelRecoverableNoticeException
{
    public StormshieldOtpReusedException(string message) : base("One-time code already used", message) { }
}
