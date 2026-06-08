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
/// decorator throws <see cref="StormshieldOtpReusedException"/> when the user re-enters the remembered code
/// inside the window. A genuinely new code (the next TOTP window) is always accepted.</para>
/// </summary>
internal sealed class StormshieldOtpReuseGuard
{
    // > one 30s TOTP step plus the previous-window skew most servers tolerate, so an immediate retry that
    // reuses a code still "live" on the authenticator is caught; a fresh code a window later is never blocked.
    // The false-positive risk (a genuinely new code that happens to equal the last one) is ~1e-6 per pair.
    internal static readonly TimeSpan DefaultReuseWindow = TimeSpan.FromSeconds(90);

    private readonly TimeSpan _reuseWindow;
    private readonly Func<DateTimeOffset> _clock;
    // Guarded by _gate (not a ConcurrentDictionary): the reuse decision is a check-THEN-record that must be
    // atomic, which a lock-free dictionary can't give on its own.
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
    /// Returns an <see cref="IOtpPromptService"/> that delegates to <paramref name="inner"/> and then, for a
    /// non-empty code, records/checks it against this tunnel's most-recent code — throwing
    /// <see cref="StormshieldOtpReusedException"/> on a within-window reuse.
    /// </summary>
    public IOtpPromptService Wrap(IOtpPromptService inner, Guid tunnelId) => new GuardedPrompt(this, inner, tunnelId);

    /// <summary>
    /// Drop this tunnel's remembered code so the SAME code is accepted again. Call after a code reached the
    /// data plane but did NOT bring the tunnel up: it may never have been consumed by the firewall (a
    /// transport-only failure, or a stale-cached-profile rejection), so the firewall — not this local guard —
    /// should be the authority on whether it's still usable. The cache-miss DOWNLOAD path does not call this:
    /// a successful download definitively spends the code, so that record stands.
    /// </summary>
    public void Forget(Guid tunnelId)
    {
        lock (_gate) { _recent.Remove(tunnelId); }
    }

    // True (and records the code as the tunnel's latest) when the code is NOT a within-window reuse; false
    // when it matches the remembered code for this tunnel inside the reuse window. The check and the record
    // are one atomic step under _gate so two near-simultaneous prompts can't both slip through.
    private bool TryAccept(Guid tunnelId, string code)
    {
        var now = _clock();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(code));

        lock (_gate)
        {
            if (_recent.TryGetValue(tunnelId, out var prior)
                && now - prior.At < _reuseWindow
                && CryptographicOperations.FixedTimeEquals(prior.Hash, hash))
            {
                return false;
            }

            _recent[tunnelId] = (hash, now);
            return true;
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

            // Match the trimming the caller applies before use, and never record an empty code (the caller's
            // empty-code check handles that). Comparing trimmed values keeps "123456" and "123456 " in sync.
            var trimmed = code.Trim();
            if (trimmed.Length == 0)
                return code;

            if (!_guard.TryAccept(_tunnelId, trimmed))
            {
                throw new StormshieldOtpReusedException(
                    "That one-time code was just used. Wait until your authenticator shows a NEW code, then reconnect.");
            }

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
