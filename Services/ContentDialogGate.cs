using System.Threading;

namespace Wormhole.Services;

/// <summary>
/// Shared gate for background-initiated ContentDialog prompts (tunnel OTP, WatchGuard SAML,
/// TLS trust — and any future prompt a connect flow raises).
///
/// WinUI 3 permits ONE open ContentDialog per XamlRoot across ALL sources — a second ShowAsync
/// throws "Only a single ContentDialog can be open at a time". Tunnel establishes run in parallel
/// (two tabs connecting through different tunnels is routine), so per-service semaphores only
/// serialize a service against itself: an OTP dialog from tunnel A and a TLS-trust dialog from
/// tunnel B would each pass their own gate and crash. Every establish-time prompt service must
/// therefore queue on this one semaphore.
///
/// Scope note: user-initiated dialogs shown through <see cref="DialogService"/> (editors,
/// confirms) do NOT take this gate, so a background prompt can still collide with a dialog the
/// user opened themselves — a pre-existing, narrower exposure. Routing DialogService through the
/// gate would close it at the cost of queueing user actions behind background prompts.
///
/// Never disposed — it lives for the process lifetime, which also means waiters are released only
/// via their own (linked) cancellation tokens, never via ObjectDisposedException.
/// </summary>
internal static class ContentDialogGate
{
    public static readonly SemaphoreSlim Shared = new(1, 1);
}
