using System.Threading;

namespace Wormhole.Services;

/// <summary>
/// Shared gate for ContentDialog prompts (DialogService, file transfer, tunnel OTP,
/// WatchGuard SAML, TLS trust, and any future prompt a connect flow raises).
///
/// WinUI 3 permits ONE open ContentDialog per XamlRoot across ALL sources — a second ShowAsync
/// throws "Only a single ContentDialog can be open at a time". Tunnel establishes run in parallel
/// (two tabs connecting through different tunnels is routine), so per-service semaphores only
/// serialize a service against itself: an OTP dialog from tunnel A and a TLS-trust dialog from
/// tunnel B would each pass their own gate and crash. Every app-owned ContentDialog must therefore
/// queue on this one semaphore.
///
/// Never disposed — it lives for the process lifetime, which also means waiters are released only
/// via their own (linked) cancellation tokens, never via ObjectDisposedException.
/// </summary>
internal static class ContentDialogGate
{
    public static readonly SemaphoreSlim Shared = new(1, 1);
}
