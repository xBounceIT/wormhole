namespace Wormhole.Helpers;

/// <summary>
/// Coordinates hiding the owned RDP overlay window(s) while a modal WinUI
/// <c>ContentDialog</c> is shown over the tab. The RDP surface is a top-level window owned by
/// the main window and composited ABOVE the WinUI content, so a centered dialog would be
/// occluded by it. <see cref="Suppress"/> raises <see cref="SuppressChanged"/> with
/// <c>true</c> for the duration of the returned scope; live <c>RdpSurfaceHost</c> instances
/// subscribe and Hide/Show their native surface accordingly.
///
/// Ref-counted so overlapping/nested dialogs collapse to a single hide/show pair. All access
/// is expected on the UI thread (dialogs are shown there), so no locking beyond the interlocked
/// depth counter is needed.
/// </summary>
internal static class RdpOverlayCoordinator
{
    private static int _suppressDepth;

    /// <summary>Raised with <c>true</c> when the overlay should hide, <c>false</c> when it may
    /// show again. Fires only on the 0↔1 depth transitions.</summary>
    public static event Action<bool>? SuppressChanged;

    /// <summary>Whether the overlay is currently suppressed (a dialog is open). Lets a host that
    /// loads while a dialog is already up seed its initial state, since <see cref="SuppressChanged"/>
    /// only fires on the 0↔1 edge and a late subscriber would otherwise miss the active suppression.</summary>
    public static bool IsSuppressed => Volatile.Read(ref _suppressDepth) > 0;

    /// <summary>Begin suppressing the overlay; dispose the returned scope to end it.</summary>
    public static IDisposable Suppress()
    {
        // Build the scope BEFORE invoking subscribers so a throwing subscriber can't escape with
        // the count incremented but no disposable handed back (which would strand the depth >0 and
        // hide the overlay forever). The scope balances the count on dispose regardless.
        var scope = new Scope();
        if (Interlocked.Increment(ref _suppressDepth) == 1)
        {
            try { SuppressChanged?.Invoke(true); }
            catch { /* a subscriber threw; swallow so the count stays balanced via the scope */ }
        }
        return scope;
    }

    private static void Release()
    {
        if (Interlocked.Decrement(ref _suppressDepth) == 0)
        {
            SuppressChanged?.Invoke(false);
        }
    }

    private sealed class Scope : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Release();
        }
    }
}
