using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Services;

internal static class ContentDialogTracker
{
    private static readonly object Gate = new();
    private static readonly HashSet<ContentDialog> ActiveDialogs = [];

    public static bool IsLockDismissalInProgress { get; private set; }

    public static IDisposable Track(ContentDialog dialog)
    {
        lock (Gate)
        {
            ActiveDialogs.Add(dialog);
        }
        return new Scope(dialog);
    }

    public static void HideAllForLock()
    {
        ContentDialog[] dialogs;
        lock (Gate)
        {
            dialogs = [.. ActiveDialogs];
        }

        IsLockDismissalInProgress = true;
        try
        {
            foreach (var dialog in dialogs)
            {
                try
                {
                    dialog.Hide();
                }
                catch
                {
                    // The dialog may have closed between snapshot and Hide().
                }
            }
        }
        finally
        {
            IsLockDismissalInProgress = false;
        }
    }

    private sealed class Scope : IDisposable
    {
        private readonly ContentDialog _dialog;
        private bool _disposed;

        public Scope(ContentDialog dialog) => _dialog = dialog;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            lock (Gate)
            {
                ActiveDialogs.Remove(_dialog);
            }
        }
    }
}
