using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Services;

internal static class ContentDialogTracker
{
    private static readonly object Gate = new();
    private static readonly HashSet<ContentDialog> ActiveDialogs = [];
    private static TaskCompletionSource? UnlockSignal;
    private static bool IsLocked;

    public static bool IsLockDismissalInProgress { get; private set; }

    public static async Task<ContentDialogResult> ShowAsync(ContentDialog dialog, CancellationToken cancellationToken = default)
    {
        await WaitUntilUnlockedAsync(cancellationToken);

        using (Track(dialog))
        {
            return await dialog.ShowAsync();
        }
    }

    public static void LockAndHideAll()
    {
        ContentDialog[] dialogs;
        lock (Gate)
        {
            IsLocked = true;
            UnlockSignal ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
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

    public static void Unlock()
    {
        TaskCompletionSource? signal;
        lock (Gate)
        {
            IsLocked = false;
            signal = UnlockSignal;
            UnlockSignal = null;
        }

        signal?.TrySetResult();
    }

    private static async Task WaitUntilUnlockedAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            Task waitTask;
            lock (Gate)
            {
                if (!IsLocked) return;
                waitTask = (UnlockSignal ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
            }

            await waitTask.WaitAsync(cancellationToken);
        }
    }

    private static Scope Track(ContentDialog dialog)
    {
        lock (Gate)
        {
            ActiveDialogs.Add(dialog);
        }
        return new Scope(dialog);
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
