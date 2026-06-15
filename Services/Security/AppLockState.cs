namespace Wormhole.Services.Security;

public sealed class AppLockState : IAppLockState
{
    private int _isLocked;

    public bool IsLocked => Volatile.Read(ref _isLocked) != 0;

    public event EventHandler? LockStateChanged;

    public void SetLocked(bool isLocked)
    {
        var value = isLocked ? 1 : 0;
        if (Interlocked.Exchange(ref _isLocked, value) == value) return;
        LockStateChanged?.Invoke(this, EventArgs.Empty);
    }
}
