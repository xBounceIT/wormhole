namespace Wormhole.Services.Security;

public interface IAppLockState
{
    bool IsLocked { get; }
    event EventHandler? LockStateChanged;
    void SetLocked(bool isLocked);
}
