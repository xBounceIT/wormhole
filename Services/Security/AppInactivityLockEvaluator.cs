using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed class AppInactivityLockEvaluator
{
    private DateTimeOffset _lastUnlockUtc = DateTimeOffset.UtcNow;

    public void MarkUnlocked(DateTimeOffset nowUtc) => _lastUnlockUtc = nowUtc;

    public bool ShouldLock(
        AppSettings settings,
        bool isAlreadyLocked,
        TimeSpan systemIdle,
        DateTimeOffset nowUtc)
    {
        if (isAlreadyLocked) return false;
        if (settings.AppAuthenticationMode == AppAuthenticationMode.Disabled) return false;
        if (settings.AppAuthenticationIdleTimeoutMinutes is not { } minutes) return false;
        if (minutes <= 0) return false;

        var timeout = TimeSpan.FromMinutes(minutes);
        if (nowUtc - _lastUnlockUtc < timeout) return false;
        return systemIdle >= timeout;
    }
}
