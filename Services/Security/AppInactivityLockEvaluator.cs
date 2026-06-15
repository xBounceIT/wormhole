using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed class AppInactivityLockEvaluator
{
    private static readonly TimeSpan SuspendedTimerGap = TimeSpan.FromSeconds(45);

    private DateTimeOffset _lastUnlockUtc = DateTimeOffset.UtcNow;
    private DateTimeOffset? _lastSampleUtc;
    private TimeSpan _lastSystemIdle;
    private bool _hasIdleSample;

    public void MarkUnlocked(DateTimeOffset nowUtc)
    {
        _lastUnlockUtc = nowUtc;
        _lastSampleUtc = nowUtc;
        _lastSystemIdle = TimeSpan.Zero;
        _hasIdleSample = false;
    }

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
        var effectiveIdle = EstimateEffectiveIdle(systemIdle, nowUtc);
        _lastSampleUtc = nowUtc;
        _lastSystemIdle = systemIdle;
        _hasIdleSample = true;

        if (nowUtc - _lastUnlockUtc < timeout) return false;
        return effectiveIdle >= timeout;
    }

    private TimeSpan EstimateEffectiveIdle(TimeSpan systemIdle, DateTimeOffset nowUtc)
    {
        if (!_hasIdleSample) return systemIdle;
        if (_lastSampleUtc is not { } lastSampleUtc) return systemIdle;

        var sampleGap = nowUtc - lastSampleUtc;
        if (sampleGap < SuspendedTimerGap) return systemIdle;

        return TimeSpan.FromTicks(Math.Max(systemIdle.Ticks, (_lastSystemIdle + sampleGap).Ticks));
    }
}
