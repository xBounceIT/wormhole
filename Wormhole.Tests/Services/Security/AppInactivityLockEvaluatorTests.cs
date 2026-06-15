using Wormhole.Models;
using Wormhole.Services.Security;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class AppInactivityLockEvaluatorTests
{
    [Fact]
    public void ShouldLock_DisabledAuth_ReturnsFalse()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.Disabled, AppAuthenticationIdleTimeoutMinutes = 1 };

        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ShouldLock_NoneTimeout_ReturnsFalse()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.Pin, AppAuthenticationIdleTimeoutMinutes = null };

        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromMinutes(10), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ShouldLock_WhenIdlePastTimeout_ReturnsTrue()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var now = DateTimeOffset.UtcNow;
        evaluator.MarkUnlocked(now - TimeSpan.FromMinutes(10));
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.Pin, AppAuthenticationIdleTimeoutMinutes = 5 };

        Assert.True(evaluator.ShouldLock(settings, false, TimeSpan.FromMinutes(6), now));
    }

    [Fact]
    public void ShouldLock_RecentUnlockPreventsImmediateRelock()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var now = DateTimeOffset.UtcNow;
        evaluator.MarkUnlocked(now);
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.WindowsHello, AppAuthenticationIdleTimeoutMinutes = 5 };

        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromHours(1), now + TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void ShouldLock_TimerGapPastTimeout_ReturnsTrueEvenWhenCurrentIdleReset()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var now = DateTimeOffset.UtcNow;
        var unlockedAt = now - TimeSpan.FromMinutes(10);
        evaluator.MarkUnlocked(unlockedAt);
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.Pin, AppAuthenticationIdleTimeoutMinutes = 5 };

        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromMinutes(1), unlockedAt + TimeSpan.FromMinutes(1)));
        Assert.True(evaluator.ShouldLock(settings, false, TimeSpan.FromSeconds(2), now));
    }

    [Fact]
    public void ShouldLock_TimerGapBelowTimeout_ReturnsFalseWhenCurrentIdleBelowTimeout()
    {
        var evaluator = new AppInactivityLockEvaluator();
        var now = DateTimeOffset.UtcNow;
        var unlockedAt = now - TimeSpan.FromMinutes(3);
        evaluator.MarkUnlocked(unlockedAt);
        var settings = new AppSettings { AppAuthenticationMode = AppAuthenticationMode.Pin, AppAuthenticationIdleTimeoutMinutes = 5 };

        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromMinutes(1), unlockedAt + TimeSpan.FromMinutes(1)));
        Assert.False(evaluator.ShouldLock(settings, false, TimeSpan.FromSeconds(2), now));
    }
}
