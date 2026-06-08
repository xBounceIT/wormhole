using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

/// <summary>
/// Unit tests for <see cref="StormshieldOtpReuseGuard"/>. The wrapped prompt only CHECKS; a code is blocked
/// only after it was explicitly Record()ed as spent, only within the reuse window, and only for the same
/// tunnel. A code that was merely prompted (never recorded — e.g. the download that would spend it failed) is
/// never blocked. Time is injected so the window logic is deterministic.
/// </summary>
public class StormshieldOtpReuseGuardTests
{
    // Returns the next queued code (or null = user dismiss) on each PromptAsync.
    private sealed class QueuedPrompt : IOtpPromptService
    {
        private readonly Queue<string?> _codes;
        public QueuedPrompt(params string?[] codes) => _codes = new Queue<string?>(codes);
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken)
            => Task.FromResult(_codes.Count > 0 ? _codes.Dequeue() : null);
    }

    private static StormshieldOtpReuseGuard NewGuard(Func<DateTimeOffset> clock, TimeSpan? window = null)
        => new(window ?? TimeSpan.FromSeconds(90), clock);

    private static Task<string?> Prompt(StormshieldOtpReuseGuard guard, Guid id, string? code)
        => guard.Wrap(new QueuedPrompt(code), id).PromptAsync("title", "subtitle", CancellationToken.None);

    [Fact]
    public async Task UnrecordedCode_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        Assert.Equal("123456", await Prompt(guard, Guid.NewGuid(), "123456"));
    }

    [Fact]
    public async Task PromptDoesNotRecord_SoSameCodeIsAcceptedAgain()
    {
        // The point of recording only on a confirmed spend: a code that was prompted but whose spend failed
        // (e.g. the config download errored before the firewall consumed it) must NOT block an immediate retry.
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        await Prompt(guard, id, "123456");   // prompted, but never Record()ed
        now += TimeSpan.FromSeconds(15);     // still inside the window
        Assert.Equal("123456", await Prompt(guard, id, "123456")); // accepted — it was never a spent code
    }

    [Fact]
    public async Task RecordedCode_WithinWindow_IsRejected()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        guard.Record(id, "123456");          // a successful download spent this code
        now += TimeSpan.FromSeconds(15);     // still inside the 90s window
        await Assert.ThrowsAsync<StormshieldOtpReusedException>(() => Prompt(guard, id, "123456"));
    }

    [Fact]
    public async Task RecordedCode_AfterWindow_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now, TimeSpan.FromSeconds(90));
        var id = Guid.NewGuid();

        guard.Record(id, "123456");
        now += TimeSpan.FromSeconds(120);    // window elapsed → a repeat is a legitimately new code now
        Assert.Equal("123456", await Prompt(guard, id, "123456"));
    }

    [Fact]
    public async Task RecordedCode_DifferentCode_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        guard.Record(id, "111111");
        Assert.Equal("222222", await Prompt(guard, id, "222222"));
    }

    [Fact]
    public async Task RecordedCode_ScopedPerTunnel()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var spent = Guid.NewGuid();
        var other = Guid.NewGuid();

        guard.Record(spent, "123456");
        // Blocked for the tunnel that spent it...
        await Assert.ThrowsAsync<StormshieldOtpReusedException>(() => Prompt(guard, spent, "123456"));
        // ...but accepted for a different tunnel.
        Assert.Equal("123456", await Prompt(guard, other, "123456"));
    }

    [Fact]
    public async Task RecordedReuse_IsDetected_IgnoringSurroundingWhitespace()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        guard.Record(id, "123456");
        // Re-entering the same code with stray whitespace is still the same spent code.
        await Assert.ThrowsAsync<StormshieldOtpReusedException>(() => Prompt(guard, id, "  123456 "));
    }

    [Fact]
    public async Task Dismiss_PassesThroughAsNull()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        Assert.Null(await Prompt(guard, Guid.NewGuid(), null));
    }

    [Fact]
    public async Task Record_WhitespaceCode_IsNoOp()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        guard.Record(id, "   ");  // nothing to remember
        Assert.Equal("123456", await Prompt(guard, id, "123456")); // not blocked
    }
}
