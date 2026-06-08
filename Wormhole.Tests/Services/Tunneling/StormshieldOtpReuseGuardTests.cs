using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

/// <summary>
/// Unit tests for <see cref="StormshieldOtpReuseGuard"/>: a re-entered code is blocked only while the
/// remembered one is still inside the reuse window, scoped per tunnel, and a user dismiss is transparent.
/// Time is injected so the window logic is deterministic.
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
    public async Task FirstCode_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        Assert.Equal("123456", await Prompt(guard, Guid.NewGuid(), "123456"));
    }

    [Fact]
    public async Task SameCode_WithinWindow_IsRejected()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        await Prompt(guard, id, "123456");

        now += TimeSpan.FromSeconds(15); // still inside the 90s window
        await Assert.ThrowsAsync<StormshieldOtpReusedException>(() => Prompt(guard, id, "123456"));
    }

    [Fact]
    public async Task SameCode_AfterWindow_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now, TimeSpan.FromSeconds(90));
        var id = Guid.NewGuid();

        await Prompt(guard, id, "123456");

        now += TimeSpan.FromSeconds(120); // window elapsed → a repeat is a legitimately new code now
        Assert.Equal("123456", await Prompt(guard, id, "123456"));
    }

    [Fact]
    public async Task DifferentCode_WithinWindow_IsAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        await Prompt(guard, id, "111111");
        Assert.Equal("222222", await Prompt(guard, id, "222222"));
    }

    [Fact]
    public async Task SameCode_DifferentTunnels_BothAccepted()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);

        Assert.Equal("123456", await Prompt(guard, Guid.NewGuid(), "123456"));
        Assert.Equal("123456", await Prompt(guard, Guid.NewGuid(), "123456"));
    }

    [Fact]
    public async Task Dismiss_PassesThroughAsNull_AndRecordsNothing()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        Assert.Null(await Prompt(guard, id, null));
        // The dismiss recorded no code, so a subsequent real code is still accepted.
        Assert.Equal("123456", await Prompt(guard, id, "123456"));
    }

    [Fact]
    public async Task Reuse_IsDetected_IgnoringSurroundingWhitespace()
    {
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        await Prompt(guard, id, "123456");
        // Re-entering the same code with stray whitespace is still the same spent code.
        await Assert.ThrowsAsync<StormshieldOtpReusedException>(() => Prompt(guard, id, "  123456 "));
    }

    [Fact]
    public async Task Forget_AllowsTheSameCodeAgain_WithinWindow()
    {
        // Forget models "the code reached the data plane but didn't bring the tunnel up, so it may be
        // unspent" — a within-window retry of the same code must then be accepted, not blocked.
        var now = DateTimeOffset.UnixEpoch;
        var guard = NewGuard(() => now);
        var id = Guid.NewGuid();

        await Prompt(guard, id, "123456");
        guard.Forget(id);

        now += TimeSpan.FromSeconds(15); // still inside the reuse window
        Assert.Equal("123456", await Prompt(guard, id, "123456"));
    }

    [Fact]
    public void Forget_UnknownTunnel_IsNoOp()
    {
        var guard = NewGuard(() => DateTimeOffset.UnixEpoch);
        guard.Forget(Guid.NewGuid()); // must not throw
    }
}
