using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services.Ssh;

public sealed class ShellCommandRunnerTests
{
    [Fact]
    public async Task RunAsync_CapturesOutputAndZeroExitCode()
    {
        var session = new ScriptedSshSession { Output = "hello\r\n", ExitCode = 0 };
        var runner = new ShellCommandRunner(session, NullLogger.Instance);

        var result = await runner.RunAsync("echo hello", TimeSpan.FromSeconds(5), 1_000_000, CancellationToken.None);

        Assert.Equal("hello", result.Output);
        Assert.Equal(0, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.False(result.Truncated);
    }

    [Fact]
    public async Task RunAsync_CapturesNonZeroExitCode()
    {
        var session = new ScriptedSshSession { Output = "nope\r\n", ExitCode = 3 };
        var runner = new ShellCommandRunner(session, NullLogger.Instance);

        var result = await runner.RunAsync("false", TimeSpan.FromSeconds(5), 1_000_000, CancellationToken.None);

        Assert.Equal(3, result.ExitCode);
        Assert.Equal("nope", result.Output);
    }

    [Fact]
    public async Task RunAsync_StripsAnsiAndDropsEchoedCommandLine()
    {
        // The echoed input line contains the literal "@@WHS_%s@@"/"@@WHE_%s_%d@@" format
        // strings — this asserts they are NOT mistaken for the assembled markers (so the
        // echoed command is dropped) and that ANSI color codes are stripped.
        var session = new ScriptedSshSession { Output = "\x1b[32mgreen\x1b[0m\r\n", ExitCode = 0 };
        var runner = new ShellCommandRunner(session, NullLogger.Instance);

        var result = await runner.RunAsync("ls --color", TimeSpan.FromSeconds(5), 1_000_000, CancellationToken.None);

        Assert.Equal("green", result.Output);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task RunAsync_TimesOut_WhenEndMarkerNeverArrives()
    {
        var session = new ScriptedSshSession { Output = "partial\r\n", EmitEnd = false };
        var runner = new ShellCommandRunner(session, NullLogger.Instance);

        var result = await runner.RunAsync("sleep 999", TimeSpan.FromMilliseconds(200), 1_000_000, CancellationToken.None);

        Assert.True(result.TimedOut);
        Assert.Null(result.ExitCode);
        Assert.Equal("partial", result.Output);
    }

    [Fact]
    public async Task RunAsync_MarksTruncated_WhenOutputExceedsCap()
    {
        var big = new string('x', 5000) + "\r\n";
        var session = new ScriptedSshSession { Output = big, ExitCode = 0 };
        var runner = new ShellCommandRunner(session, NullLogger.Instance);

        var result = await runner.RunAsync("yes", TimeSpan.FromSeconds(5), 100, CancellationToken.None);

        Assert.True(result.Truncated);
        // End marker is still detected via the rolling tail even past the cap.
        Assert.Equal(0, result.ExitCode);
    }

    /// <summary>
    /// Fake interactive shell: parses the runner's sentinel-wrapped payload, then replays a
    /// realistic terminal echo followed by the assembled start marker, the configured output,
    /// and (optionally) the assembled end marker with the exit code.
    /// </summary>
    private sealed class ScriptedSshSession : ISshSession
    {
        private static readonly Regex TokenRegex = new("[0-9a-f]{16}", RegexOptions.Compiled);

        public string Output { get; init; } = string.Empty;
        public int ExitCode { get; init; }
        public bool EmitEnd { get; init; } = true;

        public string? HostFingerprint => "SHA256:test";

        public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
#pragma warning disable CS0067 // Closed is required by ISshSession but unused by this fake.
        public event EventHandler? Closed;
#pragma warning restore CS0067

        public void Start() { }

        public Task ResizeAsync(uint columns, uint rows) => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            var payload = Encoding.UTF8.GetString(data.Span);
            var match = TokenRegex.Match(payload);
            if (!match.Success) return Task.CompletedTask;
            var token = match.Value;

            // Terminal echoes the typed line first (contains the %s/%d format strings, NOT the
            // assembled markers).
            Emit(payload.Replace("\r", string.Empty) + "\r\n");
            Emit($"@@WHS_{token}@@\r\n");
            if (Output.Length > 0) Emit(Output);
            if (EmitEnd) Emit($"@@WHE_{token}_{ExitCode}@@\r\n");
            return Task.CompletedTask;
        }

        private void Emit(string text) => DataReceived?.Invoke(this, Encoding.UTF8.GetBytes(text));
    }
}
