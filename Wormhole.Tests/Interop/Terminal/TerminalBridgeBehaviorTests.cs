using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Xunit;
using Xunit.Sdk;

namespace Wormhole.Tests.Interop.Terminal;

/// <summary>
/// Executes the shipped bridge.js inside a dependency-free Node VM with deterministic
/// WebView, DOM, timer, and xterm fakes.
/// </summary>
public sealed class TerminalBridgeBehaviorTests
{
    [Theory]
    [InlineData("fragmented-output")]
    [InlineData("alternate-screen-exit-ordering")]
    [InlineData("replay-side-effects")]
    [InlineData("async-parser-reply-stream-scope")]
    [InlineData("retirement-paste-gate")]
    [InlineData("retirement-resize-reattach")]
    [InlineData("stale-retirement-claimed-focus")]
    [InlineData("protocol-post-failures")]
    [InlineData("late-focus-after-retirement")]
    [InlineData("paste-gate-and-clear")]
    [InlineData("synchronized-output")]
    [InlineData("focus-after-fit")]
    [InlineData("neutral-parser-barrier")]
    [InlineData("focus-clear-rebind")]
    [InlineData("clear-input-gate")]
    [InlineData("ime-paste-ordering")]
    [InlineData("paste-cancellation-stress")]
    [InlineData("focus-cycle-paste-ordering")]
    public async Task Bridge_ExecutesCriticalTerminalProtocolScenario(string scenario)
    {
        var bridgePath = Path.Combine(AppContext.BaseDirectory, "Assets", "web", "bridge.js");
        Assert.True(File.Exists(bridgePath), $"The built terminal bridge was not found: {bridgePath}");

        var harnessPath = GetHarnessPath();
        Assert.True(File.Exists(harnessPath), $"The terminal bridge behavior harness was not found: {harnessPath}");

        var startInfo = new ProcessStartInfo
        {
            FileName = "node",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(harnessPath);
        startInfo.ArgumentList.Add(bridgePath);
        startInfo.ArgumentList.Add(scenario);

        Process process;
        try
        {
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Node.js returned no process handle.");
        }
        catch (Win32Exception)
        {
            throw SkipException.ForSkip(
                "Node.js is unavailable; skipping executable bridge.js behavior coverage.");
        }

        using (process)
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
        {
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); }
                catch { /* best effort after deterministic-test timeout */ }

                Assert.Fail($"Node bridge harness timed out for scenario '{scenario}'.");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            Assert.True(
                process.ExitCode == 0,
                $"Node bridge harness failed for scenario '{scenario}'.{Environment.NewLine}" +
                $"stdout:{Environment.NewLine}{stdout}{Environment.NewLine}" +
                $"stderr:{Environment.NewLine}{stderr}");
        }
    }

    private static string GetHarnessPath([CallerFilePath] string sourcePath = "") =>
        Path.Combine(
            Path.GetDirectoryName(sourcePath)
                ?? throw new InvalidOperationException("The test source directory is unavailable."),
            "terminal-bridge-harness.js");
}
