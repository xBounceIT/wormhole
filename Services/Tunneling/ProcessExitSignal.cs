using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

internal sealed class ProcessExitSignal : IDisposable
{
    private readonly Process _process;
    private readonly TaskCompletionSource<int?> _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ProcessExitSignal(Process process)
    {
        _process = process ?? throw new ArgumentNullException(nameof(process));
        _process.Exited += OnExited;
        CompleteIfExited();
    }

    public Task<int?> Exited => _exited.Task;

    public void CompleteIfExited()
    {
        if (TryReadExitCode(out var exitCode))
        {
            _exited.TrySetResult(exitCode);
        }
    }

    public void Complete()
    {
        TryReadExitCode(out var exitCode);
        _exited.TrySetResult(exitCode);
    }

    public void Dispose()
    {
        try { _process.Exited -= OnExited; } catch { /* best effort */ }
    }

    private void OnExited(object? sender, EventArgs e) => CompleteIfExited();

    private bool TryReadExitCode(out int? exitCode)
    {
        exitCode = null;
        try
        {
            if (!_process.HasExited) return false;
            exitCode = _process.ExitCode;
            return true;
        }
        catch
        {
            // Best effort: the process object may already be torn down on the dispose path.
            return true;
        }
    }
}
