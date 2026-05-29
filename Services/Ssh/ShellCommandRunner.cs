using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Result of running a command against a live interactive shell. <see cref="Output"/> is the
/// best-effort plain text the command produced (ANSI stripped); <see cref="ExitCode"/> is the
/// remote <c>$?</c> when it could be captured. <see cref="TimedOut"/> means the end marker never
/// arrived in time; <see cref="Truncated"/> means output exceeded the capture cap.
/// </summary>
public sealed record ShellCommandResult(string Output, int? ExitCode, bool TimedOut, bool Truncated);

/// <summary>
/// "Option B": runs a command by driving an existing interactive <see cref="ISshSession"/> — the
/// same shell the user sees — rather than opening a separate exec channel. Models the pattern of
/// <see cref="SshAutoSudoDriver"/>: subscribe to <see cref="ISshSession.DataReceived"/>, write
/// through <see cref="ISshSession.WriteAsync"/> (which serializes against the user's keystrokes),
/// and watch the stream for sentinels.
///
/// <para>The command is wrapped between two <c>printf</c> sentinels whose assembled form is built
/// at runtime from a <c>%s</c>/<c>%d</c> format string, so the echoed input line (which shows the
/// literal <c>printf '@@WHS_%s@@\n' &lt;tok&gt;</c>) never contains the contiguous assembled
/// marker — only the shell's real execution does. That lets us reliably find where the command's
/// output begins and ends, and parse its exit code, without fragile prompt-regex detection.</para>
///
/// <para>Best-effort by nature: it assumes the foreground process is a POSIX shell at a prompt.
/// If the user has a pager / editor / REPL in the foreground, the wrapped command is just typed
/// into that program. Callers should fall back to raw send-text + read-terminal there.</para>
/// </summary>
internal sealed class ShellCommandRunner
{
    private const int TailWindow = 256;          // chars retained for end-marker detection past the cap
    private const int DefaultMaxCaptureChars = 1_000_000;

    private readonly ISshSession _session;
    private readonly ILogger _logger;

    private readonly object _gate = new();
    private readonly StringBuilder _all = new();        // captured stream, capped at _maxCapture
    private readonly StringBuilder _tail = new();       // rolling tail for marker detection past the cap
    private readonly Decoder _decoder = Encoding.UTF8.GetDecoder();

    private Regex _endRegex = null!;
    private TaskCompletionSource _completion = null!;
    private int _maxCapture;
    private int? _exitCode;
    private bool _truncated;
    private bool _completed;

    public ShellCommandRunner(ISshSession session, ILogger logger)
    {
        _session = session;
        _logger = logger;
    }

    public async Task<ShellCommandResult> RunAsync(
        string command,
        TimeSpan timeout,
        int maxCaptureChars,
        CancellationToken cancellationToken)
    {
        _maxCapture = maxCaptureChars > 0 ? maxCaptureChars : DefaultMaxCaptureChars;
        _completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var token = GenerateToken();
        var startMarker = $"@@WHS_{token}@@";
        _endRegex = new Regex($@"@@WHE_{token}_(\d+)@@", RegexOptions.Compiled);

        // %s/%d formatting means the echoed command line shows "@@WHS_%s@@" (with the format
        // specifier), never the assembled "@@WHS_<token>@@" — so our scan only matches the
        // shell's real output. \r mirrors the byte xterm.js sends for Enter.
        var payload =
            $"printf '@@WHS_%s@@\\n' {token}; {command}; __wh_rc=$?; printf '@@WHE_%s_%d@@\\n' {token} \"$__wh_rc\"\r";

        _session.DataReceived += OnDataReceived;
        try
        {
            await _session.WriteAsync(Encoding.UTF8.GetBytes(payload), cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout > TimeSpan.Zero) timeoutCts.CancelAfter(timeout);

            var timedOut = false;
            try
            {
                await _completion.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Caller cancellation propagates; a timeout (only timeoutCts fired) returns partial output.
                cancellationToken.ThrowIfCancellationRequested();
                timedOut = true;
            }

            return BuildResult(startMarker, token, timedOut);
        }
        finally
        {
            _session.DataReceived -= OnDataReceived;
        }
    }

    private void OnDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;

        var span = data.Span;
        var charCount = _decoder.GetCharCount(span, flush: false);
        if (charCount == 0) return;
        var chars = new char[charCount];
        _decoder.GetChars(span, chars, flush: false);
        var text = new string(chars);

        lock (_gate)
        {
            if (_completed) return;

            // Always feed the rolling tail so the end marker is detectable even after the
            // capture cap stops us appending to _all.
            _tail.Append(text);
            if (_tail.Length > TailWindow)
            {
                _tail.Remove(0, _tail.Length - TailWindow);
            }

            if (_all.Length < _maxCapture)
            {
                var room = _maxCapture - _all.Length;
                if (text.Length <= room)
                {
                    _all.Append(text);
                }
                else
                {
                    _all.Append(text, 0, room);
                    _truncated = true;
                }
            }
            else
            {
                _truncated = true;
            }

            var match = _endRegex.Match(_tail.ToString());
            if (match.Success)
            {
                _exitCode = int.TryParse(match.Groups[1].Value, out var rc) ? rc : null;
                _completed = true;
                _completion.TrySetResult();
            }
        }
    }

    private ShellCommandResult BuildResult(string startMarker, string token, bool timedOut)
    {
        string captured;
        int? exitCode;
        bool truncated;
        lock (_gate)
        {
            captured = _all.ToString();
            exitCode = _exitCode;
            truncated = _truncated;
        }

        // Drop everything up to and including the start marker — that strips the echoed input
        // line (and any prior prompt) so only the command's real output remains.
        var startIdx = captured.IndexOf(startMarker, StringComparison.Ordinal);
        var body = startIdx >= 0 ? captured[(startIdx + startMarker.Length)..] : captured;

        // Trim from the end marker onward. Match on the "@@WHE_<token>" prefix (not the full
        // "_<rc>@@" form) so a truncation cut that lands inside the marker still strips the
        // partial fragment. The token is unique, so this prefix never appears in real output.
        var endIdx = body.IndexOf($"@@WHE_{token}", StringComparison.Ordinal);
        if (endIdx >= 0) body = body[..endIdx];

        var output = TerminalText.StripAnsi(body).Trim('\n');
        return new ShellCommandResult(output, exitCode, timedOut, truncated);
    }

    private static string GenerateToken()
    {
        Span<byte> buf = stackalloc byte[8];
        RandomNumberGenerator.Fill(buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }
}
