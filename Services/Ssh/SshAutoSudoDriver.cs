using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Drives the per-connection "Auto sudo" sequence on a freshly connected SSH session: once the
/// shell produces its first output it sends <c>sudo su</c>, waits for the sudo password prompt,
/// and replies with the connection's saved password. If no prompt appears within
/// <see cref="PromptTimeout"/> (NOPASSWD, cached sudo timestamp, etc.) the password is NOT sent —
/// otherwise it would be typed into the root shell where it would be echoed and recorded.
///
/// The password is sent only at the sudo prompt, where the remote disables echo, so it never
/// appears in the terminal output or the session replay buffer. The password value is never logged.
/// </summary>
public sealed class SshAutoSudoDriver : IDisposable
{
    private static readonly TimeSpan PromptTimeout = TimeSpan.FromSeconds(10);

    // Matches the tail of the output ending in a password prompt, e.g. "[sudo] password for u: ".
    // Anchored at end-of-string and confined to the final line so a login banner that merely
    // mentions "password" earlier can't trip it. Scanning only begins after "sudo su" is sent.
    private static readonly Regex PasswordPrompt =
        new(@"[Pp]assword[^\r\n]*:\s*$", RegexOptions.Compiled);

    private const int TailCapacity = 512;

    private enum State { WaitingForShell, WaitingForPassword, Done }

    private readonly ISshSession _session;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private readonly List<byte> _tail = new(TailCapacity);

    private string? _password;
    private State _state = State.WaitingForShell;
    private Timer? _timeout;
    private bool _subscribed;

    public SshAutoSudoDriver(ISshSession session, string password, ILogger logger)
    {
        _session = session;
        _password = password;
        _logger = logger;
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_state != State.WaitingForShell || _subscribed) return;
            _session.DataReceived += OnDataReceived;
            _subscribed = true;
        }
    }

    private void OnDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0) return;

        bool sendSudo = false;
        string? password = null;
        lock (_gate)
        {
            switch (_state)
            {
                case State.WaitingForShell:
                    // The shell is echoing — issue the elevation command and start watching for
                    // the password prompt. The remote PTY buffers our input until the shell reads
                    // a line, so sending now (rather than guessing when the prompt is "done") is safe.
                    _state = State.WaitingForPassword;
                    sendSudo = true;
                    ArmTimeout();
                    break;

                case State.WaitingForPassword:
                    AppendTail(data.Span);
                    if (PasswordPrompt.IsMatch(Encoding.UTF8.GetString(_tail.ToArray())))
                    {
                        password = _password;
                        Finish();
                    }
                    break;

                case State.Done:
                    break;
            }
        }

        if (sendSudo)
        {
            _logger.LogDebug("Auto sudo: shell ready, sending elevation command.");
            SendLine("sudo su");
        }
        if (password is not null)
        {
            _logger.LogDebug("Auto sudo: sudo password prompt detected, sending saved password.");
            SendLine(password);
        }
    }

    private void OnTimeout(object? _)
    {
        lock (_gate)
        {
            if (_state != State.WaitingForPassword) return;
            Finish();
        }
        _logger.LogDebug("Auto sudo: no password prompt within {Timeout}s; password not sent.", PromptTimeout.TotalSeconds);
    }

    // Carriage return mirrors the byte xterm.js sends for the Enter key (the remote PTY's ICRNL
    // turns it into a newline) — sending it keeps Auto sudo indistinguishable from real typing.
    private void SendLine(string text)
    {
        var payload = Encoding.UTF8.GetBytes(text + "\r");
        _ = WriteAsync(payload);
    }

    private async Task WriteAsync(byte[] payload)
    {
        try
        {
            await _session.WriteAsync(payload).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Never include the payload (it may be the password) in the log.
            _logger.LogDebug(ex, "Auto sudo: write to shell failed.");
        }
    }

    private void AppendTail(ReadOnlySpan<byte> span)
    {
        foreach (var b in span) _tail.Add(b);
        if (_tail.Count > TailCapacity)
        {
            _tail.RemoveRange(0, _tail.Count - TailCapacity);
        }
    }

    private void ArmTimeout()
    {
        _timeout = new Timer(OnTimeout, null, PromptTimeout, Timeout.InfiniteTimeSpan);
    }

    // Caller must hold _gate. Idempotent terminal transition: stop listening and forget the secret.
    private void Finish()
    {
        _state = State.Done;
        if (_subscribed)
        {
            _session.DataReceived -= OnDataReceived;
            _subscribed = false;
        }
        _timeout?.Dispose();
        _timeout = null;
        _password = null;
        _tail.Clear();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            Finish();
        }
    }
}
