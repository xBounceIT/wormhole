using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// UI-thread-aware prompt for a one-time code, surfaced mid-connect when a tunnel provider
/// hits a 2FA challenge. The provider runs on a background thread; the impl is responsible
/// for marshaling onto the UI dispatcher.
///
/// Returns the trimmed OTP string on Submit, or null if the user cancelled. Throws
/// <see cref="System.OperationCanceledException"/> only when <paramref name="cancellationToken"/>
/// fires — a user-cancel is not an exception, it returns null.
/// </summary>
public interface IOtpPromptService
{
    Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken);
}
