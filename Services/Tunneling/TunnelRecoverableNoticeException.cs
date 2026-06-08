using System;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Base for a benign, RECOVERABLE outcome of a tunnel establish: the provider did the right thing, but the
/// connection can't finish on this attempt and the user simply needs to reconnect — e.g. Stormshield spent
/// the one-time code downloading a fresh profile, or rejected a just-spent code that was re-entered before the
/// authenticator rolled. The session view-models and the tunnel-test dialog catch THIS type and render a
/// green success/info notice with a Reconnect affordance, NOT a red "connection failed" error.
///
/// <para>Providers raise a concrete subclass; the upper layers depend only on this tunneling-layer
/// abstraction, never on a provider-internal exception type — so a new recoverable outcome (any provider)
/// gets the notice treatment automatically by deriving from this. It still derives from
/// <see cref="InvalidOperationException"/> so it flows through generic catch/throw paths as an ordinary
/// operation failure wherever it isn't special-cased. <see cref="NoticeTitle"/> is the short, success-toned
/// heading for the notice chrome; <see cref="Exception.Message"/> is the body/guidance. Both are user-facing.</para>
/// </summary>
public abstract class TunnelRecoverableNoticeException : InvalidOperationException
{
    protected TunnelRecoverableNoticeException(string noticeTitle, string message) : base(message)
    {
        NoticeTitle = noticeTitle;
    }

    /// <summary>Short, success-toned heading shown above the notice message (e.g. "Profile downloaded").</summary>
    public string NoticeTitle { get; }
}
