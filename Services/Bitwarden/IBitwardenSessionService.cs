namespace Wormhole.Services.Bitwarden;

public interface IBitwardenSessionService
{
    string? SessionKey { get; }
    bool HasSessionKey { get; }
    void SetSessionKey(string sessionKey);
    void ClearSessionKey();
}

public sealed class BitwardenSessionService : IBitwardenSessionService
{
    private readonly object _gate = new();
    private string? _sessionKey;

    public string? SessionKey
    {
        get
        {
            lock (_gate) return _sessionKey;
        }
    }

    public bool HasSessionKey => !string.IsNullOrWhiteSpace(SessionKey);

    public void SetSessionKey(string sessionKey)
    {
        if (string.IsNullOrWhiteSpace(sessionKey)) throw new ArgumentException("Session key is empty.", nameof(sessionKey));
        lock (_gate) _sessionKey = sessionKey;
    }

    public void ClearSessionKey()
    {
        lock (_gate) _sessionKey = null;
    }
}
