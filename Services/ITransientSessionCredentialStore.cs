using System.Collections.Concurrent;

namespace Wormhole.Services;

/// <summary>
/// Process-local secrets for ephemeral session profiles. Entries are never persisted and are
/// removed when their owning tab leaves the shell.
/// </summary>
public interface ITransientSessionCredentialStore
{
    void Store(Guid sessionId, string password);
    string? Read(Guid sessionId);
    void Remove(Guid sessionId);
    void Clear();
}

public sealed class TransientSessionCredentialStore : ITransientSessionCredentialStore
{
    private readonly ConcurrentDictionary<Guid, string> _passwords = new();

    public void Store(Guid sessionId, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        _passwords[sessionId] = password;
    }

    public string? Read(Guid sessionId) =>
        _passwords.TryGetValue(sessionId, out var password) ? password : null;

    public void Remove(Guid sessionId) => _passwords.TryRemove(sessionId, out _);

    public void Clear() => _passwords.Clear();
}
