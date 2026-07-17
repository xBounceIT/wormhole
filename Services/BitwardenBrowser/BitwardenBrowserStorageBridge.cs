using System.Text.Json;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserStorageBridge
{
    internal const string Channel = "wormhole-bitwarden-storage-v1";

    public static string BuildCaptureScript(string nonce) => $$"""
        (() => {
          const nonce = {{JsonSerializer.Serialize(nonce)}};
          const send = (message) => chrome.webview.postMessage({
            channel: {{JsonSerializer.Serialize(Channel)}}, nonce, command: 'capture', ...message
          });
          try {
            chrome.storage.local.get(null, (local) => {
              if (chrome.runtime.lastError) { send({ ok: false, error: chrome.runtime.lastError.message }); return; }
              chrome.storage.session.get(null, (session) => {
                if (chrome.runtime.lastError) { send({ ok: false, error: chrome.runtime.lastError.message }); return; }
                send({ ok: true, local, session });
              });
            });
          } catch (error) { send({ ok: false, error: String(error) }); }
        })();
        """;

    public static string BuildRestoreScript(string nonce, BitwardenBrowserStorageRestore restore) => $$"""
        (() => {
          const nonce = {{JsonSerializer.Serialize(nonce)}};
          const local = {{restore.LocalJson}};
          const session = {{restore.SessionJson}};
          const send = (message) => chrome.webview.postMessage({
            channel: {{JsonSerializer.Serialize(Channel)}}, nonce, command: 'restore', ...message
          });
          const fail = () => send({ ok: false, error: chrome.runtime.lastError?.message || 'storage operation failed' });
          try {
            chrome.storage.local.clear(() => {
              if (chrome.runtime.lastError) { fail(); return; }
              chrome.storage.local.set(local, () => {
                if (chrome.runtime.lastError) { fail(); return; }
                chrome.storage.session.clear(() => {
                  if (chrome.runtime.lastError) { fail(); return; }
                  chrome.storage.session.set(session, () => chrome.runtime.lastError ? fail() : send({ ok: true }));
                });
              });
            });
          } catch (error) { send({ ok: false, error: String(error) }); }
        })();
        """;

    public static bool TryParseMessage(
        string json,
        string nonce,
        string command,
        out BitwardenBrowserStorageSnapshot? snapshot,
        out string? error)
    {
        snapshot = null;
        error = null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("channel", out var channel)
                || channel.ValueKind != JsonValueKind.String
                || channel.GetString() != Channel
                || !root.TryGetProperty("nonce", out var receivedNonce)
                || receivedNonce.ValueKind != JsonValueKind.String
                || receivedNonce.GetString() != nonce
                || !root.TryGetProperty("command", out var receivedCommand)
                || receivedCommand.ValueKind != JsonValueKind.String
                || receivedCommand.GetString() != command)
            {
                return false;
            }

            if (!root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            {
                error = root.TryGetProperty("error", out var failure)
                    && failure.ValueKind == JsonValueKind.String
                    ? failure.GetString()
                    : "Unknown storage bridge error.";
                error ??= "Unknown storage bridge error.";
                return true;
            }

            if (command == "capture")
            {
                if (!root.TryGetProperty("local", out var local) || local.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("session", out var session) || session.ValueKind != JsonValueKind.Object)
                {
                    error = "Bitwarden returned an invalid storage snapshot.";
                    return true;
                }

                snapshot = new BitwardenBrowserStorageSnapshot(
                    JsonSerializer.Serialize(local),
                    JsonSerializer.Serialize(session));
            }
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
