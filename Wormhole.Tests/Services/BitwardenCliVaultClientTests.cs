using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenCliVaultClientTests
{
    [Fact]
    public async Task GetStatusAsync_ParsesLockedStatus()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(
            0,
            """{"status":"locked","userEmail":"alice@example.com","serverUrl":"https://vault.bitwarden.com"}""",
            string.Empty));
        var client = NewClient(runner);

        var status = await client.GetStatusAsync();

        Assert.Equal(BitwardenVaultStatus.Locked, status.Status);
        Assert.Equal("alice@example.com", status.UserEmail);
        Assert.Equal("https://vault.bitwarden.com", status.ServerUrl);
        var request = runner.Requests.Single();
        Assert.Collection(request.Arguments, arg => Assert.Equal("status", arg));
        Assert.True(request.Environment.ContainsKey("BW_SESSION"));
        Assert.Null(request.Environment["BW_SESSION"]);
    }

    [Fact]
    public async Task UnlockAsync_PassesMasterPasswordThroughEnvironmentOnly()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(0, "SESSION-KEY\n", string.Empty));
        var client = NewClient(runner);

        var session = await client.UnlockAsync("master-secret");

        Assert.Equal("SESSION-KEY", session);
        var request = runner.Requests.Single();
        Assert.Collection(
            request.Arguments,
            arg => Assert.Equal("unlock", arg),
            arg => Assert.Equal("--passwordenv", arg),
            arg => Assert.Equal("WORMHOLE_BW_PASSWORD", arg),
            arg => Assert.Equal("--raw", arg));
        Assert.DoesNotContain("master-secret", request.Arguments);
        Assert.Equal("master-secret", request.Environment["WORMHOLE_BW_PASSWORD"]);
    }

    [Fact]
    public async Task LoginAsync_PassesMasterPasswordThroughEnvironmentOnly()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(0, "SESSION-KEY\n", string.Empty));
        var client = NewClient(runner);

        var session = await client.LoginAsync(" alice@example.com ", "master-secret");

        Assert.Equal("SESSION-KEY", session);
        var request = runner.Requests.Single();
        Assert.Collection(
            request.Arguments,
            arg => Assert.Equal("login", arg),
            arg => Assert.Equal("alice@example.com", arg),
            arg => Assert.Equal("--passwordenv", arg),
            arg => Assert.Equal("WORMHOLE_BW_PASSWORD", arg),
            arg => Assert.Equal("--raw", arg),
            arg => Assert.Equal("--nointeraction", arg));
        Assert.DoesNotContain("master-secret", request.Arguments);
        Assert.Equal("master-secret", request.Environment["WORMHOLE_BW_PASSWORD"]);
    }

    [Fact]
    public async Task LoginAsync_WithAuthenticatorCode_PassesTotpMethodAndCode()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(0, "SESSION-KEY\n", string.Empty));
        var client = NewClient(runner);

        var session = await client.LoginAsync("alice@example.com", "master-secret", " 123 456 ");

        Assert.Equal("SESSION-KEY", session);
        Assert.Collection(
            runner.Requests.Single().Arguments,
            arg => Assert.Equal("login", arg),
            arg => Assert.Equal("alice@example.com", arg),
            arg => Assert.Equal("--passwordenv", arg),
            arg => Assert.Equal("WORMHOLE_BW_PASSWORD", arg),
            arg => Assert.Equal("--raw", arg),
            arg => Assert.Equal("--nointeraction", arg),
            arg => Assert.Equal("--method", arg),
            arg => Assert.Equal("0", arg),
            arg => Assert.Equal("--code", arg),
            arg => Assert.Equal("123456", arg));
    }

    [Fact]
    public async Task SearchLoginItemsAsync_SyncsThenParsesLoginItems()
    {
        var runner = new FakeRunner(
            new BitwardenProcessResult(0, string.Empty, string.Empty),
            new BitwardenProcessResult(0, """
            [
              {"id":"1","name":"Router","type":1,"login":{"username":"admin","password":"pw"}},
              {"id":"2","name":"Note","type":2},
              {"id":"3","name":"Server","login":{"username":"root","password":"secret"}}
            ]
            """, string.Empty));
        var client = NewClient(runner);

        var items = await client.SearchLoginItemsAsync("srv", "SESSION");

        Assert.Collection(runner.Requests[0].Arguments, arg => Assert.Equal("sync", arg));
        Assert.Equal("SESSION", runner.Requests[0].Environment["BW_SESSION"]);
        Assert.Collection(
            runner.Requests[1].Arguments,
            arg => Assert.Equal("list", arg),
            arg => Assert.Equal("items", arg),
            arg => Assert.Equal("--search", arg),
            arg => Assert.Equal("srv", arg));
        Assert.Equal("SESSION", runner.Requests[1].Environment["BW_SESSION"]);
        Assert.Collection(
            items,
            item =>
            {
                Assert.Equal("1", item.Id);
                Assert.Equal("Router", item.Name);
                Assert.Equal("admin", item.Username);
                Assert.Equal("pw", item.Password);
            },
            item =>
            {
                Assert.Equal("3", item.Id);
                Assert.Equal("Server", item.Name);
                Assert.Equal("root", item.Username);
                Assert.Equal("secret", item.Password);
            });
    }

    [Fact]
    public async Task GetLoginItemAsync_WithoutSession_RemovesInheritedSessionEnvironment()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(0, """
        {"id":"item-1","name":"Router","type":1,"login":{"username":"admin","password":"pw"}}
        """, string.Empty));
        var client = NewClient(runner);

        var item = await client.GetLoginItemAsync("item-1", sessionKey: null);

        Assert.NotNull(item);
        var request = runner.Requests.Single();
        Assert.Collection(
            request.Arguments,
            arg => Assert.Equal("get", arg),
            arg => Assert.Equal("item", arg),
            arg => Assert.Equal("item-1", arg));
        Assert.True(request.Environment.ContainsKey("BW_SESSION"));
        Assert.Null(request.Environment["BW_SESSION"]);
    }
    [Fact]
    public async Task Errors_RedactSessionAndPasswordEnvValues()
    {
        var runner = new FakeRunner(new BitwardenProcessResult(
            1,
            string.Empty,
            "failed command --session SESSION-SECRET --code 123456 BW_SESSION=SESSION-SECRET WORMHOLE_BW_PASSWORD=master-secret"));
        var client = NewClient(runner);

        var ex = await Assert.ThrowsAsync<BitwardenVaultException>(() =>
            client.GetLoginItemAsync("item-1", "SESSION-SECRET"));

        Assert.DoesNotContain("SESSION-SECRET", ex.Message);
        Assert.DoesNotContain("master-secret", ex.Message);
        Assert.DoesNotContain("123456", ex.Message);
        Assert.Contains("--session [redacted]", ex.Message);
        Assert.Contains("BW_SESSION=[redacted]", ex.Message);
        Assert.Contains("--code [redacted]", ex.Message);
        Assert.Contains("WORMHOLE_BW_PASSWORD=[redacted]", ex.Message);
    }

    private static BitwardenCliVaultClient NewClient(FakeRunner runner) =>
        new(runner, new FakeSettings(), NullLogger<BitwardenCliVaultClient>.Instance);

    private sealed class FakeSettings : IAppSettingsService
    {
        public AppSettings Current { get; } = new() { BitwardenCliPath = "bw-test" };
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class FakeRunner : IBitwardenProcessRunner
    {
        private readonly Queue<BitwardenProcessResult> _responses;

        public FakeRunner(params BitwardenProcessResult[] responses)
        {
            _responses = new Queue<BitwardenProcessResult>(responses);
        }

        public List<Request> Requests { get; } = new();

        public Task<BitwardenProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            IReadOnlyDictionary<string, string?>? environment = null,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(new Request(fileName, arguments.ToArray(), environment?.ToDictionary(kv => kv.Key, kv => kv.Value) ?? new()));
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private sealed record Request(string FileName, string[] Arguments, Dictionary<string, string?> Environment);
}
