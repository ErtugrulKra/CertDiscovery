using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace CertificateDiscovery.UnitTests;

public sealed class DeploymentAgentServiceTests
{
    [Fact]
    public async Task Registration_token_is_single_use_and_only_hashes_are_persisted()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new DeploymentAgentService(fixture.Db);
        var bootstrap = await service.CreateRegistrationTokenAsync(
            new("iis-server registration", 15), "admin", default);
        var request = Registration(bootstrap.Token);

        var registered = await service.RegisterAsync(request, default);

        var tokenRecord = Assert.Single(fixture.Db.DeploymentAgentRegistrationTokens);
        var agent = Assert.Single(fixture.Db.DeploymentAgents);
        Assert.NotEqual(bootstrap.Token, tokenRecord.TokenHash);
        Assert.NotEqual(registered.AgentToken, agent.AuthenticationTokenHash);
        Assert.NotNull(tokenRecord.UsedAtUtc);
        Assert.Equal(agent.Id, tokenRecord.RegisteredAgentId);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.RegisterAsync(request, default));
    }

    [Fact]
    public async Task Heartbeat_authenticates_agent_updates_state_and_rejects_wrong_token()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new DeploymentAgentService(fixture.Db);
        var bootstrap = await service.CreateRegistrationTokenAsync(new("test", 15), "admin", default);
        var registered = await service.RegisterAsync(Registration(bootstrap.Token), default);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.HeartbeatAsync(registered.AgentId, "wrong-token", new("1.0.1", "Windows", ["MicrosoftIis"], false), default));

        await service.HeartbeatAsync(
            registered.AgentId,
            registered.AgentToken,
            new("1.0.1", "Windows Server 2025", ["MicrosoftIis", "Binding"], true),
            default);

        var agent = await fixture.Db.DeploymentAgents.SingleAsync();
        Assert.Equal(DeploymentAgentStatus.Busy, agent.Status);
        Assert.Equal("1.0.1", agent.Version);
        Assert.DoesNotContain(registered.AgentToken, agent.CapabilitiesJson);

        await service.RevokeAsync(agent.Id, default);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.HeartbeatAsync(agent.Id, registered.AgentToken, new("1.0.1", "Windows", [], false), default));
    }

    [Fact]
    public async Task Expired_registration_token_is_rejected()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new DeploymentAgentService(fixture.Db);
        var bootstrap = await service.CreateRegistrationTokenAsync(new("expired", 1), "admin", default);
        var record = await fixture.Db.DeploymentAgentRegistrationTokens.SingleAsync();
        record.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
        await fixture.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.RegisterAsync(Registration(bootstrap.Token), default));
    }

    [Fact]
    public async Task Approved_exchange_returns_agent_token_once_and_persists_only_hashes()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new DeploymentAgentService(fixture.Db);
        using var rsa = RSA.Create(2048);
        var started = await service.BeginExchangeAsync(
            new("IIS Agent", "IIS-SERVER-02", "1.0.0", "Windows Server",
                ["MicrosoftIis", "Binding"], rsa.ExportSubjectPublicKeyInfoPem()),
            "https://central.test/DeploymentAgents",
            default);

        var pending = await service.PollExchangeAsync(
            started.Response.ExchangeId, started.Response.ExchangeSecret, default);
        Assert.Equal("Pending", pending.Status);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.PollExchangeAsync(started.Response.ExchangeId, "wrong-secret", default));

        await service.ApproveExchangeAsync(started.Response.ExchangeId, "admin", default);
        var completed = await service.PollExchangeAsync(
            started.Response.ExchangeId, started.Response.ExchangeSecret, default);

        Assert.Equal("Completed", completed.Status);
        Assert.NotNull(completed.Registration);
        fixture.Db.ChangeTracker.Clear();
        var exchange = await fixture.Db.DeploymentAgentRegistrationExchanges.SingleAsync();
        var agent = await fixture.Db.DeploymentAgents.SingleAsync();
        Assert.NotEqual(started.Response.ExchangeSecret, exchange.ExchangeSecretHash);
        Assert.NotEqual(completed.Registration!.AgentToken, agent.AuthenticationTokenHash);
        Assert.Equal(agent.Id, exchange.RegisteredAgentId);
        Assert.Equal(DeploymentAgentExchangeStatus.Completed, exchange.Status);

        var consumed = await service.PollExchangeAsync(
            started.Response.ExchangeId, started.Response.ExchangeSecret, default);
        Assert.Equal("Completed", consumed.Status);
        Assert.Null(consumed.Registration);
    }

    [Fact]
    public async Task Rejected_exchange_never_creates_an_agent()
    {
        await using var fixture = await Fixture.CreateAsync();
        var service = new DeploymentAgentService(fixture.Db);
        using var rsa = RSA.Create(2048);
        var started = await service.BeginExchangeAsync(
            new("Rejected Agent", "IIS-SERVER-03", "1.0.0", "Windows Server",
                ["MicrosoftIis"], rsa.ExportSubjectPublicKeyInfoPem()),
            "https://central.test/DeploymentAgents",
            default);

        await service.RejectExchangeAsync(started.Response.ExchangeId, "admin", default);
        var result = await service.PollExchangeAsync(
            started.Response.ExchangeId, started.Response.ExchangeSecret, default);

        Assert.Equal("Rejected", result.Status);
        Assert.Empty(fixture.Db.DeploymentAgents);
    }

    private static DeploymentAgentRegisterRequest Registration(string token) => new(
        token,
        "IIS Agent",
        "IIS-SERVER-01",
        "1.0.0",
        "Windows Server",
        ["MicrosoftIis", "Binding", "MicrosoftIis"],
        "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----");

    private sealed class Fixture(SqliteConnection connection, CertificateDiscoveryDbContext db) : IAsyncDisposable
    {
        public CertificateDiscoveryDbContext Db { get; } = db;

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new CertificateDiscoveryDbContext(
                new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            return new(connection, db);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
