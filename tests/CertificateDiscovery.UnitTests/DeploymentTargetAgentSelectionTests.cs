using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class DeploymentTargetAgentSelectionTests
{
    [Fact]
    public async Task Microsoft_IIS_target_persists_selected_registered_agent_as_foreign_key()
    {
        await using var fixture = await Fixture.CreateAsync();
        var agent = fixture.AddAgent(DeploymentAgentStatus.Online);
        await fixture.Db.SaveChangesAsync();

        await fixture.Service.CreateTargetAsync(new(
            "Production IIS",
            DeploymentTargetType.Iis,
            null,
            """{"agentId":"00000000-0000-0000-0000-000000000000","siteName":"Default Web Site","bindingPort":443,"certificateStoreName":"My"}""",
            null,
            true,
            agent.Id), default);

        var target = await fixture.Db.DeploymentTargets.SingleAsync();
        Assert.Equal(agent.Id, target.DeploymentAgentId);
        Assert.DoesNotContain("agentId", target.ConfigurationJson, StringComparison.OrdinalIgnoreCase);
        var options = await fixture.Service.GetMicrosoftIisAgentOptionsAsync(agent.Id, default);
        Assert.Contains(options, x => x.Id == agent.Id && x.IsSelectable);
    }

    [Fact]
    public async Task Offline_agent_cannot_be_assigned_to_a_new_Microsoft_IIS_target()
    {
        await using var fixture = await Fixture.CreateAsync();
        var agent = fixture.AddAgent(DeploymentAgentStatus.Offline);
        await fixture.Db.SaveChangesAsync();

        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.Service.CreateTargetAsync(new(
                "Offline IIS",
                DeploymentTargetType.Iis,
                null,
                """{"siteName":"Default Web Site","bindingPort":443,"certificateStoreName":"My"}""",
                null,
                true,
                agent.Id), default));

        Assert.Contains("Offline", exception.Message);
        Assert.Empty(fixture.Db.DeploymentTargets);
    }

    [Fact]
    public async Task Deployment_create_options_only_list_Vault_stored_certificates_and_enabled_destinations()
    {
        await using var fixture = await Fixture.CreateAsync();
        var provider = new AcmeProvider
        {
            Name = "ACME", DirectoryUrl = new("https://acme.test"), AccountEmail = "admin@test"
        };
        var vault = new VaultServer { Name = "Vault", BaseUrl = new("https://vault.test") };
        var certificate = new Certificate
        {
            FingerprintSha256 = new string('A', 64),
            Subject = "CN=stored.example",
            Issuer = "CN=Test",
            NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
            NotAfterUtc = DateTime.UtcNow.AddDays(30)
        };
        fixture.Db.AddRange(
            new AcmeCertificateRequest
            {
                Domain = "stored.example", Status = CertificateRequestStatus.StoredInVault,
                VaultSecretPath = "secret/certificates/stored.example",
                AcmeProvider = provider, VaultServer = vault, Certificate = certificate,
                StoredAtUtc = DateTime.UtcNow
            },
            new AcmeCertificateRequest
            {
                Domain = "draft.example", Status = CertificateRequestStatus.Draft,
                VaultSecretPath = "secret/certificates/draft.example",
                AcmeProvider = provider, VaultServer = vault
            },
            new DeploymentTarget { Name = "Enabled target", IsEnabled = true },
            new DeploymentTarget { Name = "Disabled target", IsEnabled = false },
            new DeploymentPolicy { Name = "Enabled policy", IsEnabled = true },
            new DeploymentPolicy { Name = "Disabled policy", IsEnabled = false });
        await fixture.Db.SaveChangesAsync();

        var options = await fixture.Service.GetDeploymentCreateOptionsAsync(default);

        var stored = Assert.Single(options.Certificates);
        Assert.Equal("stored.example", stored.Domain);
        Assert.Equal("secret/certificates/stored.example", stored.VaultSecretPath);
        Assert.Equal("Enabled target", Assert.Single(options.Targets).Name);
        Assert.Equal("Enabled policy", Assert.Single(options.Policies).Name);
    }

    private sealed class Fixture(
        SqliteConnection connection,
        CertificateDiscoveryDbContext db,
        DeploymentService service) : IAsyncDisposable
    {
        public CertificateDiscoveryDbContext Db { get; } = db;
        public DeploymentService Service { get; } = service;

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new CertificateDiscoveryDbContext(
                new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var service = new DeploymentService(
                db, new NoopSecrets(), new NoopResolver(), new NoopOrchestrator(), new NoopQueue());
            return new(connection, db, service);
        }

        public DeploymentAgent AddAgent(DeploymentAgentStatus status)
        {
            var agent = new DeploymentAgent
            {
                Name = "IIS-PROD-01",
                MachineName = "WIN-WEB-01",
                AgentType = "MicrosoftIis",
                CapabilitiesJson = """["MicrosoftIis","CertificateStore","Binding"]""",
                Status = status,
                PublicKeyPem = "public-key"
            };
            Db.DeploymentAgents.Add(agent);
            return agent;
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class NoopSecrets : ISecretProvider
    {
        public Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken) => Task.FromResult("secret");
        public Task<string> GetAsync(string secretReference, CancellationToken cancellationToken) => Task.FromResult("secret");
        public Task DeleteAsync(string secretReference, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NoopResolver : ICertificateDeployerResolver
    {
        public ICertificateDeployer Resolve(DeploymentTargetType targetType) => throw new NotSupportedException();
    }

    private sealed class NoopOrchestrator : ICertificateDeploymentOrchestrator
    {
        public Task<Guid> CreateAsync(Guid requestId, Guid targetId, Guid policyId, string actor, DeploymentOrigin origin, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task ExecuteAsync(Guid deploymentId, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task ApproveAsync(Guid deploymentId, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RejectAsync(Guid deploymentId, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task CancelAsync(Guid deploymentId, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RollbackAsync(Guid deploymentId, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class NoopQueue : IDeploymentQueue
    {
        public Task EnqueueAsync(Guid deploymentId, string idempotencyKey, DateTime nextAttemptAtUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DeploymentJob?> ClaimAsync(string owner, TimeSpan lease, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task CompleteAsync(Guid jobId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task FailAsync(Guid jobId, string error, int maxAttempts, TimeSpan retryDelay, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
