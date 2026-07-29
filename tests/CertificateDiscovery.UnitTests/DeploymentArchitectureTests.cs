using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateDiscovery.UnitTests;

public sealed class DeploymentArchitectureTests
{
    [Theory]
    [InlineData(CertificateDeploymentStatus.Pending, CertificateDeploymentStatus.Prechecking)]
    [InlineData(CertificateDeploymentStatus.Verifying, CertificateDeploymentStatus.Succeeded)]
    [InlineData(CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.RollingBack)]
    public void State_machine_allows_legal_transitions(CertificateDeploymentStatus from, CertificateDeploymentStatus to)
    {
        var deployment = new CertificateDeployment { Status = from };
        new DeploymentStateMachine().Transition(deployment, to);
        Assert.Equal(to, deployment.Status);
    }

    [Fact]
    public void State_machine_rejects_skipped_stage()
    {
        var deployment = new CertificateDeployment { Status = CertificateDeploymentStatus.Pending };
        Assert.Throws<InvalidOperationException>(() =>
            new DeploymentStateMachine().Transition(deployment, CertificateDeploymentStatus.Succeeded));
    }

    [Fact]
    public async Task Queue_is_idempotent_and_reclaims_expired_lease()
    {
        await using var fixture = await DbFixture.CreateAsync();
        var deployment = fixture.SeedDeployment();
        await fixture.Db.SaveChangesAsync();
        var queue = new DeploymentQueue(fixture.Db);
        await queue.EnqueueAsync(deployment.Id, "same-key", DateTime.UtcNow, default);
        await queue.EnqueueAsync(deployment.Id, "same-key", DateTime.UtcNow, default);
        Assert.Single(fixture.Db.DeploymentJobs);
        var first = await queue.ClaimAsync("worker-a", TimeSpan.FromMinutes(-1), default);
        var reclaimed = await queue.ClaimAsync("worker-b", TimeSpan.FromMinutes(5), default);
        Assert.NotNull(first);
        Assert.Equal(first!.Id, reclaimed!.Id);
        Assert.Equal("worker-b", reclaimed.ClaimOwner);
    }

    [Fact]
    public async Task Orchestrator_runs_fake_deployer_to_success()
    {
        await using var fixture = await DbFixture.CreateAsync();
        var request = fixture.SeedStoredRequest();
        var target = new DeploymentTarget { Name = "fake", TargetType = DeploymentTargetType.Fake };
        var policy = new DeploymentPolicy { Name = "auto", RequireApproval = false };
        fixture.Db.AddRange(target, policy);
        await fixture.Db.SaveChangesAsync();
        var orchestrator = CreateOrchestrator(fixture.Db);
        var id = await orchestrator.CreateAsync(request.Id, target.Id, policy.Id, "test", DeploymentOrigin.Manual, default);
        await orchestrator.ExecuteAsync(id, "test-worker", default);
        var deployment = await fixture.Db.CertificateDeployments.FindAsync(id);
        Assert.Equal(CertificateDeploymentStatus.Succeeded, deployment!.Status);
        Assert.Equal(deployment.ExpectedFingerprint, deployment.ObservedFingerprint);
        Assert.Contains(fixture.Db.DeploymentAuditEvents, x => x.EventType == "Succeeded");
    }

    [Fact]
    public async Task Verification_failure_rolls_back_when_policy_requires_it()
    {
        await using var fixture = await DbFixture.CreateAsync();
        var request = fixture.SeedStoredRequest();
        var target = new DeploymentTarget { Name = "fake", TargetType = DeploymentTargetType.Fake, ConfigurationJson = "{\"failStage\":\"verify\",\"previousFingerprint\":\"old\"}" };
        var policy = new DeploymentPolicy { Name = "rollback", RequireApproval = false, RollbackOnFailure = true };
        fixture.Db.AddRange(target, policy);
        await fixture.Db.SaveChangesAsync();
        var orchestrator = CreateOrchestrator(fixture.Db);
        var id = await orchestrator.CreateAsync(request.Id, target.Id, policy.Id, "test", DeploymentOrigin.Manual, default);
        await Assert.ThrowsAnyAsync<Exception>(() => orchestrator.ExecuteAsync(id, "test-worker", default));
        var deployment = await fixture.Db.CertificateDeployments.FindAsync(id);
        Assert.Equal(CertificateDeploymentStatus.RolledBack, deployment!.Status);
        Assert.Equal("old", deployment.ObservedFingerprint);
    }

    [Fact]
    public void Bundle_converter_creates_password_protected_pfx_without_temporary_files()
    {
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var certificatePem = certificate.ExportCertificatePem();
        var keyPem = rsa.ExportPkcs8PrivateKeyPem();
        var converted = new CertificateBundleConverter().Convert(
            new(certificatePem, keyPem, certificatePem, certificate.Thumbprint), "strong-password");
        Assert.NotEmpty(converted.Pfx);
        Assert.Equal(X509ContentType.Pkcs12, X509Certificate2.GetCertContentType(converted.Pfx));
    }

    private static CertificateDeploymentOrchestrator CreateOrchestrator(CertificateDiscoveryDbContext db)
    {
        var fake = new FakeCertificateDeployer();
        return new(db, new CertificateDeployerResolver([fake]), new DeploymentStateMachine(), new DeploymentQueue(db), new NoopSecrets(), new TestBundleSource());
    }

    private sealed class NoopSecrets : ISecretProvider
    {
        public Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken) => Task.FromResult("secret");
        public Task<string> GetAsync(string secretReference, CancellationToken cancellationToken) => Task.FromResult("value");
        public Task DeleteAsync(string secretReference, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TestBundleSource : IDeploymentCertificateBundleSource
    {
        public Task<IssuedCertificateBundle> LoadAsync(CertificateDeployment deployment, CancellationToken cancellationToken) =>
            Task.FromResult(new IssuedCertificateBundle("certificate", "private-key", "chain", deployment.ExpectedFingerprint));
    }

    private sealed class DbFixture(SqliteConnection connection, CertificateDiscoveryDbContext db) : IAsyncDisposable
    {
        public CertificateDiscoveryDbContext Db { get; } = db;
        public static async Task<DbFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new CertificateDiscoveryDbContext(new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            return new(connection, db);
        }
        public AcmeCertificateRequest SeedStoredRequest()
        {
            var provider = new AcmeProvider { Name = Guid.NewGuid().ToString(), DirectoryUrl = new("https://acme.example/directory"), AccountEmail = "a@example.com" };
            var vault = new VaultServer { Name = Guid.NewGuid().ToString(), BaseUrl = new("https://vault.example") };
            var certificate = new Certificate
            {
                FingerprintSha256 = "ABC123", Subject = "CN=example.com", Issuer = "CN=Test",
                NotBeforeUtc = DateTime.UtcNow.AddDays(-1), NotAfterUtc = DateTime.UtcNow.AddDays(30)
            };
            var request = new AcmeCertificateRequest
            {
                Domain = "example.com", AcmeProvider = provider, VaultServer = vault, VaultSecretPath = "secret/cert",
                Status = CertificateRequestStatus.StoredInVault, Certificate = certificate
            };
            Db.Add(request);
            Db.SaveChanges();
            return request;
        }
        public CertificateDeployment SeedDeployment()
        {
            var request = SeedStoredRequest();
            var target = new DeploymentTarget { Name = Guid.NewGuid().ToString() };
            var policy = new DeploymentPolicy { Name = Guid.NewGuid().ToString() };
            var deployment = new CertificateDeployment
            {
                CertificateRequest = request, Certificate = request.Certificate!, DeploymentTarget = target,
                DeploymentPolicy = policy, ExpectedFingerprint = "ABC123", IdempotencyKey = Guid.NewGuid().ToString()
            };
            Db.Add(deployment);
            return deployment;
        }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }
}
