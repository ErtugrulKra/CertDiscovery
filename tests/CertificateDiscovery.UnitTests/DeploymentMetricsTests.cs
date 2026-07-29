using CertificateDiscovery.Application.Options;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CertificateDiscovery.UnitTests;

public sealed class DeploymentMetricsTests
{
    [Fact]
    public async Task Exposes_deployment_retry_rollback_verification_and_duration_metrics_without_sensitive_labels()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new CertificateDiscoveryDbContext(
            new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var target = new DeploymentTarget
        {
            Name = "sensitive-target-name",
            TargetType = DeploymentTargetType.AzureKeyVault,
            ConfigurationJson = "{\"privateKey\":\"must-not-appear\"}"
        };
        var deployment = Deployment(target);
        db.Add(deployment);
        db.DeploymentVerificationRuns.Add(new()
        {
            CertificateDeployment = deployment,
            Attempt = 3,
            QuorumMode = VerificationQuorumMode.All,
            QuorumPercentage = 100,
            MinimumSuccessfulNodes = 1,
            TotalNodes = 2,
            SuccessfulNodes = 2,
            Outcome = DeploymentVerificationOutcome.Verified,
            Summary = "verification-secret-value"
        });
        db.DeploymentAuditEvents.AddRange(
            Event(deployment, "Deploying", DateTime.UtcNow.AddSeconds(-5)),
            Event(deployment, "Verifying", DateTime.UtcNow.AddSeconds(-2)),
            Event(deployment, "RolledBack", DateTime.UtcNow));
        await db.SaveChangesAsync();
        var settings = new ApplicationSettingsService(db, Options.Create(new CertificateDiscoveryOptions()));

        var output = await new PrometheusMetricsService(db, settings).RenderAsync(default);

        Assert.Contains("certificate_discovery_deployments_total{status=\"RolledBack\",target_type=\"AzureKeyVault\"} 1", output);
        Assert.Contains("certificate_discovery_deployment_retries_total{target_type=\"AzureKeyVault\"} 2", output);
        Assert.Contains("certificate_discovery_deployment_rollbacks_total{target_type=\"AzureKeyVault\",outcome=\"RolledBack\"} 1", output);
        Assert.Contains("certificate_discovery_deployment_verifications_total{target_type=\"AzureKeyVault\",outcome=\"Verified\"} 1", output);
        Assert.Contains("certificate_discovery_deployment_stage_duration_seconds_sum{stage=\"Deploying\",target_type=\"AzureKeyVault\"} 3", output);
        Assert.Contains("certificate_discovery_deployment_stage_duration_seconds_sum{stage=\"Verifying\",target_type=\"AzureKeyVault\"} 2", output);
        Assert.DoesNotContain("sensitive-target-name", output);
        Assert.DoesNotContain("verification-secret-value", output);
        Assert.DoesNotContain("must-not-appear", output);
    }

    private static CertificateDeployment Deployment(DeploymentTarget target)
    {
        var provider = new AcmeProvider { Name = "provider", DirectoryUrl = new("https://acme.example/directory"), AccountEmail = "a@example.com" };
        var vault = new VaultServer { Name = "vault", BaseUrl = new("https://vault.example") };
        var certificate = new Certificate
        {
            FingerprintSha256 = "ABC123", Subject = "CN=secret.example", CommonName = "secret.example",
            Issuer = "CN=CA", NotBeforeUtc = DateTime.UtcNow.AddDays(-1), NotAfterUtc = DateTime.UtcNow.AddDays(30)
        };
        var request = new AcmeCertificateRequest
        {
            Domain = "secret.example", AcmeProvider = provider, VaultServer = vault,
            VaultSecretPath = "secret/cert", Status = CertificateRequestStatus.StoredInVault, Certificate = certificate
        };
        return new()
        {
            CertificateRequest = request, Certificate = certificate, DeploymentTarget = target,
            DeploymentPolicy = new DeploymentPolicy { Name = "policy" },
            Status = CertificateDeploymentStatus.RolledBack, Attempt = 3, ExpectedFingerprint = "ABC123",
            IdempotencyKey = "metric-test", StartedAtUtc = DateTime.UtcNow.AddSeconds(-10), CompletedAtUtc = DateTime.UtcNow
        };
    }
    private static DeploymentAuditEvent Event(CertificateDeployment deployment, string type, DateTime at) =>
        new() { CertificateDeployment = deployment, EventType = type, Status = deployment.Status, CreatedAtUtc = at };
}
