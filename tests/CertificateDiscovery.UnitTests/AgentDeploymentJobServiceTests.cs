using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class AgentDeploymentJobServiceTests
{
    [Fact]
    public async Task Agent_job_is_isolated_leased_encrypted_and_completes_deployment()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var rsa = RSA.Create(3072);
        var agentService = new DeploymentAgentService(fixture.Db);
        var registration = await agentService.CreateRegistrationTokenAsync(new("iis", 15), "admin", default);
        var identity = await agentService.RegisterAsync(new(
            registration.Token, "agent", "IIS-01", "1.0", "Windows", ["MicrosoftIis"],
            rsa.ExportSubjectPublicKeyInfoPem()), default);
        var (context, bundle) = fixture.SeedDeployment();
        var jobService = new AgentDeploymentJobService(
            fixture.Db, agentService, new DeploymentStateMachine(), new CertificateBundleConverter(),
            new FixedBundleSource(bundle));
        await fixture.Db.SaveChangesAsync();

        var jobId = await jobService.QueueAsync(context, identity.AgentId, default);
        var persisted = await fixture.Db.AgentDeploymentJobs.SingleAsync();
        Assert.Equal(jobId, persisted.Id);
        Assert.DoesNotContain(
            fixture.Db.Model.FindEntityType(typeof(AgentDeploymentJob))!.GetProperties(),
            property => property.Name.Contains("Bundle", StringComparison.OrdinalIgnoreCase));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            jobService.ClaimAsync(identity.AgentId, "wrong-agent-token", default));
        var claim = await jobService.ClaimAsync(identity.AgentId, identity.AgentToken, default);
        Assert.NotNull(claim);
        Assert.NotEqual(claim!.LeaseToken, persisted.LeaseTokenHash);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            jobService.GetBundleAsync(identity.AgentId, jobId, identity.AgentToken, "wrong-lease", default));

        var encrypted = await jobService.GetBundleAsync(identity.AgentId, jobId, identity.AgentToken, claim.LeaseToken, default);
        var clearBundle = Decrypt(encrypted.EncryptedBundleJson, rsa);
        Assert.Equal(bundle.Fingerprint, clearBundle.GetProperty("Fingerprint").GetString());
        Assert.NotEmpty(clearBundle.GetProperty("PfxBase64").GetString()!);

        await jobService.RecordStageAsync(identity.AgentId, jobId, identity.AgentToken,
            new(claim.LeaseToken, "BindingUpdated", "Binding updated."), default);
        await jobService.CompleteAsync(identity.AgentId, jobId, identity.AgentToken,
            new(claim.LeaseToken, true, false, bundle.Fingerprint, "OLD", null, null), default);

        var completed = await fixture.Db.AgentDeploymentJobs.SingleAsync();
        var deployment = await fixture.Db.CertificateDeployments.SingleAsync();
        Assert.Equal(AgentDeploymentJobStatus.Completed, completed.Status);
        Assert.Equal(CertificateDeploymentStatus.Succeeded, deployment.Status);
        Assert.Equal(bundle.Fingerprint, deployment.ObservedFingerprint);
        Assert.Contains(fixture.Db.DeploymentAuditEvents, x => x.EventType == "AgentDeploymentSucceeded");
    }

    private static JsonElement Decrypt(string envelopeJson, RSA rsa)
    {
        using var envelope = JsonDocument.Parse(envelopeJson);
        var root = envelope.RootElement;
        var key = rsa.Decrypt(Convert.FromBase64String(root.GetProperty("EncryptedKey").GetString()!), RSAEncryptionPadding.OaepSHA256);
        var nonce = Convert.FromBase64String(root.GetProperty("Nonce").GetString()!);
        var ciphertext = Convert.FromBase64String(root.GetProperty("Ciphertext").GetString()!);
        var tag = Convert.FromBase64String(root.GetProperty("Tag").GetString()!);
        var clear = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, tag.Length);
        aes.Decrypt(nonce, ciphertext, tag, clear);
        using var document = JsonDocument.Parse(clear);
        return document.RootElement.Clone();
    }

    private sealed class FixedBundleSource(IssuedCertificateBundle bundle) : IDeploymentCertificateBundleSource
    {
        public Task<IssuedCertificateBundle> LoadAsync(
            CertificateDeployment deployment,
            CancellationToken cancellationToken) => Task.FromResult(bundle);
    }

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

        public (DeploymentContext Context, IssuedCertificateBundle Bundle) SeedDeployment()
        {
            using var rsa = RSA.Create(2048);
            var certificateRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var x509 = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
            var fingerprint = Convert.ToHexString(SHA256.HashData(x509.RawData));
            var bundle = new IssuedCertificateBundle(
                x509.ExportCertificatePem(), rsa.ExportPkcs8PrivateKeyPem(), x509.ExportCertificatePem(), fingerprint);
            var provider = new AcmeProvider { Name = "acme", DirectoryUrl = new("https://acme.test"), AccountEmail = "a@test" };
            var vault = new VaultServer { Name = "vault", BaseUrl = new("https://vault.test") };
            var certificate = new Certificate
            {
                FingerprintSha256 = fingerprint, Subject = x509.Subject, Issuer = x509.Issuer,
                NotBeforeUtc = x509.NotBefore.ToUniversalTime(), NotAfterUtc = x509.NotAfter.ToUniversalTime()
            };
            var request = new AcmeCertificateRequest
            {
                Domain = "example.com", AcmeProvider = provider, VaultServer = vault,
                VaultSecretPath = "secret/example", Status = CertificateRequestStatus.StoredInVault,
                Certificate = certificate
            };
            var target = new DeploymentTarget { Name = "iis", TargetType = DeploymentTargetType.Iis };
            var policy = new DeploymentPolicy { Name = "policy" };
            var deployment = new CertificateDeployment
            {
                CertificateRequest = request, Certificate = certificate, DeploymentTarget = target,
                DeploymentPolicy = policy, ExpectedFingerprint = fingerprint,
                IdempotencyKey = Guid.NewGuid().ToString(), Status = CertificateDeploymentStatus.Deploying
            };
            Db.Add(deployment);
            return (new(deployment, target, policy), bundle);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
