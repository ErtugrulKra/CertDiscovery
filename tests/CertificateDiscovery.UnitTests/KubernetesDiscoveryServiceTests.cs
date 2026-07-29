using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class KubernetesDiscoveryServiceTests
{
    [Fact]
    public async Task Discovers_tls_secrets_deduplicates_certificates_and_preserves_every_source()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new CertificateDiscoveryDbContext(
            new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var secrets = new MemorySecretProvider();
        var handler = new KubernetesHandler(CertificateChainPem());
        var service = new KubernetesDiscoveryService(db, new TestHttpClientFactory(handler), secrets);
        await service.CreateAsync(new KubernetesClusterUpsertRequest(
            "production", "https://cluster.test", null, "apps", "super-secret-token", true), default);
        var cluster = await db.KubernetesClusters.SingleAsync();

        var imported = await service.DiscoverAsync(cluster.Id, default);

        Assert.Equal(2, imported);
        var certificate = await db.Certificates.SingleAsync();
        Assert.Equal(CertificateSource.KubernetesSecret, certificate.Source);
        Assert.Equal("production", certificate.SourceName);
        Assert.Equal(2, await db.CertificateChainEntries.CountAsync());
        Assert.Contains(await db.CertificateSubjectAlternativeNames.Select(x => x.Name).ToListAsync(), x => x == "app.example.com");
        Assert.Equal(2, await db.KubernetesCertificateSources.CountAsync());
        Assert.All(await db.KubernetesCertificateSources.ToListAsync(), x => Assert.Equal("apps", x.Namespace));
        Assert.Equal("/api/v1/namespaces/apps/secrets", handler.RequestPath);
        Assert.Equal("super-secret-token", handler.Token);
    }

    [Fact]
    public async Task Cluster_configuration_protects_token_and_never_exposes_it_in_dto()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new CertificateDiscoveryDbContext(
            new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var secrets = new MemorySecretProvider();
        var service = new KubernetesDiscoveryService(
            db, new TestHttpClientFactory(new KubernetesHandler(CertificateChainPem())), secrets);

        await service.CreateAsync(new KubernetesClusterUpsertRequest(
            "cluster", "https://cluster.test", null, null, "private-token", true), default);
        var entity = await db.KubernetesClusters.SingleAsync();
        var dto = await service.GetAsync(entity.Id, default);

        Assert.NotEqual("private-token", entity.BearerTokenSecretReference);
        Assert.True(dto!.HasBearerToken);
        Assert.DoesNotContain("private-token", JsonSerializer.Serialize(dto));
    }

    private static string CertificateChainPem()
    {
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=app.example.com", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("app.example.com");
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var leaf = leafRequest.Create(
            ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(16));
        return leaf.ExportCertificatePem() + ca.ExportCertificatePem();
    }

    private sealed class KubernetesHandler(string certificatePem) : HttpMessageHandler
    {
        public string? RequestPath { get; private set; }
        public string? Token { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestPath = request.RequestUri!.AbsolutePath;
            Token = request.Headers.Authorization?.Parameter;
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(certificatePem));
            var payload = JsonSerializer.Serialize(new
            {
                items = new[]
                {
                    Secret("secret-a", encoded),
                    Secret("secret-b", encoded),
                    new
                    {
                        metadata = new { name = "opaque", @namespace = "apps" },
                        type = "Opaque",
                        data = new Dictionary<string, string> { ["tls.key"] = "must-not-be-read" }
                    }
                }
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            });
        }

        private static object Secret(string name, string certificate) => new
        {
            metadata = new { name, @namespace = "apps" },
            type = "kubernetes.io/tls",
            data = new Dictionary<string, string>
            {
                ["tls.crt"] = certificate,
                ["tls.key"] = "private-key-must-remain-opaque"
            }
        };
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class MemorySecretProvider : ISecretProvider
    {
        private readonly Dictionary<string, string> values = [];
        public Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken)
        {
            var reference = $"memory:{Guid.NewGuid():D}";
            values[reference] = value;
            return Task.FromResult(reference);
        }
        public Task<string> GetAsync(string secretReference, CancellationToken cancellationToken) =>
            Task.FromResult(values[secretReference]);
        public Task DeleteAsync(string secretReference, CancellationToken cancellationToken)
        {
            values.Remove(secretReference);
            return Task.CompletedTask;
        }
    }
}
