using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class VaultDeploymentCertificateBundleSourceTests
{
    [Fact]
    public async Task Deployment_bundle_is_loaded_only_from_latest_vault_kv_version()
    {
        var certificate = CreateCertificate();
        var handler = new VaultReadHandler(certificate);
        var source = new VaultDeploymentCertificateBundleSource(new TestHttpClientFactory(handler));
        var deployment = Deployment(certificate.Fingerprint);

        var bundle = await source.LoadAsync(deployment, default);

        Assert.Equal(certificate.CertificatePem, bundle.CertificatePem);
        Assert.Equal(certificate.PrivateKeyPem, bundle.PrivateKeyPem);
        Assert.Equal(certificate.FullChainPem, bundle.FullChainPem);
        Assert.Equal(certificate.Fingerprint, bundle.Fingerprint);
        Assert.Equal(9, bundle.VaultVersion);
        Assert.Equal("/v1/secret/data/certificates/example.com", handler.Path);
        Assert.Equal("vault-token", handler.Token);
    }

    [Fact]
    public async Task Specific_vault_version_can_be_loaded_for_rollback_without_expected_fingerprint_match()
    {
        var certificate = CreateCertificate();
        var handler = new VaultReadHandler(certificate);
        var source = new VaultDeploymentCertificateBundleSource(new TestHttpClientFactory(handler));
        var deployment = Deployment(new string('F', 64));

        var bundle = await source.LoadVersionAsync(deployment, 8, default);

        Assert.Equal(certificate.Fingerprint, bundle.Fingerprint);
        Assert.Equal("?version=8", handler.Query);
    }

    [Fact]
    public async Task Deployment_stops_without_database_fallback_when_vault_is_unavailable()
    {
        var certificate = CreateCertificate();
        var source = new VaultDeploymentCertificateBundleSource(
            new TestHttpClientFactory(new VaultReadHandler(certificate, HttpStatusCode.NotFound)));
        var deployment = Deployment(certificate.Fingerprint);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => source.LoadAsync(deployment, default));

        Assert.Contains("not found in Vault", exception.Message);
    }

    [Fact]
    public async Task Latest_vault_version_must_match_deployment_fingerprint()
    {
        var certificate = CreateCertificate();
        var source = new VaultDeploymentCertificateBundleSource(
            new TestHttpClientFactory(new VaultReadHandler(certificate)));
        var deployment = Deployment(new string('F', 64));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => source.LoadAsync(deployment, default));

        Assert.Contains("does not match", exception.Message);
    }

    private static CertificateData CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem();
        return new(
            pem,
            rsa.ExportPkcs8PrivateKeyPem(),
            pem,
            Convert.ToHexString(SHA256.HashData(certificate.RawData)));
    }

    private static CertificateDeployment Deployment(string expectedFingerprint)
    {
        var vault = new VaultServer { Name = "vault", BaseUrl = new("https://vault.test"), Token = "vault-token" };
        var request = new AcmeCertificateRequest
        {
            Domain = "example.com",
            VaultServer = vault,
            VaultSecretPath = "secret/certificates/example.com"
        };
        return new CertificateDeployment
        {
            CertificateRequest = request,
            ExpectedFingerprint = expectedFingerprint
        };
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class VaultReadHandler(CertificateData certificate, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public string? Path { get; private set; }
        public string? Token { get; private set; }
        public string? Query { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri?.AbsolutePath;
            Query = request.RequestUri?.Query;
            Token = request.Headers.GetValues("X-Vault-Token").Single();
            var body = status == HttpStatusCode.OK
                ? JsonSerializer.Serialize(new
                {
                    data = new
                    {
                        data = new
                        {
                            certificate_pem = certificate.CertificatePem,
                            private_key_pem = certificate.PrivateKeyPem,
                            fullchain_pem = certificate.FullChainPem,
                            fingerprint_sha256 = certificate.Fingerprint
                        },
                        metadata = new { version = 9 }
                    }
                })
                : "{}";
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed record CertificateData(
        string CertificatePem,
        string PrivateKeyPem,
        string FullChainPem,
        string Fingerprint);
}
