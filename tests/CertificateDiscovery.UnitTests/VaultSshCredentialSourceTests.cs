using System.Net;
using System.Text;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class VaultSshCredentialSourceTests
{
    [Fact]
    public async Task Reads_private_key_from_vault_kv_v2()
    {
        var handler = new Handler(request =>
        {
            Assert.Equal("/v1/secret/data/ssh/web01", request.RequestUri!.AbsolutePath);
            Assert.Equal("vault-token", request.Headers.GetValues("X-Vault-Token").Single());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"data":{"data":{"private_key_pem":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----","passphrase":"phrase"}}}""",
                    Encoding.UTF8,
                    "application/json")
            };
        });
        var source = new VaultSshCredentialSource(new TestHttpClientFactory(handler));
        var options = SshCertificateTargetOptions.Parse(SshTargetOptionsTests.Target(CertificateDiscovery.Domain.DeploymentTargetType.Nginx));

        var credential = await source.LoadAsync(options, "vault-token", default);

        Assert.Contains("BEGIN PRIVATE KEY", credential.PrivateKeyPem);
        Assert.Equal("phrase", credential.Passphrase);
    }

    [Fact]
    public async Task Does_not_include_vault_token_in_errors()
    {
        var source = new VaultSshCredentialSource(new TestHttpClientFactory(
            new Handler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden))));
        var options = SshCertificateTargetOptions.Parse(SshTargetOptionsTests.Target(CertificateDiscovery.Domain.DeploymentTargetType.Nginx));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => source.LoadAsync(options, "super-secret-token", default));

        Assert.DoesNotContain("super-secret-token", exception.Message);
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response(request));
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
