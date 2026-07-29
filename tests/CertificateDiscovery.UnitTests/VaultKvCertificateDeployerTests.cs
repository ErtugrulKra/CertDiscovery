using System.Net;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class VaultKvCertificateDeployerTests
{
    [Fact]
    public async Task Vault_kv_deployer_preserves_version_verifies_write_and_restores_previous_data()
    {
        var handler = new VaultKvHandler(new Dictionary<string, object?>
        {
            ["certificate_pem"] = "old-certificate",
            ["private_key_pem"] = "old-private-key",
            ["fullchain_pem"] = "old-chain",
            ["fingerprint_sha256"] = "OLD"
        }, 3);
        var deployer = new VaultKvCertificateDeployer(new TestHttpClientFactory(handler));
        var target = Target();
        var context = Context(target, "vault-token");
        var bundle = new IssuedCertificateBundle("new-certificate", "new-private-key", "new-chain", "NEW");

        var validation = await deployer.ValidateTargetAsync(new(target, "vault-token"), default);
        var precheck = await deployer.PrecheckAsync(context, default);
        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, bundle, default);
        var verified = await deployer.VerifyAsync(context, bundle, default);
        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.True(validation.IsValid);
        Assert.True(precheck.IsReady);
        Assert.Equal("OLD", precheck.PreviousFingerprint);
        Assert.Equal("vault-kv:secret:certificates%2Fexample.com:3", backup.BackupReference);
        Assert.True(applied.Succeeded);
        Assert.True(verified.Succeeded);
        Assert.Equal("NEW", verified.ObservedFingerprint);
        Assert.True(rollback.Succeeded);
        Assert.Equal("OLD", rollback.ObservedFingerprint);
        Assert.Equal("OLD", handler.Current!["fingerprint_sha256"]?.ToString());
        Assert.All(handler.Tokens, token => Assert.Equal("vault-token", token));
        Assert.DoesNotContain("new-private-key", string.Join(" ", new[]
        {
            validation.Message, precheck.Message, backup.Message, applied.Message,
            verified.Message, rollback.Message
        }.Where(x => x is not null)));
    }

    [Fact]
    public async Task Vault_kv_deployer_deletes_new_secret_when_no_previous_version_exists()
    {
        var handler = new VaultKvHandler(null, 0);
        var deployer = new VaultKvCertificateDeployer(new TestHttpClientFactory(handler));
        var target = Target();
        var context = Context(target, "vault-token");
        var bundle = new IssuedCertificateBundle("certificate", "private-key", "chain", "NEW");

        var backup = await deployer.BackupAsync(context, default);
        Assert.Equal("vault-kv:secret:certificates%2Fexample.com:none", backup.BackupReference);
        Assert.True((await deployer.DeployAsync(context, bundle, default)).Succeeded);
        Assert.NotNull(handler.Current);

        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.True(rollback.Succeeded);
        Assert.Null(handler.Current);
    }

    [Fact]
    public async Task Vault_kv_target_requires_token_and_kv_v2_path()
    {
        var deployer = new VaultKvCertificateDeployer(new TestHttpClientFactory(new VaultKvHandler(null, 0)));
        var target = Target();
        var noToken = await deployer.ValidateTargetAsync(new(target, null), default);
        target.ConfigurationJson = """{"baseUrl":"https://vault.test","secretPath":"invalid"}""";
        var invalidPath = await deployer.ValidateTargetAsync(new(target, "token"), default);

        Assert.False(noToken.IsValid);
        Assert.Equal("Vault token is required.", noToken.Message);
        Assert.False(invalidPath.IsValid);
        Assert.Contains("<mount>/<path>", invalidPath.Message);
    }

    private static DeploymentTarget Target() => new()
    {
        Name = "vault",
        TargetType = DeploymentTargetType.VaultKv,
        ConfigurationJson = """
            {
              "baseUrl": "https://vault.test",
              "secretPath": "secret/certificates/example.com",
              "namespace": "tenant-a"
            }
            """
    };

    private static DeploymentContext Context(DeploymentTarget target, string secret)
    {
        var request = new AcmeCertificateRequest { Domain = "example.com" };
        var certificate = new Certificate
        {
            FingerprintSha256 = "NEW",
            Subject = "CN=example.com",
            Issuer = "CN=Test",
            NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
            NotAfterUtc = DateTime.UtcNow.AddDays(30)
        };
        var deployment = new CertificateDeployment
        {
            CertificateRequest = request,
            Certificate = certificate,
            DeploymentTarget = target,
            DeploymentPolicy = new() { Name = "test" },
            ExpectedFingerprint = "NEW"
        };
        return new(deployment, target, deployment.DeploymentPolicy, secret);
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class VaultKvHandler(Dictionary<string, object?>? initial, int initialVersion) : HttpMessageHandler
    {
        private readonly Dictionary<int, Dictionary<string, object?>> versions =
            initial is null ? [] : new() { [initialVersion] = new(initial) };
        private int version = initialVersion;

        public Dictionary<string, object?>? Current { get; private set; } =
            initial is null ? null : new(initial);
        public List<string?> Tokens { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Tokens.Add(request.Headers.TryGetValues("X-Vault-Token", out var values) ? values.Single() : null);
            Assert.Equal("tenant-a", request.Headers.GetValues("X-Vault-Namespace").Single());
            var path = request.RequestUri!.AbsolutePath;

            if (path.Contains("/metadata/", StringComparison.Ordinal))
                return Response(Current is null ? HttpStatusCode.NotFound : HttpStatusCode.OK, "{}");

            if (request.Method == HttpMethod.Get)
            {
                var requestedVersion = ReadVersion(request.RequestUri);
                var data = requestedVersion is null
                    ? Current
                    : versions.GetValueOrDefault(requestedVersion.Value);
                if (data is null) return Response(HttpStatusCode.NotFound, "{}");
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new
                {
                    data = new { data, metadata = new { version = requestedVersion ?? version } }
                }));
            }

            if (request.Method == HttpMethod.Post)
            {
                using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                Current = JsonSerializer.Deserialize<Dictionary<string, object?>>(
                    document.RootElement.GetProperty("data").GetRawText())!;
                version++;
                versions[version] = new(Current);
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { data = new { version } }));
            }

            if (request.Method == HttpMethod.Delete)
            {
                Current = null;
                return Response(HttpStatusCode.NoContent, string.Empty);
            }

            return Response(HttpStatusCode.MethodNotAllowed, "{}");
        }

        private static int? ReadVersion(Uri uri)
        {
            var query = uri.Query.TrimStart('?');
            return query.StartsWith("version=", StringComparison.Ordinal) &&
                   int.TryParse(query["version=".Length..], out var parsed)
                ? parsed
                : null;
        }

        private static HttpResponseMessage Response(HttpStatusCode status, string json) => new(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }
}
