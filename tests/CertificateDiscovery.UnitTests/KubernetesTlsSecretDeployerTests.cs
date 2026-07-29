using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class KubernetesTlsSecretDeployerTests
{
    [Fact]
    public async Task Kubernetes_deployer_retries_conflict_preserves_metadata_verifies_and_rolls_back()
    {
        var oldBundle = CertificateBundle("old.example.com");
        var newBundle = CertificateBundle("new.example.com");
        var handler = new KubernetesHandler(Secret(oldBundle, "7"), conflictOnce: true);
        var secrets = new MemorySecretProvider();
        var deployer = new KubernetesTlsSecretDeployer(new TestHttpClientFactory(handler), secrets);
        var target = Target(restart: true);
        var context = Context(target, newBundle.Fingerprint);

        Assert.True((await deployer.ValidateTargetAsync(new(target, "service-account-token"), default)).IsValid);
        var precheck = await deployer.PrecheckAsync(context, default);
        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, newBundle, default);
        var verification = await deployer.VerifyAsync(context, newBundle, default);

        Assert.Equal(oldBundle.Fingerprint, precheck.PreviousFingerprint);
        Assert.True(backup.Succeeded);
        Assert.StartsWith("memory:", backup.BackupReference);
        Assert.DoesNotContain("old-private-key", backup.BackupReference);
        Assert.True(applied.Succeeded);
        Assert.Equal(2, handler.PutAttempts);
        Assert.Equal(1, handler.RestartPatches);
        Assert.True(verification.Succeeded);
        Assert.Equal(newBundle.Fingerprint, verification.ObservedFingerprint);
        Assert.Equal("keep-me", handler.Current!["metadata"]!["labels"]!["existing"]!.GetValue<string>());
        Assert.Equal("unrelated-value", Decode(handler.Current!["data"]!["unrelated"]!.GetValue<string>()));
        Assert.Equal("certdiscovery", handler.Current!["metadata"]!["annotations"]!["managed-by"]!.GetValue<string>());

        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.True(rollback.Succeeded);
        Assert.Equal(oldBundle.Fingerprint, rollback.ObservedFingerprint);
        Assert.Equal(oldBundle.Fingerprint, Fingerprint(handler.Current!));
        Assert.All(handler.Tokens, token => Assert.Equal("service-account-token", token));
    }

    [Fact]
    public async Task Kubernetes_deployer_creates_missing_secret_and_deletes_it_on_rollback()
    {
        var bundle = CertificateBundle("new.example.com");
        var handler = new KubernetesHandler(null);
        var secrets = new MemorySecretProvider();
        var deployer = new KubernetesTlsSecretDeployer(new TestHttpClientFactory(handler), secrets);
        var target = Target();
        var context = Context(target, bundle.Fingerprint);

        var precheck = await deployer.PrecheckAsync(context, default);
        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, bundle, default);
        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.True(precheck.IsReady);
        Assert.True(applied.Succeeded);
        Assert.True(handler.Created);
        Assert.True(rollback.Succeeded);
        Assert.Null(handler.Current);
    }

    [Fact]
    public async Task Kubernetes_target_requires_https_token_and_valid_dns_names()
    {
        var deployer = new KubernetesTlsSecretDeployer(
            new TestHttpClientFactory(new KubernetesHandler(null)),
            new MemorySecretProvider());
        var target = Target();
        var noToken = await deployer.ValidateTargetAsync(new(target, null), default);
        target.ConfigurationJson = """
            {"apiServer":"http://cluster.test","namespace":"Invalid_Name","secretName":"tls"}
            """;
        var invalid = await deployer.ValidateTargetAsync(new(target, "token"), default);

        Assert.False(noToken.IsValid);
        Assert.Contains("bearer token", noToken.Message);
        Assert.False(invalid.IsValid);
        Assert.Contains("HTTPS", invalid.Message);
    }

    private static DeploymentTarget Target(bool restart = false) => new()
    {
        Name = "kubernetes",
        TargetType = DeploymentTargetType.Kubernetes,
        ConfigurationJson = $$"""
            {
              "apiServer": "https://cluster.test",
              "namespace": "production",
              "secretName": "example-tls",
              "createIfMissing": true,
              "caBundleField": "ca.crt",
              "annotations": { "managed-by": "certdiscovery" },
              "restartWorkloads": {{(restart ? """[{"kind":"Deployment","name":"web"}]""" : "[]")}}
            }
            """
    };

    private static DeploymentContext Context(DeploymentTarget target, string fingerprint)
    {
        var deployment = new CertificateDeployment
        {
            CertificateRequest = new() { Domain = "example.com" },
            Certificate = new()
            {
                FingerprintSha256 = fingerprint,
                Subject = "CN=example.com",
                Issuer = "CN=Test",
                NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
                NotAfterUtc = DateTime.UtcNow.AddDays(30)
            },
            DeploymentTarget = target,
            DeploymentPolicy = new() { Name = "test" },
            ExpectedFingerprint = fingerprint
        };
        return new(deployment, target, deployment.DeploymentPolicy, "service-account-token");
    }

    private static IssuedCertificateBundle CertificateBundle(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem();
        return new(
            pem,
            rsa.ExportPkcs8PrivateKeyPem(),
            pem,
            Convert.ToHexString(SHA256.HashData(certificate.RawData)));
    }

    private static JsonObject Secret(IssuedCertificateBundle bundle, string resourceVersion) =>
        JsonNode.Parse(JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new
            {
                name = "example-tls",
                @namespace = "production",
                resourceVersion,
                uid = "server-managed",
                labels = new Dictionary<string, string> { ["existing"] = "keep-me" },
                annotations = new Dictionary<string, string> { ["existing"] = "keep-me" }
            },
            type = "kubernetes.io/tls",
            data = new Dictionary<string, string>
            {
                ["tls.crt"] = Encode(bundle.FullChainPem),
                ["tls.key"] = Encode(bundle.PrivateKeyPem),
                ["unrelated"] = Encode("unrelated-value")
            }
        }))!.AsObject();

    private static string Fingerprint(JsonObject secret)
    {
        var pem = Decode(secret["data"]!["tls.crt"]!.GetValue<string>());
        using var certificate = X509Certificate2.CreateFromPem(pem);
        return Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }

    private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    private static string Decode(string value) => Encoding.UTF8.GetString(Convert.FromBase64String(value));

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

    private sealed class KubernetesHandler(JsonObject? initial, bool conflictOnce = false) : HttpMessageHandler
    {
        private int version = int.TryParse(
            initial?["metadata"]?["resourceVersion"]?.GetValue<string>(),
            out var initialVersion)
            ? initialVersion
            : 0;
        private bool conflictPending = conflictOnce;
        public JsonObject? Current { get; private set; } = initial?.DeepClone().AsObject();
        public int PutAttempts { get; private set; }
        public int RestartPatches { get; private set; }
        public bool Created { get; private set; }
        public List<string?> Tokens { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Tokens.Add(request.Headers.Authorization?.Parameter);
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/api/v1/namespaces/production")
                return Response(HttpStatusCode.OK, "{}");
            if (request.Method == HttpMethod.Patch)
            {
                RestartPatches++;
                Assert.Equal("application/merge-patch+json", request.Content!.Headers.ContentType!.MediaType);
                return Response(HttpStatusCode.OK, "{}");
            }
            if (request.Method == HttpMethod.Get)
                return Current is null
                    ? Response(HttpStatusCode.NotFound, "{}")
                    : Response(HttpStatusCode.OK, Current.ToJsonString());
            if (request.Method == HttpMethod.Post)
            {
                Created = true;
                Current = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
                SetVersion();
                return Response(HttpStatusCode.Created, Current.ToJsonString());
            }
            if (request.Method == HttpMethod.Put)
            {
                PutAttempts++;
                if (conflictPending)
                {
                    conflictPending = false;
                    version++;
                    Current!["metadata"]!["resourceVersion"] = version.ToString();
                    return Response(HttpStatusCode.Conflict, "{}");
                }
                Current = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
                SetVersion();
                return Response(HttpStatusCode.OK, Current.ToJsonString());
            }
            if (request.Method == HttpMethod.Delete)
            {
                Current = null;
                return Response(HttpStatusCode.OK, "{}");
            }
            return Response(HttpStatusCode.MethodNotAllowed, "{}");
        }

        private void SetVersion()
        {
            version++;
            Current!["metadata"]!["resourceVersion"] = version.ToString();
        }

        private static HttpResponseMessage Response(HttpStatusCode status, string json) => new(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }
}
