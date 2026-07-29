using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.IntegrationTests;

public sealed class SshCertificateDeploymentIntegrationTests
{
    [Theory]
    [InlineData(DeploymentTargetType.Nginx, 22221, 18443, "/etc/nginx/tls", "nginx")]
    [InlineData(DeploymentTargetType.ApacheWebServer, 22222, 19443, "/etc/apache2/tls", "apache2")]
    public async Task Deploys_verifies_reloads_and_rolls_back_real_server_over_pinned_ssh(
        DeploymentTargetType type,
        int port,
        int tlsPort,
        string directory,
        string service)
    {
        var privateKey = Environment.GetEnvironmentVariable("P55_SSH_PRIVATE_KEY");
        var fingerprint = Environment.GetEnvironmentVariable($"P55_{type}_HOST_KEY");
        if (string.IsNullOrWhiteSpace(privateKey) || string.IsNullOrWhiteSpace(fingerprint))
            return;
        var target = Target(type, port, tlsPort, directory, service, fingerprint);
        var deployment = new CertificateDeployment { Id = Guid.NewGuid() };
        var context = new DeploymentContext(deployment, target, new DeploymentPolicy(), "integration-token");
        var remote = new SshNetRemoteClient();
        var deployer = type == DeploymentTargetType.Nginx
            ? (ICertificateDeployer)new NginxSshCertificateDeployer(
                new StaticCredentialSource(privateKey), remote, new TlsEndpointVerifier())
            : new ApacheSshCertificateDeployer(
                new StaticCredentialSource(privateKey), remote, new TlsEndpointVerifier());
        var bundle = CertificateBundle();

        Assert.True((await deployer.ValidateTargetAsync(new(target, "integration-token"), default)).IsValid);
        var backup = await deployer.BackupAsync(context, default);
        Assert.True(backup.Succeeded);
        Assert.True((await deployer.DeployAsync(context, bundle, default)).Succeeded);
        Assert.True((await deployer.ActivateAsync(context, default)).Succeeded);
        var verification = await deployer.VerifyAsync(context, bundle, default);
        Assert.True(verification.Succeeded, verification.Message);
        Assert.True((await deployer.RollbackAsync(context, backup, default)).Succeeded);
    }

    private static DeploymentTarget Target(
        DeploymentTargetType type,
        int port,
        int tlsPort,
        string directory,
        string service,
        string fingerprint) => new()
    {
        TargetType = type,
        ConfigurationJson = JsonSerializer.Serialize(new
        {
            host = "127.0.0.1",
            sshPort = port,
            username = "root",
            vaultBaseUrl = "https://vault.invalid",
            sshKeySecretPath = "secret/ssh/integration",
            hostKeyFingerprint = fingerprint,
            certificatePath = $"{directory}/certificate.pem",
            privateKeyPath = $"{directory}/private-key.pem",
            fullChainPath = $"{directory}/fullchain.pem",
            fileOwner = "root",
            fileGroup = "root",
            certificateMode = "0644",
            privateKeyMode = "0600",
            serviceName = service,
            configurationTest = true,
            reloadService = true,
            useSudo = false,
            backupRetention = 2,
            externalVerificationEndpoints = new[] { $"https://localhost:{tlsPort}" }
        })
    };

    private static IssuedCertificateBundle CertificateBundle()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var certificatePem = certificate.ExportCertificatePem();
        return new(
            certificatePem,
            rsa.ExportPkcs8PrivateKeyPem(),
            certificatePem,
            Convert.ToHexString(SHA256.HashData(certificate.RawData)));
    }

    private sealed class StaticCredentialSource(string privateKey) : ISshCredentialSource
    {
        public Task<SshPrivateKeyCredential> LoadAsync(
            SshCertificateTargetOptions options,
            string vaultToken,
            CancellationToken cancellationToken) =>
            Task.FromResult(new SshPrivateKeyCredential(privateKey, null));
    }
}
