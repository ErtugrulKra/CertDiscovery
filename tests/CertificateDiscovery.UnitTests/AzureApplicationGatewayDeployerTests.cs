using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AzureApplicationGatewayDeployerTests
{
    [Fact]
    public async Task Applies_Key_Vault_reference_and_verifies_listener_and_endpoint()
    {
        var bundle = Bundle(2);
        var gateway = new FakeGateway();
        var deployer = new AzureApplicationGatewayDeployer(gateway, new Bundles(bundle), new Tls());
        var context = Context();
        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, bundle, default);
        var verified = await deployer.VerifyAsync(context, bundle, default);

        Assert.True(backup.Succeeded);
        Assert.True(applied.Succeeded);
        Assert.True(verified.Succeeded);
        Assert.DoesNotContain("PRIVATE KEY", backup.BackupReference);
        Assert.Equal("https://certs.vault.azure.net/secrets/example-com", gateway.SecretId);
    }

    [Fact]
    public async Task Direct_upload_rollback_reads_previous_source_Vault_version()
    {
        var previous = Bundle(1);
        var current = Bundle(2);
        var gateway = new FakeGateway();
        var deployer = new AzureApplicationGatewayDeployer(gateway, new Bundles(current, previous), new Tls());
        var context = Context("DirectUpload");

        var backup = await deployer.BackupAsync(context, default);
        await deployer.DeployAsync(context, current, default);
        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.True(rollback.Succeeded);
        Assert.Equal(2, gateway.Uploads);
        Assert.Contains("\"PreviousSourceVaultVersion\":1", backup.BackupReference);
        Assert.DoesNotContain("CERTIFICATE", backup.BackupReference);
    }

    [Fact]
    public async Task Rejects_Key_Vault_mode_when_gateway_has_no_user_assigned_identity()
    {
        var bundle = Bundle(2);
        var gateway = new FakeGateway { HasIdentity = false };
        var deployer = new AzureApplicationGatewayDeployer(gateway, new Bundles(bundle), new Tls());
        var result = await deployer.PrecheckAsync(Context(), default);
        Assert.False(result.IsReady);
        Assert.Contains("user-assigned", result.Message);
    }

    private static DeploymentContext Context(string mode = "KeyVaultReference")
    {
        var target = AzureApplicationGatewayTargetOptionsTests.Target(mode: mode);
        var deployment = new CertificateDeployment { DeploymentTarget = target, PreviousFingerprint = "old" };
        return new(deployment, target, new DeploymentPolicy());
    }
    private static IssuedCertificateBundle Bundle(int version) =>
        new("CERTIFICATE", "PRIVATE KEY", "CHAIN", $"fingerprint-{version}", version);

    private sealed class Bundles(IssuedCertificateBundle current, IssuedCertificateBundle? previous = null) : IVersionedDeploymentCertificateBundleSource
    {
        public Task<IssuedCertificateBundle> LoadAsync(CertificateDeployment deployment, CancellationToken cancellationToken) => Task.FromResult(current);
        public Task<IssuedCertificateBundle> LoadVersionAsync(CertificateDeployment deployment, int version, CancellationToken cancellationToken) =>
            Task.FromResult(previous ?? throw new InvalidOperationException("Missing version."));
    }
    private sealed class Tls : ITlsEndpointVerifier
    {
        public Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(IReadOnlyList<Uri> endpoints, string expectedFingerprint, CancellationToken cancellationToken) =>
            Task.FromResult((true, (string?)expectedFingerprint, "Verified."));
    }
    private sealed class FakeGateway : IAzureApplicationGateway
    {
        public bool HasIdentity { get; set; } = true;
        public int Uploads { get; private set; }
        public string? SecretId { get; private set; }
        private string certificateId = "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/applicationGateways/g/sslCertificates/old";
        public Task<AzureApplicationGatewayState> GetAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, CancellationToken cancellationToken) => Task.FromResult(State());
        public Task<AzureApplicationGatewayState> ApplyKeyVaultReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, Uri secretId, CancellationToken cancellationToken)
        {
            SecretId = secretId.ToString(); certificateId = $"{certificateId[..(certificateId.LastIndexOf('/') + 1)]}{options.SslCertificateName}";
            return Task.FromResult(State());
        }
        public Task<AzureApplicationGatewayState> UploadAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, IssuedCertificateBundle bundle, CancellationToken cancellationToken)
        {
            Uploads++; certificateId = $"{certificateId[..(certificateId.LastIndexOf('/') + 1)]}{options.SslCertificateName}";
            return Task.FromResult(State());
        }
        public Task<AzureApplicationGatewayState> RestoreReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, string listenerCertificateId, string? secretId, CancellationToken cancellationToken)
        {
            certificateId = listenerCertificateId; SecretId = secretId; return Task.FromResult(State());
        }
        private AzureApplicationGatewayState State() => new("/gateway", "Succeeded", HasIdentity, true, true, certificateId, certificateId, SecretId);
    }
}
