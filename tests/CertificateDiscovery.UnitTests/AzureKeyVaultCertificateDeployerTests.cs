using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AzureKeyVaultCertificateDeployerTests
{
    [Fact]
    public async Task Creates_tracks_and_verifies_first_certificate_version()
    {
        var current = Bundle(2);
        var gateway = new FakeGateway();
        var deployer = Create(gateway, new FakeBundles(current));
        var context = Context();

        var validation = await deployer.ValidateTargetAsync(new(context.Target, null), default);
        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, current, default);
        var verified = await deployer.VerifyAsync(context, current, default);

        Assert.True(validation.IsValid);
        Assert.True(backup.Succeeded);
        Assert.True(applied.Succeeded);
        Assert.True(verified.Succeeded);
        Assert.Equal(1, gateway.ImportCount);
        Assert.Contains("/certificates/example-com/v1", context.Deployment.ExternalResourceReference);
    }

    [Fact]
    public async Task Update_manifest_contains_only_references_and_rollback_imports_previous_source_Vault_version()
    {
        var previous = Bundle(1);
        var current = Bundle(2);
        var gateway = new FakeGateway(previous);
        var deployer = Create(gateway, new FakeBundles(current, previous));
        var context = Context();

        var backup = await deployer.BackupAsync(context, default);
        await deployer.DeployAsync(context, current, default);
        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.DoesNotContain("PRIVATE KEY", backup.BackupReference);
        Assert.DoesNotContain("BEGIN CERTIFICATE", backup.BackupReference);
        Assert.Contains("\"PreviousSourceVaultVersion\":1", backup.BackupReference);
        Assert.True(rollback.Succeeded);
        Assert.Equal(previous.Fingerprint, rollback.ObservedFingerprint);
        Assert.Equal(2, gateway.ImportCount);
        Assert.Contains("/v3", context.Deployment.ExternalResourceReference);
    }

    [Fact]
    public async Task Blocks_update_when_previous_source_Vault_version_does_not_match_target()
    {
        var deployed = Bundle(1);
        var unrelated = Bundle(3) with { VaultVersion = 1 };
        var current = Bundle(2);
        var deployer = Create(
            new FakeGateway(deployed),
            new FakeBundles(current, unrelated));

        var backup = await deployer.BackupAsync(Context(), default);

        Assert.False(backup.Succeeded);
        Assert.Contains("does not match", backup.Message);
    }

    [Fact]
    public async Task Does_not_create_duplicate_version_when_current_version_already_matches()
    {
        var current = Bundle(2);
        var gateway = new FakeGateway(current);
        var deployer = Create(gateway, new FakeBundles(current));
        var context = Context();

        var result = await deployer.DeployAsync(context, current, default);

        Assert.True(result.Succeeded);
        Assert.Equal(0, gateway.ImportCount);
        Assert.Contains("already contains", result.Message);
    }

    private static AzureKeyVaultCertificateDeployer Create(
        FakeGateway gateway,
        IVersionedDeploymentCertificateBundleSource bundles) =>
        new(gateway, bundles, new FakeTlsVerifier());

    private static DeploymentContext Context()
    {
        var target = AzureKeyVaultTargetOptionsTests.Target(
            "\"importFormat\":\"Pfx\",\"contentType\":\"application/x-pkcs12\",");
        var deployment = new CertificateDeployment
        {
            ExpectedFingerprint = "unused",
            DeploymentTarget = target
        };
        return new(deployment, target, new DeploymentPolicy());
    }

    private static IssuedCertificateBundle Bundle(int version)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN=v{version}.example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem();
        return new(
            pem,
            key.ExportPkcs8PrivateKeyPem(),
            pem,
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            version);
    }

    private sealed class FakeBundles(
        IssuedCertificateBundle latest,
        IssuedCertificateBundle? previous = null) : IVersionedDeploymentCertificateBundleSource
    {
        public Task<IssuedCertificateBundle> LoadAsync(
            CertificateDeployment deployment,
            CancellationToken cancellationToken) =>
            Task.FromResult(latest);

        public Task<IssuedCertificateBundle> LoadVersionAsync(
            CertificateDeployment deployment,
            int version,
            CancellationToken cancellationToken) =>
            Task.FromResult(previous is not null && previous.VaultVersion == version
                ? previous
                : throw new InvalidOperationException("Source Vault version was not found."));
    }

    private sealed class FakeGateway : IAzureKeyVaultCertificateGateway
    {
        private IssuedCertificateBundle? current;
        private int version;
        public int ImportCount { get; private set; }

        public FakeGateway(IssuedCertificateBundle? current = null)
        {
            this.current = current;
            version = current is null ? 0 : 1;
        }

        public Task<AzureKeyVaultCertificateState?> GetCurrentAsync(
            AzureKeyVaultTargetOptions options,
            string? clientSecret,
            CancellationToken cancellationToken) =>
            Task.FromResult(current is null ? null : State(options, current));

        public Task<AzureKeyVaultCertificateState> ImportAsync(
            AzureKeyVaultTargetOptions options,
            string? clientSecret,
            IssuedCertificateBundle bundle,
            CancellationToken cancellationToken)
        {
            current = bundle;
            version++;
            ImportCount++;
            return Task.FromResult(State(options, bundle));
        }

        private AzureKeyVaultCertificateState State(
            AzureKeyVaultTargetOptions options,
            IssuedCertificateBundle bundle)
        {
            var tags = new Dictionary<string, string>(options.Tags)
            {
                ["certdiscovery-managed-by"] = "CertDiscovery",
                ["certdiscovery-fingerprint"] = bundle.Fingerprint
            };
            if (bundle.VaultVersion is not null)
                tags["certdiscovery-source-vault-version"] = bundle.VaultVersion.Value.ToString();
            return new(
                $"{options.VaultUri}certificates/{options.CertificateName}/v{version}",
                options.CertificateName,
                $"v{version}",
                bundle.Fingerprint,
                options.ContentType,
                options.Enabled,
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddDays(30),
                tags);
        }
    }

    private sealed class FakeTlsVerifier : ITlsEndpointVerifier
    {
        public Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(
            IReadOnlyList<Uri> endpoints,
            string expectedFingerprint,
            CancellationToken cancellationToken) =>
            Task.FromResult((true, (string?)expectedFingerprint, "Verified."));
    }
}
