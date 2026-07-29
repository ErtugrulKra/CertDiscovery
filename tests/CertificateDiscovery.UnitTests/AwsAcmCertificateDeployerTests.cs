using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AwsAcmCertificateDeployerTests
{
    [Fact]
    public async Task Creates_and_records_a_new_imported_certificate()
    {
        var current = Bundle(2);
        var gateway = new FakeGateway();
        var deployer = new AwsAcmCertificateDeployer(
            gateway,
            new FakeBundles(current),
            new FakeTlsVerifier());
        var context = Context();

        var backup = await deployer.BackupAsync(context, default);
        var applied = await deployer.DeployAsync(context, current, default);
        var verified = await deployer.VerifyAsync(context, current, default);

        Assert.True(backup.Succeeded);
        Assert.True(applied.Succeeded);
        Assert.NotNull(context.Deployment.ExternalResourceReference);
        Assert.True(verified.Succeeded);
        Assert.Equal(current.Fingerprint, verified.ObservedFingerprint);
    }

    [Fact]
    public async Task Update_manifest_references_only_the_previous_Vault_version_and_rollback_restores_it()
    {
        var previous = Bundle(1);
        var current = Bundle(2);
        const string arn = "arn:aws:acm:eu-central-1:123456789012:certificate/11111111-1111-1111-1111-111111111111";
        var gateway = new FakeGateway(arn, previous);
        var deployer = new AwsAcmCertificateDeployer(
            gateway,
            new FakeBundles(current, previous),
            new FakeTlsVerifier());
        var context = Context(arn);

        var precheck = await deployer.PrecheckAsync(context, default);
        var backup = await deployer.BackupAsync(context, default);
        await deployer.DeployAsync(context, current, default);
        var rollback = await deployer.RollbackAsync(context, backup, default);

        Assert.Equal(previous.Fingerprint, precheck.PreviousFingerprint);
        Assert.DoesNotContain("PRIVATE KEY", backup.BackupReference);
        Assert.Contains("\"PreviousVaultVersion\":1", backup.BackupReference);
        Assert.True(rollback.Succeeded);
        Assert.Equal(previous.Fingerprint, rollback.ObservedFingerprint);
    }

    [Fact]
    public async Task Blocks_update_when_previous_Vault_version_does_not_match_ACM()
    {
        var acmCertificate = Bundle(1);
        var unrelatedPrevious = Bundle(3) with { VaultVersion = 1 };
        var current = Bundle(2);
        const string arn = "arn:aws:acm:eu-central-1:123456789012:certificate/22222222-2222-2222-2222-222222222222";
        var deployer = new AwsAcmCertificateDeployer(
            new FakeGateway(arn, acmCertificate),
            new FakeBundles(current, unrelatedPrevious),
            new FakeTlsVerifier());

        var backup = await deployer.BackupAsync(Context(arn), default);

        Assert.False(backup.Succeeded);
        Assert.Contains("does not match", backup.Message);
    }

    private static DeploymentContext Context(string? arn = null)
    {
        var target = new DeploymentTarget
        {
            Name = "acm",
            TargetType = DeploymentTargetType.AwsAcm,
            ConfigurationJson =
                $$"""{"region":"eu-central-1","authenticationMode":"DefaultCredentialChain","certificateArn":{{(arn is null ? "null" : $"\"{arn}\"")}},"createIfMissing":true,"requirePreviousVaultVersionForUpdate":true,"externalVerificationEndpoints":[]}"""
        };
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
                : throw new InvalidOperationException("Vault version was not found."));
    }

    private sealed class FakeGateway : IAwsAcmGateway
    {
        private string? arn;
        private IssuedCertificateBundle? bundle;

        public FakeGateway(string? arn = null, IssuedCertificateBundle? bundle = null)
        {
            this.arn = arn;
            this.bundle = bundle;
        }

        public Task<AwsAcmCertificateState?> DescribeAsync(
            AwsAcmTargetOptions options,
            string? externalId,
            string certificateArn,
            CancellationToken cancellationToken) =>
            Task.FromResult<AwsAcmCertificateState?>(
                arn == certificateArn && bundle is not null
                    ? new(arn, "IMPORTED", "ISSUED", "example.com", null, null, [])
                    : null);

        public Task<string> ImportAsync(
            AwsAcmTargetOptions options,
            string? externalId,
            string? certificateArn,
            IssuedCertificateBundle imported,
            CancellationToken cancellationToken)
        {
            arn = certificateArn ??
                  "arn:aws:acm:eu-central-1:123456789012:certificate/33333333-3333-3333-3333-333333333333";
            bundle = imported;
            return Task.FromResult(arn);
        }

        public Task<string> GetFingerprintAsync(
            AwsAcmTargetOptions options,
            string? externalId,
            string certificateArn,
            CancellationToken cancellationToken) =>
            Task.FromResult(bundle?.Fingerprint ?? throw new InvalidOperationException("Missing certificate."));
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
