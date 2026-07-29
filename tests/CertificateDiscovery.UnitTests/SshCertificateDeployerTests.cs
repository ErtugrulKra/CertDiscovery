using System.Security.Cryptography;
using System.Text;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class SshCertificateDeployerTests
{
    [Theory]
    [InlineData(DeploymentTargetType.Nginx)]
    [InlineData(DeploymentTargetType.ApacheWebServer)]
    public async Task Deploys_validates_reloads_and_verifies_remote_files(DeploymentTargetType type)
    {
        var remote = new FakeRemote();
        var deployer = Create(type, remote);
        var context = Context(type);
        var bundle = Bundle();

        Assert.True((await deployer.ValidateTargetAsync(new(context.Target, "vault-token"), default)).IsValid);
        var backup = await deployer.BackupAsync(context, default);
        var apply = await deployer.DeployAsync(context, bundle, default);
        var activation = await deployer.ActivateAsync(context, default);
        var verification = await deployer.VerifyAsync(context, bundle, default);

        Assert.True(backup.Succeeded);
        Assert.True(apply.Succeeded);
        Assert.True(activation.Succeeded);
        Assert.True(verification.Succeeded);
        Assert.Equal(bundle.Fingerprint, verification.ObservedFingerprint);
        Assert.Equal(3, remote.Files.Count);
        Assert.Equal(1, remote.ValidationCount);
        Assert.Equal(1, remote.ReloadCount);
        Assert.Equal("0600", remote.Modes["/etc/tls/private-key.pem"]);
    }

    [Fact]
    public async Task Configuration_test_failure_prevents_reload()
    {
        var remote = new FakeRemote { FailValidation = true };
        var deployer = Create(DeploymentTargetType.Nginx, remote);

        var result = await deployer.ActivateAsync(Context(DeploymentTargetType.Nginx), default);

        Assert.False(result.Succeeded);
        Assert.Equal(1, remote.ValidationCount);
        Assert.Equal(0, remote.ReloadCount);
    }

    [Fact]
    public async Task Rollback_restores_manifest_then_validates_and_reloads()
    {
        var remote = new FakeRemote();
        var deployer = Create(DeploymentTargetType.Nginx, remote);
        var context = Context(DeploymentTargetType.Nginx);
        var backup = await deployer.BackupAsync(context, default);
        await deployer.DeployAsync(context, Bundle(), default);

        var result = await deployer.RollbackAsync(context, backup, default);

        Assert.True(result.Succeeded);
        Assert.Equal(3, remote.Restored.Count);
        Assert.Equal(1, remote.ValidationCount);
        Assert.Equal(1, remote.ReloadCount);
    }

    [Fact]
    public async Task Rejects_backup_manifest_from_another_deployment()
    {
        var remote = new FakeRemote();
        var deployer = Create(DeploymentTargetType.Nginx, remote);
        var context = Context(DeploymentTargetType.Nginx);
        var backup = await deployer.BackupAsync(context, default);
        var other = context with { Deployment = new CertificateDeployment { Id = Guid.NewGuid() } };

        var result = await deployer.RollbackAsync(other, backup, default);

        Assert.False(result.Succeeded);
        Assert.Empty(remote.Restored);
    }

    private static ICertificateDeployer Create(DeploymentTargetType type, FakeRemote remote) =>
        type == DeploymentTargetType.Nginx
            ? new NginxSshCertificateDeployer(new FakeCredentials(), remote, new TlsEndpointVerifier())
            : new ApacheSshCertificateDeployer(new FakeCredentials(), remote, new TlsEndpointVerifier());

    private static DeploymentContext Context(DeploymentTargetType type)
    {
        var target = SshTargetOptionsTests.Target(type);
        var deployment = new CertificateDeployment { Id = Guid.NewGuid(), PreviousFingerprint = "OLD" };
        return new(deployment, target, new DeploymentPolicy(), "vault-token");
    }

    private static IssuedCertificateBundle Bundle() =>
        new("CERTIFICATE", "PRIVATE-KEY", "CERTIFICATE\nCHAIN", "EXPECTED");

    private sealed class FakeCredentials : ISshCredentialSource
    {
        public Task<SshPrivateKeyCredential> LoadAsync(
            SshCertificateTargetOptions options,
            string vaultToken,
            CancellationToken cancellationToken)
        {
            Assert.Equal("vault-token", vaultToken);
            return Task.FromResult(new SshPrivateKeyCredential("PRIVATE SSH KEY", null));
        }
    }

    private sealed class FakeRemote : ISshRemoteClient
    {
        public Dictionary<string, byte[]> Files { get; } = [];
        public Dictionary<string, string> Modes { get; } = [];
        public List<RemoteFileBackup> Restored { get; } = [];
        public int ValidationCount { get; private set; }
        public int ReloadCount { get; private set; }
        public bool FailValidation { get; init; }

        public Task ProbeAsync(SshCertificateTargetOptions options, SshPrivateKeyCredential credential, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<RemoteFileBackup>> BackupAsync(
            SshCertificateTargetOptions options,
            SshPrivateKeyCredential credential,
            Guid deploymentId,
            IReadOnlyList<string> paths,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<RemoteFileBackup>>(
                paths.Select(path => new RemoteFileBackup(path, false, null)).ToList());

        public Task WriteAtomicAsync(
            SshCertificateTargetOptions options,
            SshPrivateKeyCredential credential,
            string path,
            byte[] content,
            string mode,
            CancellationToken cancellationToken)
        {
            Files[path] = content.ToArray();
            Modes[path] = mode;
            return Task.CompletedTask;
        }

        public Task<string?> HashAsync(
            SshCertificateTargetOptions options,
            SshPrivateKeyCredential credential,
            string path,
            CancellationToken cancellationToken) =>
            Task.FromResult<string?>(Files.TryGetValue(path, out var content)
                ? Convert.ToHexString(SHA256.HashData(content))
                : null);

        public Task ExecuteValidationAsync(SshCertificateTargetOptions options, SshPrivateKeyCredential credential, CancellationToken cancellationToken)
        {
            ValidationCount++;
            return FailValidation
                ? Task.FromException(new InvalidOperationException("Configuration test failed."))
                : Task.CompletedTask;
        }

        public Task ExecuteReloadAsync(SshCertificateTargetOptions options, SshPrivateKeyCredential credential, CancellationToken cancellationToken)
        {
            ReloadCount++;
            return Task.CompletedTask;
        }

        public Task RestoreAsync(
            SshCertificateTargetOptions options,
            SshPrivateKeyCredential credential,
            IReadOnlyList<RemoteFileBackup> files,
            CancellationToken cancellationToken)
        {
            Restored.AddRange(files);
            return Task.CompletedTask;
        }
    }
}
