using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class FileSystemCertificateDeployerTests
{
    [Fact]
    public async Task File_system_deployer_writes_verifies_and_restores_files_atomically()
    {
        var directory = CreateTestDirectory();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(directory, "certificate.pem"), "old-certificate");
            await File.WriteAllTextAsync(Path.Combine(directory, "private-key.pem"), "old-private-key");
            var deployer = new FileSystemCertificateDeployer(new CertificateBundleConverter());
            var target = Target(directory);
            var context = Context(target);
            var bundle = new IssuedCertificateBundle("new-certificate", "new-private-key", "new-chain", "NEW");

            Assert.True((await deployer.ValidateTargetAsync(new(target, null), default)).IsValid);
            Assert.True((await deployer.PrecheckAsync(context, default)).IsReady);
            var backup = await deployer.BackupAsync(context, default);
            Assert.True(backup.Succeeded);
            Assert.True((await deployer.DeployAsync(context, bundle, default)).Succeeded);

            var verification = await deployer.VerifyAsync(context, bundle, default);
            Assert.True(verification.Succeeded);
            Assert.Equal("NEW", verification.ObservedFingerprint);
            Assert.Equal("new-private-key", await File.ReadAllTextAsync(Path.Combine(directory, "private-key.pem")));
            Assert.Empty(Directory.GetFiles(directory, "*.tmp-*"));

            await File.WriteAllTextAsync(Path.Combine(directory, "certificate.pem"), "tampered");
            var failedVerification = await deployer.VerifyAsync(context, bundle, default);
            Assert.False(failedVerification.Succeeded);
            Assert.Contains("hash verification", failedVerification.Message);

            var rollback = await deployer.RollbackAsync(context, backup, default);
            Assert.True(rollback.Succeeded);
            Assert.Equal("old-certificate", await File.ReadAllTextAsync(Path.Combine(directory, "certificate.pem")));
            Assert.Equal("old-private-key", await File.ReadAllTextAsync(Path.Combine(directory, "private-key.pem")));
            Assert.False(File.Exists(Path.Combine(directory, "fullchain.pem")));
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    [Fact]
    public async Task File_system_deployer_rejects_path_traversal_and_pfx_without_password()
    {
        var directory = CreateTestDirectory();
        try
        {
            var deployer = new FileSystemCertificateDeployer(new CertificateBundleConverter());
            var traversalTarget = Target(directory);
            traversalTarget.ConfigurationJson = $$"""
                {
                  "outputDirectory": {{Json(directory)}},
                  "certificateFile": "../certificate.pem",
                  "privateKeyFile": "private-key.pem",
                  "fullChainFile": "fullchain.pem"
                }
                """;
            var traversal = await deployer.ValidateTargetAsync(new(traversalTarget, null), default);

            var pfxTarget = Target(directory, includePfx: true);
            var noPassword = await deployer.ValidateTargetAsync(new(pfxTarget, null), default);

            Assert.False(traversal.IsValid);
            Assert.Contains("without a directory", traversal.Message);
            Assert.False(noPassword.IsValid);
            Assert.Contains("PFX password", noPassword.Message);
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    [Fact]
    public async Task File_system_rollback_rejects_backup_from_another_deployment()
    {
        var directory = CreateTestDirectory();
        try
        {
            var deployer = new FileSystemCertificateDeployer(new CertificateBundleConverter());
            var target = Target(directory);
            var context = Context(target);
            var result = await deployer.RollbackAsync(
                context,
                new(true, Path.Combine(directory, ".certdiscovery-backups", Guid.NewGuid().ToString("N"))),
                default);

            Assert.False(result.Succeeded);
            Assert.Contains("does not belong", result.Message);
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    private static DeploymentTarget Target(string directory, bool includePfx = false) => new()
    {
        Name = "file-system",
        TargetType = DeploymentTargetType.FileSystem,
        ConfigurationJson = $$"""
            {
              "outputDirectory": {{Json(directory)}},
              "certificateFile": "certificate.pem",
              "privateKeyFile": "private-key.pem",
              "fullChainFile": "fullchain.pem",
              "pfxFile": {{(includePfx ? "\"certificate.pfx\"" : "null")}},
              "privateKeyUnixMode": "600",
              "publicFileUnixMode": "644"
            }
            """
    };

    private static DeploymentContext Context(DeploymentTarget target)
    {
        var deployment = new CertificateDeployment
        {
            CertificateRequest = new() { Domain = "example.com" },
            Certificate = new()
            {
                FingerprintSha256 = "NEW",
                Subject = "CN=example.com",
                Issuer = "CN=Test",
                NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
                NotAfterUtc = DateTime.UtcNow.AddDays(30)
            },
            DeploymentTarget = target,
            DeploymentPolicy = new() { Name = "test" },
            ExpectedFingerprint = "NEW",
            PreviousFingerprint = "OLD"
        };
        return new(deployment, target, deployment.DeploymentPolicy);
    }

    private static string CreateTestDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "certdiscovery-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return Path.GetFullPath(path);
    }

    private static void DeleteTestDirectory(string path)
    {
        var resolved = Path.GetFullPath(path);
        var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "certdiscovery-tests"));
        if (!resolved.StartsWith(expectedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to remove a directory outside the test root.");
        if (Directory.Exists(resolved))
            Directory.Delete(resolved, true);
    }

    private static string Json(string value) => System.Text.Json.JsonSerializer.Serialize(value);
}
