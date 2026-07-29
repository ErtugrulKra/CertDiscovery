using System.ComponentModel.DataAnnotations;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.UnitTests;

public sealed class DeploymentTargetNamingTests
{
    [Theory]
    [InlineData(DeploymentTargetType.Iis, "Microsoft IIS")]
    [InlineData(DeploymentTargetType.Nginx, "NGNIX")]
    [InlineData(DeploymentTargetType.HaProxy, "HA Proxy")]
    [InlineData(DeploymentTargetType.Traefik, "Traefik")]
    [InlineData(DeploymentTargetType.ApacheWebServer, "Apache Web Server")]
    [InlineData(DeploymentTargetType.VaultKv, "Vault KV")]
    [InlineData(DeploymentTargetType.FileSystem, "File System Export")]
    public void Target_type_uses_required_display_name(DeploymentTargetType type, string expected) =>
        Assert.Equal(expected, type.GetDisplayName());

    [Fact]
    public void Every_target_type_has_a_nonempty_display_name()
    {
        foreach (var type in Enum.GetValues<DeploymentTargetType>())
            Assert.False(string.IsNullOrWhiteSpace(type.GetDisplayName()));
    }
}
