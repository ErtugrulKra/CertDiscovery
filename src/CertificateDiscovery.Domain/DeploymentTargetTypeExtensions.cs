using System.ComponentModel.DataAnnotations;
using System.Reflection;

namespace CertificateDiscovery.Domain;

public static class DeploymentTargetTypeExtensions
{
    public static string GetDisplayName(this DeploymentTargetType targetType) =>
        typeof(DeploymentTargetType).GetMember(targetType.ToString()).Single()
            .GetCustomAttribute<DisplayAttribute>()?.Name ?? targetType.ToString();
}
