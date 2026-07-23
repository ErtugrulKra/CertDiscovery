namespace CertificateDiscovery.Web.Models;

public sealed class DiscoveryJobCreateViewModel
{
    public string Name { get; set; } = string.Empty;
    public string Cidr { get; set; } = "10.10.0.0/24";
    public string Ports { get; set; } = "443,8443,9443,465,993,995,636";
    public int TimeoutSeconds { get; set; } = 3;
    public int MaxConcurrency { get; set; } = 100;
}
