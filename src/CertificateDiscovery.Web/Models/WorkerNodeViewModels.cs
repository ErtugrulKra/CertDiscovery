namespace CertificateDiscovery.Web.Models;

public sealed class WorkerNodeCreateViewModel
{
    public string WorkerName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
}

public sealed class WorkerNodeEditViewModel
{
    public Guid Id { get; set; }
    public string WorkerName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; }
}
