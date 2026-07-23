namespace CertificateDiscovery.Domain.Entities;

public sealed class WorkerNode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string WorkerName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? Version { get; set; }
    public string Status { get; set; } = "Online";
    public bool IsEnabled { get; set; } = true;
    public DateTime LastHeartbeatAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public int ProcessedJobCount { get; set; }
    public string? LastError { get; set; }
}
