namespace CertificateDiscovery.Domain.Entities;

public sealed class AcmeAccountEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AcmeProviderId { get; set; }
    public Guid? AcmeAccountId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public string? Message { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

