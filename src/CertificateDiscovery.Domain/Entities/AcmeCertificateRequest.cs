namespace CertificateDiscovery.Domain.Entities;

public sealed class AcmeCertificateRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Domain { get; set; } = string.Empty;
    public string? SubjectAlternativeNames { get; set; }
    public AcmeChallengeType ChallengeType { get; set; } = AcmeChallengeType.ManualDns01;
    public CertificateRequestStatus Status { get; set; } = CertificateRequestStatus.Draft;
    public Guid AcmeProviderId { get; set; }
    public AcmeProvider? AcmeProvider { get; set; }
    public Guid? AcmeAccountId { get; set; }
    public AcmeAccount? AcmeAccount { get; set; }
    public Guid VaultServerId { get; set; }
    public VaultServer? VaultServer { get; set; }
    public Guid? DnsProviderId { get; set; }
    public DnsProvider? DnsProvider { get; set; }
    public string VaultSecretPath { get; set; } = string.Empty;
    public string? DnsTxtName { get; set; }
    public string? DnsTxtValue { get; set; }
    public string? AcmeAccountKeyPem { get; set; }
    public string? AcmeOrderLocation { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime? DnsPublishedAtUtc { get; set; }
    public string? DnsPublishStatus { get; set; }
    public string? DnsPublishError { get; set; }
    public bool ScheduleCheck { get; set; }
    public int RenewalThresholdDays { get; set; } = 5;
    public string RenewalCronExpression { get; set; } = "0 0 * * *";
    public DateTime? NextScheduleCheckAtUtc { get; set; }
    public DateTime? LastScheduleCheckAtUtc { get; set; }
    public string? LastScheduleCheckStatus { get; set; }
    public string? LastScheduleCheckMessage { get; set; }
    public Guid? RenewedFromRequestId { get; set; }
    public Guid? LastRenewalRequestId { get; set; }
    public Guid? CertificateId { get; set; }
    public Certificate? Certificate { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? ChallengeCreatedAtUtc { get; set; }
    public DateTime? IssuedAtUtc { get; set; }
    public DateTime? StoredAtUtc { get; set; }
}
