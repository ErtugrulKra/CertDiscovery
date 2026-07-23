namespace CertificateDiscovery.Contracts;

public sealed record DashboardDto(
    int TotalAssets,
    int ActiveAssets,
    int TotalCertificates,
    int ExpiredCertificates,
    int ExpiringIn7Days,
    int ExpiringIn30Days,
    int ExpiringIn60Days,
    int CriticalThresholdDays,
    int WarningThresholdDays,
    int AttentionThresholdDays,
    DateTime? LastScanAtUtc,
    int LastScanSuccessCount,
    int LastScanFailedCount,
    IReadOnlyList<WorkerNodeDto> Workers,
    IReadOnlyList<CertificateSummaryDto> UpcomingExpirations);
