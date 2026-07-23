namespace CertificateDiscovery.Contracts;

public sealed record ApplicationSettingsDto(
    bool SchedulerEnabled,
    int DefaultScanIntervalMinutes,
    int ExpireCriticalDays,
    int ExpireWarningDays,
    int ExpireAttentionDays,
    int MaxConcurrentScans);

public sealed record UpdateApplicationSettingsRequest(
    bool SchedulerEnabled,
    int DefaultScanIntervalMinutes,
    int ExpireCriticalDays,
    int ExpireWarningDays,
    int ExpireAttentionDays,
    int MaxConcurrentScans);
