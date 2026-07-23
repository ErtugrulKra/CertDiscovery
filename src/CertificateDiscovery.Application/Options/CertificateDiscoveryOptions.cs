namespace CertificateDiscovery.Application.Options;

public sealed class CertificateDiscoveryOptions
{
    public string WorkerApiKey { get; set; } = "dev-worker-key-change-me";
    public bool SchedulerEnabled { get; set; } = true;
    public int DefaultScanIntervalMinutes { get; set; } = 1440;
    public int ExpireAttentionDays { get; set; } = 60;
    public int ExpireWarningDays { get; set; } = 30;
    public int ExpireCriticalDays { get; set; } = 7;
    public int MaxConcurrentScans { get; set; } = 10;
    public bool ApplyMigrationsOnStartup { get; set; } = true;
}
