namespace CertificateDiscovery.Infrastructure;

using CertificateDiscovery.Application.Options;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Scheduling;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddCertificateDiscoveryInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("CertificateDiscovery");
        services.Configure<CertificateDiscoveryOptions>(options =>
        {
            options.WorkerApiKey = section["WorkerApiKey"] ?? options.WorkerApiKey;
            options.SchedulerEnabled = ReadBool(section["SchedulerEnabled"], options.SchedulerEnabled);
            options.DefaultScanIntervalMinutes = ReadInt(section["DefaultScanIntervalMinutes"], options.DefaultScanIntervalMinutes);
            options.ExpireAttentionDays = ReadInt(section["ExpireAttentionDays"], options.ExpireAttentionDays);
            options.ExpireWarningDays = ReadInt(section["ExpireWarningDays"], options.ExpireWarningDays);
            options.ExpireCriticalDays = ReadInt(section["ExpireCriticalDays"], options.ExpireCriticalDays);
            options.MaxConcurrentScans = ReadInt(section["MaxConcurrentScans"], options.MaxConcurrentScans);
            options.ApplyMigrationsOnStartup = ReadBool(section["ApplyMigrationsOnStartup"], options.ApplyMigrationsOnStartup);
        });
        services.AddDbContext<CertificateDiscoveryDbContext>(options =>
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection") ?? "Data Source=certificate-discovery.db"));

        services.AddScoped<AssetService>();
        services.AddScoped<CertificateService>();
        services.AddScoped<ScanJobService>();
        services.AddScoped<WorkerService>();
        services.AddScoped<DashboardService>();
        services.AddScoped<UserService>();
        services.AddScoped<NetworkDiscoveryService>();
        services.AddScoped<ApplicationSettingsService>();
        services.AddScoped<PrometheusMetricsService>();
        services.AddScoped<IntegrationService>();
        services.AddScoped<VaultCertificateImportService>();
        services.AddScoped<CertificateRequestService>();
        services.AddScoped<VaultDiscoveryService>();
        services.AddHttpClient();
        services.AddHostedService<ScanSchedulerService>();
        services.AddHostedService<CertificateRequestRenewalWorker>();
        return services;
    }

    private static int ReadInt(string? value, int fallback) => int.TryParse(value, out var parsed) ? parsed : fallback;
    private static bool ReadBool(string? value, bool fallback) => bool.TryParse(value, out var parsed) ? parsed : fallback;
}
