namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Application.Options;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

public sealed class ApplicationSettingsService(CertificateDiscoveryDbContext db, IOptions<CertificateDiscoveryOptions> options)
{
    private const string SchedulerEnabledKey = "SchedulerEnabled";
    private const string DefaultScanIntervalMinutesKey = "DefaultScanIntervalMinutes";
    private const string ExpireCriticalDaysKey = "ExpireCriticalDays";
    private const string ExpireWarningDaysKey = "ExpireWarningDays";
    private const string ExpireAttentionDaysKey = "ExpireAttentionDays";
    private const string MaxConcurrentScansKey = "MaxConcurrentScans";

    public async Task<ApplicationSettingsDto> GetAsync(CancellationToken cancellationToken)
    {
        var values = await db.AppSettings.AsNoTracking().ToDictionaryAsync(x => x.Key, x => x.Value, cancellationToken);
        var fallback = options.Value;
        return new ApplicationSettingsDto(
            ReadBool(values, SchedulerEnabledKey, fallback.SchedulerEnabled),
            ReadInt(values, DefaultScanIntervalMinutesKey, fallback.DefaultScanIntervalMinutes),
            ReadInt(values, ExpireCriticalDaysKey, fallback.ExpireCriticalDays),
            ReadInt(values, ExpireWarningDaysKey, fallback.ExpireWarningDays),
            ReadInt(values, ExpireAttentionDaysKey, fallback.ExpireAttentionDays),
            ReadInt(values, MaxConcurrentScansKey, fallback.MaxConcurrentScans));
    }

    public async Task UpdateAsync(UpdateApplicationSettingsRequest request, CancellationToken cancellationToken)
    {
        Validate(request);
        await UpsertAsync(SchedulerEnabledKey, request.SchedulerEnabled.ToString(), "Enables scheduled scan job creation.", cancellationToken);
        await UpsertAsync(DefaultScanIntervalMinutesKey, request.DefaultScanIntervalMinutes.ToString(), "Default interval for newly created assets.", cancellationToken);
        await UpsertAsync(ExpireCriticalDaysKey, request.ExpireCriticalDays.ToString(), "Critical certificate expiration threshold in days.", cancellationToken);
        await UpsertAsync(ExpireWarningDaysKey, request.ExpireWarningDays.ToString(), "Warning certificate expiration threshold in days.", cancellationToken);
        await UpsertAsync(ExpireAttentionDaysKey, request.ExpireAttentionDays.ToString(), "Attention certificate expiration threshold in days.", cancellationToken);
        await UpsertAsync(MaxConcurrentScansKey, request.MaxConcurrentScans.ToString(), "Maximum concurrent scans used by application services.", cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task UpsertAsync(string key, string value, string description, CancellationToken cancellationToken)
    {
        var setting = await db.AppSettings.FirstOrDefaultAsync(x => x.Key == key, cancellationToken);
        if (setting is null)
        {
            db.AppSettings.Add(new AppSetting
            {
                Key = key,
                Value = value,
                Description = description
            });
            return;
        }

        setting.Value = value;
        setting.Description = description;
        setting.UpdatedAtUtc = DateTime.UtcNow;
    }

    private static void Validate(UpdateApplicationSettingsRequest request)
    {
        if (request.DefaultScanIntervalMinutes is < 1 or > 525600) throw new ArgumentException("Default scan interval must be between 1 minute and 1 year.");
        if (request.ExpireCriticalDays is < 0 or > 365) throw new ArgumentException("Critical threshold must be between 0 and 365 days.");
        if (request.ExpireWarningDays is < 1 or > 730) throw new ArgumentException("Warning threshold must be between 1 and 730 days.");
        if (request.ExpireAttentionDays is < 1 or > 1095) throw new ArgumentException("Attention threshold must be between 1 and 1095 days.");
        if (request.ExpireCriticalDays > request.ExpireWarningDays) throw new ArgumentException("Critical threshold cannot be greater than warning threshold.");
        if (request.ExpireWarningDays > request.ExpireAttentionDays) throw new ArgumentException("Warning threshold cannot be greater than attention threshold.");
        if (request.MaxConcurrentScans is < 1 or > 1000) throw new ArgumentException("Maximum concurrent scans must be between 1 and 1000.");
    }

    private static int ReadInt(IReadOnlyDictionary<string, string> values, string key, int fallback) =>
        values.TryGetValue(key, out var value) && int.TryParse(value, out var parsed) ? parsed : fallback;

    private static bool ReadBool(IReadOnlyDictionary<string, string> values, string key, bool fallback) =>
        values.TryGetValue(key, out var value) && bool.TryParse(value, out var parsed) ? parsed : fallback;
}
