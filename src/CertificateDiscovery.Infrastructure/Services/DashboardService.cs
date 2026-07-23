namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Mapping;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class DashboardService(CertificateDiscoveryDbContext db, WorkerService workers, ApplicationSettingsService settings)
{
    public async Task<DashboardDto> GetAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var appSettings = await settings.GetAsync(cancellationToken);
        var certificates = await db.Certificates.Include(x => x.AssetCertificates).ToListAsync(cancellationToken);
        var lastJob = await db.ScanJobs.OrderByDescending(x => x.RequestedAtUtc).FirstOrDefaultAsync(cancellationToken);
        var upcoming = certificates.Where(x => x.NotAfterUtc >= now).OrderBy(x => x.NotAfterUtc).Take(20)
            .Select(x => DtoMapper.ToSummary(x, now, appSettings.ExpireCriticalDays, appSettings.ExpireWarningDays, appSettings.ExpireAttentionDays))
            .ToList();

        return new DashboardDto(
            await db.Assets.CountAsync(cancellationToken),
            await db.Assets.CountAsync(x => x.IsEnabled, cancellationToken),
            certificates.Count,
            certificates.Count(x => CertificateStatusCalculator.GetStatus(x.NotAfterUtc, now, appSettings.ExpireCriticalDays, appSettings.ExpireWarningDays, appSettings.ExpireAttentionDays) == CertificateHealthStatus.Expired),
            certificates.Count(x => CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) is >= 0 && CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) <= appSettings.ExpireCriticalDays),
            certificates.Count(x => CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) is >= 0 && CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) <= appSettings.ExpireWarningDays),
            certificates.Count(x => CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) is >= 0 && CertificateStatusCalculator.RemainingDays(x.NotAfterUtc, now) <= appSettings.ExpireAttentionDays),
            appSettings.ExpireCriticalDays,
            appSettings.ExpireWarningDays,
            appSettings.ExpireAttentionDays,
            lastJob?.CompletedAtUtc ?? lastJob?.StartedAtUtc ?? lastJob?.RequestedAtUtc,
            lastJob?.SuccessfulAssetCount ?? 0,
            lastJob?.FailedAssetCount ?? 0,
            await workers.ListAsync(cancellationToken),
            upcoming);
    }
}
