namespace CertificateDiscovery.Infrastructure.Scheduling;

using CertificateDiscovery.Application.Options;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public sealed class ScanSchedulerService(IServiceScopeFactory scopeFactory, IOptions<CertificateDiscoveryOptions> options, ILogger<ScanSchedulerService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.SchedulerEnabled)
        {
            logger.LogInformation("Scan scheduler is disabled by initial configuration; runtime settings will still be checked.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CreateDueJobsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduler iteration failed.");
            }

            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task CreateDueJobsAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateDiscoveryDbContext>();
        var settings = await scope.ServiceProvider.GetRequiredService<ApplicationSettingsService>().GetAsync(cancellationToken);
        if (!settings.SchedulerEnabled)
        {
            return;
        }

        var now = DateTime.UtcNow;
        var dueAssets = await db.Assets
            .Where(x => x.IsEnabled && (x.NextScanAtUtc == null || x.NextScanAtUtc <= now))
            .OrderBy(x => x.NextScanAtUtc)
            .Take(50)
            .ToListAsync(cancellationToken);

        foreach (var asset in dueAssets)
        {
            var duplicateExists = await db.ScanJobAssets.AnyAsync(x =>
                x.AssetId == asset.Id &&
                (x.ScanJob.Status == ScanJobStatus.Pending || x.ScanJob.Status == ScanJobStatus.Running),
                cancellationToken);
            if (duplicateExists) continue;

            var job = new ScanJob { TriggerType = ScanTriggerType.Scheduled, TotalAssetCount = 1 };
            job.Assets.Add(new ScanJobAsset { ScanJob = job, AssetId = asset.Id });
            asset.NextScanAtUtc = now.AddMinutes(asset.ScanIntervalMinutes);
            db.ScanJobs.Add(job);
        }

        await db.SaveChangesAsync(cancellationToken);
    }
}
