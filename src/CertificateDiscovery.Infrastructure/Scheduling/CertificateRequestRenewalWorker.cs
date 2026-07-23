namespace CertificateDiscovery.Infrastructure.Scheduling;

using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public sealed class CertificateRequestRenewalWorker(IServiceScopeFactory scopeFactory, ILogger<CertificateRequestRenewalWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var service = scope.ServiceProvider.GetRequiredService<CertificateRequestService>();
                var processed = await service.RunDueScheduledChecksAsync(stoppingToken);
                if (processed > 0)
                {
                    logger.LogInformation("Processed {Count} scheduled certificate renewal check(s).", processed);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled certificate renewal worker iteration failed.");
            }

            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
