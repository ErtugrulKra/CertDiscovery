using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class DeploymentWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<DeploymentWorker> logger) : BackgroundService
{
    private readonly string owner = $"deployment-worker-{Environment.MachineName}-{Guid.NewGuid():N}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var queue = scope.ServiceProvider.GetRequiredService<IDeploymentQueue>();
                var job = await queue.ClaimAsync(owner, TimeSpan.FromMinutes(5), stoppingToken);
                if (job is null)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    continue;
                }
                try
                {
                    var orchestrator = scope.ServiceProvider.GetRequiredService<ICertificateDeploymentOrchestrator>();
                    await orchestrator.ExecuteAsync(job.CertificateDeploymentId, owner, stoppingToken);
                    await queue.CompleteAsync(job.Id, stoppingToken);
                }
                catch (Exception ex)
                {
                    var db = scope.ServiceProvider.GetRequiredService<CertificateDiscoveryDbContext>();
                    var deployment = await db.CertificateDeployments.Include(x => x.DeploymentPolicy)
                        .FirstAsync(x => x.Id == job.CertificateDeploymentId, stoppingToken);
                    if (deployment.Status == CertificateDeploymentStatus.RolledBack)
                    {
                        await queue.CompleteAsync(job.Id, stoppingToken);
                    }
                    else if (deployment.Status == CertificateDeploymentStatus.Failed && job.RetryCount + 1 < deployment.DeploymentPolicy.MaxAttempts)
                    {
                        deployment.Status = CertificateDeploymentStatus.Pending;
                        deployment.UpdatedAtUtc = DateTime.UtcNow;
                        db.DeploymentAuditEvents.Add(new DeploymentAuditEvent
                        {
                            CertificateDeploymentId = deployment.Id,
                            EventType = "AutomaticRetryScheduled",
                            Actor = owner,
                            Status = deployment.Status,
                            Message = $"Retry {job.RetryCount + 1} of {deployment.DeploymentPolicy.MaxAttempts} was scheduled."
                        });
                        await db.SaveChangesAsync(stoppingToken);
                        await queue.FailAsync(job.Id, ex.Message, deployment.DeploymentPolicy.MaxAttempts,
                            TimeSpan.FromSeconds(deployment.DeploymentPolicy.RetryDelaySeconds), stoppingToken);
                    }
                    else
                    {
                        await queue.FailAsync(job.Id, ex.Message, 1, TimeSpan.Zero, stoppingToken);
                    }
                    logger.LogWarning("Deployment job {JobId} failed with code {ErrorType}.", job.Id, ex.GetType().Name);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception ex)
            {
                logger.LogError(ex, "Deployment worker loop failed.");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }
}
