using Microsoft.Extensions.Options;
using WinDeployAgent.Contracts;

namespace WinDeployAgent;

public sealed class AgentWorker(
    CentralClient central,
    AgentJobProcessor processor,
    MachineCredentialStore credentialStore,
    IOptions<AgentOptions> options,
    ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var identity = await credentialStore.LoadAsync(stoppingToken);
        var delay = TimeSpan.FromSeconds(Math.Clamp(options.Value.PollIntervalSeconds, 5, 300));
        while (identity is null && !stoppingToken.IsCancellationRequested)
        {
            try
            {
                logger.LogInformation("Registering IIS deployment agent with Central.");
                identity = await central.RegisterAsync(stoppingToken);
                await credentialStore.SaveAsync(identity, stoppingToken);
                logger.LogInformation("IIS deployment agent registration completed.");
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    "Central is unavailable during agent registration; retrying. ErrorType={ErrorType}",
                    exception.GetType().Name);
                await Task.Delay(delay, stoppingToken);
            }
        }

        if (identity is null) return;
        var activeJob = await credentialStore.LoadActiveJobAsync(stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await central.HeartbeatAsync(identity, busy: false, stoppingToken);
                if (activeJob is not null && !CanResume(activeJob, DateTime.UtcNow))
                {
                    credentialStore.DeleteActiveJob();
                    activeJob = null;
                }
                var job = activeJob ?? await central.ClaimAsync(identity, stoppingToken);
                if (job is not null)
                {
                    if (activeJob is null)
                        await credentialStore.SaveActiveJobAsync(job, stoppingToken);
                    await central.HeartbeatAsync(identity, busy: true, stoppingToken);
                    if (await processor.ProcessAsync(identity, job, stoppingToken))
                    {
                        credentialStore.DeleteActiveJob();
                        activeJob = null;
                    }
                    else
                    {
                        activeJob = job;
                    }
                }
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError("Agent heartbeat failed: {ErrorType}", exception.GetType().Name);
            }
            await Task.Delay(delay, stoppingToken);
        }
    }

    public static bool CanResume(AgentJobClaimResponse job, DateTime utcNow) =>
        job.LeaseExpiresAtUtc > utcNow.AddSeconds(5);
}
