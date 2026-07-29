using WinDeployAgent;
using WinDeployAgent.Contracts;
using Xunit;

namespace WinDeployAgent.Tests;

public sealed class AgentRecoveryTests
{
    [Fact]
    public void Resumes_protected_active_job_while_lease_is_valid()
    {
        var now = DateTime.UtcNow;
        var job = new AgentJobClaimResponse(Guid.NewGuid(), "lease", now.AddMinutes(1), "{}");

        Assert.True(AgentWorker.CanResume(job, now));
    }

    [Fact]
    public void Discards_active_job_before_expired_lease_is_reclaimed()
    {
        var now = DateTime.UtcNow;
        var job = new AgentJobClaimResponse(Guid.NewGuid(), "lease", now.AddSeconds(5), "{}");

        Assert.False(AgentWorker.CanResume(job, now));
    }
}
