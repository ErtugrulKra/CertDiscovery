using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace CertificateDiscovery.Web.Controllers;

[ApiController]
[Route("api/deployment-agents")]
public sealed class ApiDeploymentAgentsController(
    DeploymentAgentService service,
    AgentDeploymentJobService jobs) : ControllerBase
{
    [Authorize(Roles = "Admin")]
    [HttpPost("registration-tokens")]
    public async Task<ActionResult<DeploymentAgentRegistrationTokenResponse>> CreateRegistrationToken(
        DeploymentAgentRegistrationTokenRequest request,
        CancellationToken cancellationToken) =>
        await service.CreateRegistrationTokenAsync(request, User.Identity?.Name ?? "admin", cancellationToken);

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult<DeploymentAgentRegisterResponse>> Register(
        DeploymentAgentRegisterRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            return await service.RegisterAsync(request, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [EnableRateLimiting("agent-registration-exchange-create")]
    [HttpPost("exchanges")]
    public async Task<ActionResult<DeploymentAgentExchangeCreateResponse>> BeginExchange(
        DeploymentAgentExchangeCreateRequest request,
        CancellationToken cancellationToken)
    {
        var verificationUri = Url.Action(
            "Index",
            "DeploymentAgents",
            values: null,
            protocol: Request.Scheme,
            host: Request.Host.ToString()) ?? "/DeploymentAgents";
        var result = await service.BeginExchangeAsync(request, verificationUri, cancellationToken);
        return result.Response;
    }

    [AllowAnonymous]
    [EnableRateLimiting("agent-registration-exchange-poll")]
    [HttpGet("exchanges/{exchangeId:guid}")]
    public async Task<ActionResult<DeploymentAgentExchangePollResponse>> PollExchange(
        Guid exchangeId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await service.PollExchangeAsync(
                exchangeId,
                Request.Headers["X-Agent-Exchange-Secret"].FirstOrDefault(),
                cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpPost("{agentId:guid}/heartbeat")]
    public async Task<IActionResult> Heartbeat(
        Guid agentId,
        DeploymentAgentHeartbeatRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await service.HeartbeatAsync(agentId, Request.Headers["X-Deployment-Agent-Token"].FirstOrDefault(), request, cancellationToken);
            return NoContent();
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [Authorize(Roles = "Admin")]
    [HttpGet]
    public Task<IReadOnlyList<DeploymentAgentDto>> List(CancellationToken cancellationToken) =>
        service.ListAsync(cancellationToken);

    [Authorize(Roles = "Admin")]
    [HttpPost("{agentId:guid}/revoke")]
    public async Task<IActionResult> Revoke(Guid agentId, CancellationToken cancellationToken)
    {
        try
        {
            await service.RevokeAsync(agentId, cancellationToken);
            return NoContent();
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    [AllowAnonymous]
    [HttpPost("{agentId:guid}/jobs/claim")]
    public async Task<ActionResult<AgentJobClaimResponse>> ClaimJob(Guid agentId, CancellationToken cancellationToken)
    {
        try
        {
            var job = await jobs.ClaimAsync(agentId, AgentToken(), cancellationToken);
            return job is null ? NoContent() : job;
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpPost("{agentId:guid}/jobs/{jobId:guid}/renew-lease")]
    public async Task<IActionResult> RenewLease(
        Guid agentId,
        Guid jobId,
        AgentJobLeaseRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await jobs.RenewLeaseAsync(agentId, jobId, AgentToken(), request.LeaseToken, cancellationToken);
            return NoContent();
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpGet("{agentId:guid}/jobs/{jobId:guid}/bundle")]
    public async Task<ActionResult<AgentJobBundleResponse>> Bundle(
        Guid agentId,
        Guid jobId,
        [FromHeader(Name = "X-Agent-Job-Lease")] string leaseToken,
        CancellationToken cancellationToken)
    {
        try
        {
            return await jobs.GetBundleAsync(agentId, jobId, AgentToken(), leaseToken, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpPost("{agentId:guid}/jobs/{jobId:guid}/stage-result")]
    public async Task<IActionResult> StageResult(
        Guid agentId,
        Guid jobId,
        AgentJobStageResultRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await jobs.RecordStageAsync(agentId, jobId, AgentToken(), request, cancellationToken);
            return NoContent();
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpPost("{agentId:guid}/jobs/{jobId:guid}/complete")]
    public async Task<IActionResult> Complete(
        Guid agentId,
        Guid jobId,
        AgentJobCompleteRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await jobs.CompleteAsync(agentId, jobId, AgentToken(), request, cancellationToken);
            return NoContent();
        }
        catch (UnauthorizedAccessException)
        {
            return Unauthorized();
        }
    }

    private string? AgentToken() => Request.Headers["X-Deployment-Agent-Token"].FirstOrDefault();
}
