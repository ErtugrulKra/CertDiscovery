namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/workers")]
[AllowAnonymous]
[WorkerApiKeyFilter]
public sealed class ApiWorkersController(ScanJobService jobs, WorkerService workers) : ControllerBase
{
    [HttpGet("jobs/next")]
    public async Task<ActionResult<WorkerJobDto>> Next([FromQuery] string workerName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workerName)) return BadRequest("workerName is required.");
        var job = await jobs.ClaimNextAsync(workerName, cancellationToken);
        return job is null ? NoContent() : job;
    }

    [HttpPost("heartbeat")]
    public async Task<IActionResult> Heartbeat(WorkerHeartbeatRequest request, CancellationToken cancellationToken)
    {
        await workers.HeartbeatAsync(request, cancellationToken);
        return NoContent();
    }

    [HttpPost("scan-results")]
    public async Task<IActionResult> ScanResult(WorkerScanResultRequest request, CancellationToken cancellationToken)
    {
        await jobs.RecordResultAsync(request, cancellationToken);
        return NoContent();
    }
}
