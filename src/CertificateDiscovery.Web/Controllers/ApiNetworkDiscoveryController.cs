namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/network-discovery")]
public sealed class ApiNetworkDiscoveryController(NetworkDiscoveryService discovery) : ControllerBase
{
    [Authorize]
    [HttpGet]
    public async Task<ActionResult<List<DiscoveryJobDto>>> Get(CancellationToken cancellationToken)
        => await discovery.ListAsync(cancellationToken);

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<ActionResult<DiscoveryJobDto>> Create(DiscoveryJobCreateRequest request, CancellationToken cancellationToken)
    {
        var job = await discovery.CreateAsync(request, User.Identity?.Name ?? "api", cancellationToken);
        var dto = (await discovery.ListAsync(cancellationToken)).First(x => x.Id == job.Id);
        return CreatedAtAction(nameof(Get), new { id = job.Id }, dto);
    }

    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpGet("jobs/next")]
    public async Task<ActionResult<WorkerDiscoveryJobDto>> Next([FromQuery] string workerName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workerName)) return BadRequest("workerName is required.");
        var job = await discovery.ClaimNextAsync(workerName, cancellationToken);
        return job is null ? NoContent() : job;
    }

    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpPost("scan-results")]
    public async Task<IActionResult> Result(WorkerDiscoveryResultRequest request, CancellationToken cancellationToken)
    {
        await discovery.RecordResultAsync(request, cancellationToken);
        return NoContent();
    }

    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpPost("{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id, WorkerDiscoveryCompleteRequest request, CancellationToken cancellationToken)
    {
        await discovery.CompleteAsync(id, request.WorkerName, cancellationToken);
        return NoContent();
    }

    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpPost("{id:guid}/fail")]
    public async Task<IActionResult> Fail(Guid id, WorkerDiscoveryFailRequest request, CancellationToken cancellationToken)
    {
        await discovery.FailAsync(id, request.WorkerName, request.ErrorMessage, cancellationToken);
        return NoContent();
    }
}
