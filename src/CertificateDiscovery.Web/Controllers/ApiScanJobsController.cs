namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CertificateDiscovery.Web.Infrastructure;

[ApiController]
[Route("api/scan-jobs")]
[Authorize]
public sealed class ApiScanJobsController(ScanJobService jobs) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<ScanJobDto>>> Get(CancellationToken cancellationToken)
        => await jobs.ListAsync(cancellationToken);

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<ScanJobDto>> Get(Guid id, CancellationToken cancellationToken)
    {
        var job = await jobs.GetAsync(id, cancellationToken);
        return job is null ? NotFound() : job;
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<ActionResult<ScanJobDto>> Create(ScanJobCreateRequest request, CancellationToken cancellationToken)
    {
        if (request.AssetIds is null || request.AssetIds.Count == 0) return BadRequest("At least one asset is required.");
        var job = await jobs.CreateAsync(request.AssetIds, request.TriggerType, cancellationToken);
        var dto = await jobs.GetAsync(job.Id, cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = job.Id }, dto);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("{id:guid}/claim")]
    public async Task<ActionResult<WorkerJobDto>> Claim(Guid id, ScanJobClaimRequest request, CancellationToken cancellationToken)
    {
        var next = await jobs.ClaimNextAsync(request.WorkerName, cancellationToken);
        if (next is null || next.JobId != id) return Conflict();
        return next;
    }

    [Authorize(Roles = "Admin")]
    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpPost("{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id, ScanJobCompleteRequest request, CancellationToken cancellationToken)
    {
        await jobs.CompleteAsync(id, request.WorkerName, cancellationToken);
        return NoContent();
    }

    [Authorize(Roles = "Admin")]
    [AllowAnonymous]
    [WorkerApiKeyFilter]
    [HttpPost("{id:guid}/fail")]
    public async Task<IActionResult> Fail(Guid id, ScanJobFailRequest request, CancellationToken cancellationToken)
    {
        await jobs.FailAsync(id, request.WorkerName, request.ErrorMessage, cancellationToken);
        return NoContent();
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("{id:guid}/requeue")]
    public async Task<ActionResult<ScanJobDto>> Requeue(Guid id, CancellationToken cancellationToken)
    {
        var retryJob = await jobs.RequeueAsync(id, "api", cancellationToken);
        if (retryJob is null) return NotFound();
        var dto = await jobs.GetAsync(retryJob.Id, cancellationToken);
        return AcceptedAtAction(nameof(Get), new { id = retryJob.Id }, dto);
    }
}
