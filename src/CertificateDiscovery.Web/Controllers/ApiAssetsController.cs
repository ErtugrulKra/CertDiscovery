namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/assets")]
[Authorize]
public sealed class ApiAssetsController(AssetService assets, ScanJobService jobs) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<AssetDto>>> Get([FromQuery] AssetEnvironment? environment, [FromQuery] AssetProtocol? protocol, [FromQuery] AssetType? assetType, [FromQuery] string? owner, [FromQuery] bool? isEnabled, [FromQuery] int? expiresWithinDays, CancellationToken cancellationToken)
        => await assets.ListAsync(new AssetFilter(environment, protocol, assetType, owner, isEnabled, expiresWithinDays), cancellationToken);

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<AssetDto>> Get(Guid id, CancellationToken cancellationToken)
    {
        var asset = await assets.GetAsync(id, cancellationToken);
        return asset is null ? NotFound() : asset;
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<ActionResult<AssetDto>> Create(AssetCreateRequest request, CancellationToken cancellationToken)
    {
        var asset = await assets.CreateAsync(request, cancellationToken);
        var dto = await assets.GetAsync(asset.Id, cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = asset.Id }, dto);
    }

    [Authorize(Roles = "Admin")]
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, AssetUpdateRequest request, CancellationToken cancellationToken)
        => await assets.UpdateAsync(id, request, cancellationToken) ? NoContent() : NotFound();

    [Authorize(Roles = "Admin")]
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
        => await assets.DeleteAsync(id, cancellationToken) ? NoContent() : NotFound();

    [Authorize(Roles = "Admin")]
    [HttpPost("{id:guid}/scan")]
    public async Task<ActionResult<ScanJobDto>> Scan(Guid id, CancellationToken cancellationToken)
    {
        var job = await jobs.CreateForAssetAsync(id, ScanTriggerType.Manual, cancellationToken);
        if (job is null) return NotFound();
        var dto = await jobs.GetAsync(job.Id, cancellationToken);
        return AcceptedAtAction("Get", "ApiScanJobs", new { id = job.Id }, dto);
    }
}
