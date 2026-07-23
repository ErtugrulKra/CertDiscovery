namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
public sealed class AssetsController(AssetService assets, ScanJobService jobs, CertificateDiscoveryDbContext db, ApplicationSettingsService settings) : Controller
{
    public async Task<IActionResult> Index(AssetEnvironment? environment, AssetProtocol? protocol, AssetType? assetType, string? owner, bool? isEnabled, int? expiresWithinDays, CancellationToken cancellationToken)
        => View(await assets.ListAsync(new AssetFilter(environment, protocol, assetType, owner, isEnabled, expiresWithinDays), cancellationToken));

    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Create(CancellationToken cancellationToken)
    {
        var appSettings = await settings.GetAsync(cancellationToken);
        return View(new AssetCreateRequest("", "", 443, AssetProtocol.HTTPS, null, null, null, AssetEnvironment.Production, AssetType.WebApplication, null, true, appSettings.DefaultScanIntervalMinutes, 10, null));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Create(AssetCreateRequest request, CancellationToken cancellationToken)
    {
        var asset = await assets.CreateAsync(request, cancellationToken);
        return RedirectToAction(nameof(Details), new { id = asset.Id });
    }

    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Edit(Guid id, CancellationToken cancellationToken)
    {
        var asset = await db.Assets.FindAsync([id], cancellationToken);
        if (asset is null) return NotFound();
        return View(new AssetUpdateRequest(asset.Name, asset.Host, asset.Port, asset.Protocol, asset.Description, asset.Path, asset.SniHost, asset.Environment, asset.AssetType, asset.Owner, asset.IsEnabled, asset.ScanIntervalMinutes, asset.TimeoutSeconds, asset.Tags));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Edit(Guid id, AssetUpdateRequest request, CancellationToken cancellationToken)
    {
        await assets.UpdateAsync(id, request, cancellationToken);
        return RedirectToAction(nameof(Details), new { id });
    }

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var asset = await db.Assets
            .Include(x => x.AssetCertificates.OrderByDescending(a => a.LastSeenAtUtc)).ThenInclude(x => x.Certificate)
            .Include(x => x.ScanResults.OrderByDescending(r => r.CompletedAtUtc).Take(25))
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return asset is null ? NotFound() : View(asset);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        await assets.DeleteAsync(id, cancellationToken);
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Toggle(Guid id, CancellationToken cancellationToken)
    {
        var asset = await db.Assets.FindAsync([id], cancellationToken);
        if (asset is null) return NotFound();
        asset.IsEnabled = !asset.IsEnabled;
        asset.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Scan(Guid id, CancellationToken cancellationToken)
    {
        await jobs.CreateForAssetAsync(id, ScanTriggerType.Manual, cancellationToken);
        return RedirectToAction(nameof(Details), new { id });
    }
}
