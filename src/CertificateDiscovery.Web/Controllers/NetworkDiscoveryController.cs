namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public sealed class NetworkDiscoveryController(NetworkDiscoveryService discovery) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await discovery.ListAsync(cancellationToken));

    [Authorize(Roles = "Admin")]
    public IActionResult Create() => View(new DiscoveryJobCreateViewModel());

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Create(DiscoveryJobCreateViewModel model, CancellationToken cancellationToken)
    {
        try
        {
            var job = await discovery.CreateAsync(
                new DiscoveryJobCreateRequest(model.Name, model.Cidr, model.Ports, model.TimeoutSeconds, model.MaxConcurrency),
                User.Identity?.Name ?? "ui",
                cancellationToken);
            return RedirectToAction(nameof(Details), new { id = job.Id });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(model);
        }
    }

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var job = await discovery.GetEntityAsync(id, cancellationToken);
        return job is null ? NotFound() : View(job);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Promote(Guid id, Guid jobId, CancellationToken cancellationToken)
    {
        await discovery.PromoteAsync(id, cancellationToken);
        return RedirectToAction(nameof(Details), new { id = jobId });
    }
}
