namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public sealed class VaultDiscoveryController(VaultDiscoveryService discovery) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken) =>
        View(await discovery.ListAsync(cancellationToken));

    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Create(CancellationToken cancellationToken) =>
        View(new VaultDiscoveryCreateViewModel(new VaultDiscoveryJobCreateRequest("Vault certificates", Guid.Empty, "secret", "certificates", true, false), await discovery.GetCreateOptionsAsync(cancellationToken)));

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Create([Bind(Prefix = "Request")] VaultDiscoveryJobCreateRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var job = await discovery.CreateAsync(request, User.Identity?.Name ?? "ui", cancellationToken);
            await discovery.RunAsync(job.Id, cancellationToken);
            return RedirectToAction(nameof(Details), new { id = job.Id });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(new VaultDiscoveryCreateViewModel(request, await discovery.GetCreateOptionsAsync(cancellationToken)));
        }
    }

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var job = await discovery.GetEntityAsync(id, cancellationToken);
        return job is null ? NotFound() : View(job);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Run(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await discovery.RunAsync(id, cancellationToken);
            TempData["VaultDiscoveryMessage"] = "Vault discovery scan completed.";
        }
        catch (Exception ex)
        {
            TempData["VaultDiscoveryError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }
}
