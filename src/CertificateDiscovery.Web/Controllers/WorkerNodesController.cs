namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class WorkerNodesController(WorkerService workers) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await workers.ListAsync(cancellationToken));

    public IActionResult Create() => View(new WorkerNodeCreateViewModel());

    [HttpPost]
    public async Task<IActionResult> Create(WorkerNodeCreateViewModel model, CancellationToken cancellationToken)
    {
        try
        {
            await workers.CreateAsync(model.WorkerName, model.Description, model.IsEnabled, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(model);
        }
    }

    public async Task<IActionResult> Edit(Guid id, CancellationToken cancellationToken)
    {
        var worker = await workers.GetAsync(id, cancellationToken);
        if (worker is null) return NotFound();

        return View(new WorkerNodeEditViewModel
        {
            Id = worker.Id,
            WorkerName = worker.WorkerName,
            Description = worker.Description,
            IsEnabled = worker.IsEnabled
        });
    }

    [HttpPost]
    public async Task<IActionResult> Edit(Guid id, WorkerNodeEditViewModel model, CancellationToken cancellationToken)
    {
        var updated = await workers.UpdateAsync(id, model.Description, model.IsEnabled, cancellationToken);
        if (!updated) return NotFound();
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Toggle(Guid id, CancellationToken cancellationToken)
    {
        var updated = await workers.ToggleAsync(id, cancellationToken);
        return updated ? RedirectToAction(nameof(Index)) : NotFound();
    }

    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        var deleted = await workers.DeleteAsync(id, cancellationToken);
        return deleted ? RedirectToAction(nameof(Index)) : NotFound();
    }
}
