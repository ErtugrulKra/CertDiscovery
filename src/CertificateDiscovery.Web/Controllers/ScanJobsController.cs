namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
public sealed class ScanJobsController(ScanJobService jobs, CertificateDiscoveryDbContext db) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await jobs.ListAsync(cancellationToken));

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var job = await db.ScanJobs.Include(x => x.Results).ThenInclude(x => x.Asset).FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return job is null ? NotFound() : View(job);
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<IActionResult> Requeue(Guid id, CancellationToken cancellationToken)
    {
        var retryJob = await jobs.RequeueAsync(id, "ui", cancellationToken);
        return retryJob is null ? NotFound() : RedirectToAction(nameof(Index));
    }
}
