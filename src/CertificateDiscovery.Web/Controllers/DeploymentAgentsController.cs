using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertificateDiscovery.Web.Controllers;

[Authorize(Roles = "Admin")]
public sealed class DeploymentAgentsController(DeploymentAgentService service) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        ViewBag.Agents = await service.ListAsync(cancellationToken);
        return View(await service.ListExchangesAsync(cancellationToken));
    }

    [HttpPost]
    public async Task<IActionResult> Approve(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await service.ApproveExchangeAsync(id, User.Identity?.Name ?? "admin", cancellationToken);
            TempData["AgentMessage"] = "Agent registration approved.";
        }
        catch (Exception exception)
        {
            TempData["AgentError"] = exception.Message;
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Reject(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await service.RejectExchangeAsync(id, User.Identity?.Name ?? "admin", cancellationToken);
            TempData["AgentMessage"] = "Agent registration rejected.";
        }
        catch (Exception exception)
        {
            TempData["AgentError"] = exception.Message;
        }
        return RedirectToAction(nameof(Index));
    }
}
