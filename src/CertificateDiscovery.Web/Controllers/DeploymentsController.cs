using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace CertificateDiscovery.Web.Controllers;

[Authorize(Roles = "Admin")]
public sealed class DeploymentsController(DeploymentService service) : Controller
{
    public async Task<IActionResult> Index(CancellationToken token) => View(await service.GetIndexAsync(token));
    public async Task<IActionResult> Details(Guid id, CancellationToken token)
    {
        var model = await service.GetAsync(id, token);
        return model is null ? NotFound() : View(model);
    }
    public async Task<IActionResult> CreateTarget(CancellationToken token)
    {
        var model = new DeploymentTargetUpsertRequest("Fake target", DeploymentTargetType.Fake, null, "{}", null, true);
        await PopulateAgentOptionsAsync(model.DeploymentAgentId, token);
        return View(model);
    }
    [HttpPost]
    public Task<IActionResult> CreateTarget(DeploymentTargetUpsertRequest request, CancellationToken token) =>
        RunTargetFormAsync(() => service.CreateTargetAsync(request, token), nameof(CreateTarget), request, token);
    public async Task<IActionResult> EditTarget(Guid id, CancellationToken token)
    {
        var model = await service.GetTargetAsync(id, token);
        if (model is null) return NotFound();
        await PopulateAgentOptionsAsync(model.DeploymentAgentId, token);
        return View(model);
    }
    [HttpPost]
    public async Task<IActionResult> EditTarget(Guid id, DeploymentTargetUpsertRequest request, CancellationToken token) =>
        await RunTargetFormAsync(async () =>
        {
            if (!await service.UpdateTargetAsync(id, request, token)) throw new KeyNotFoundException();
        }, nameof(EditTarget), request, token);
    public IActionResult CreatePolicy() => View(new DeploymentPolicyUpsertRequest("Default", true, false, 3, 60, true, 120, null, true));
    [HttpPost]
    public async Task<IActionResult> CreatePolicy(DeploymentPolicyUpsertRequest request, CancellationToken token) =>
        await RunFormAsync(() => service.CreatePolicyAsync(request, token), nameof(CreatePolicy), request);
    public async Task<IActionResult> Create(CancellationToken token)
    {
        var model = new DeploymentCreateRequest(Guid.Empty, Guid.Empty, Guid.Empty);
        await PopulateDeploymentOptionsAsync(model, token);
        return View(model);
    }
    [HttpPost]
    public async Task<IActionResult> Create(DeploymentCreateRequest request, CancellationToken token)
    {
        try
        {
            var id = await service.CreateDeploymentAsync(request, User.Identity?.Name ?? "admin", token);
            return RedirectToAction(nameof(Details), new { id });
        }
        catch (Exception ex)
        {
            ModelState.AddModelError("", ex.Message);
            await PopulateDeploymentOptionsAsync(request, token);
            return View(request);
        }
    }
    [HttpPost] public Task<IActionResult> Approve(Guid id, CancellationToken t) => RunAction(id, () => service.ApproveAsync(id, Actor(), t));
    [HttpPost] public Task<IActionResult> Reject(Guid id, CancellationToken t) => RunAction(id, () => service.RejectAsync(id, Actor(), t));
    [HttpPost] public Task<IActionResult> Retry(Guid id, CancellationToken t) => RunAction(id, () => service.RetryAsync(id, Actor(), t));
    [HttpPost] public Task<IActionResult> Cancel(Guid id, CancellationToken t) => RunAction(id, () => service.CancelAsync(id, Actor(), t));
    [HttpPost] public Task<IActionResult> Rollback(Guid id, CancellationToken t) => RunAction(id, () => service.RollbackAsync(id, Actor(), t));
    [HttpPost] public Task<IActionResult> TestTarget(Guid id, CancellationToken t) => RunAction(null, () => service.TestTargetAsync(id, t));

    private string Actor() => User.Identity?.Name ?? "admin";
    private async Task<IActionResult> RunAction(Guid? id, Func<Task> action)
    {
        try { await action(); TempData["DeploymentMessage"] = "Action completed."; }
        catch (Exception ex) { TempData["DeploymentError"] = ex.Message; }
        return id is null ? RedirectToAction(nameof(Index)) : RedirectToAction(nameof(Details), new { id });
    }
    private async Task<IActionResult> RunFormAsync(Func<Task> action, string view, object model)
    {
        try { await action(); return RedirectToAction(nameof(Index)); }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (Exception ex) { ModelState.AddModelError("", ex.Message); return View(view, model); }
    }

    private async Task<IActionResult> RunTargetFormAsync(
        Func<Task> action,
        string view,
        DeploymentTargetUpsertRequest model,
        CancellationToken token)
    {
        try
        {
            await action();
            return RedirectToAction(nameof(Index));
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (Exception ex)
        {
            ModelState.AddModelError("", ex.Message);
            await PopulateAgentOptionsAsync(model.DeploymentAgentId, token);
            return View(view, model);
        }
    }

    private async Task PopulateAgentOptionsAsync(Guid? selectedAgentId, CancellationToken token)
    {
        var agents = await service.GetMicrosoftIisAgentOptionsAsync(selectedAgentId, token);
        ViewBag.MicrosoftIisAgents = agents.Select(agent => new SelectListItem(
            $"{agent.Name} — {agent.MachineName} — {agent.Status}",
            agent.Id.ToString(),
            agent.Id == selectedAgentId,
            !agent.IsSelectable)).ToList();
    }

    private async Task PopulateDeploymentOptionsAsync(DeploymentCreateRequest selected, CancellationToken token)
    {
        var options = await service.GetDeploymentCreateOptionsAsync(token);
        ViewBag.CertificateOptions = options.Certificates.Select(item => new SelectListItem(
            $"{item.Domain} — Vault: {item.VaultSecretPath} — SHA-256: {ShortFingerprint(item.Fingerprint)}",
            item.CertificateRequestId.ToString(),
            item.CertificateRequestId == selected.CertificateRequestId)).ToList();
        ViewBag.TargetOptions = options.Targets.Select(item => new SelectListItem(
            $"{item.Name} — {item.TargetType.GetDisplayName()}{(item.DeploymentAgentName is null ? string.Empty : $" — {item.DeploymentAgentName}")}",
            item.Id.ToString(),
            item.Id == selected.DeploymentTargetId)).ToList();
        ViewBag.PolicyOptions = options.Policies.Select(item => new SelectListItem(
            $"{item.Name} — {(item.RequireApproval ? "Approval required" : "Immediate")} — Rollback: {(item.RollbackOnFailure ? "On" : "Off")}",
            item.Id.ToString(),
            item.Id == selected.DeploymentPolicyId)).ToList();
    }

    private static string ShortFingerprint(string value) =>
        value.Length <= 16 ? value : $"{value[..8]}…{value[^8..]}";
}
