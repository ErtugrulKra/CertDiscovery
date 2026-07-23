namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class ApplicationSettingsController(ApplicationSettingsService settings) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await settings.GetAsync(cancellationToken));

    [HttpPost]
    public async Task<IActionResult> Index(UpdateApplicationSettingsRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await settings.UpdateAsync(request, cancellationToken);
            TempData["SettingsSaved"] = "Application settings were saved.";
            return RedirectToAction(nameof(Index));
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError("", ex.Message);
            return View(new ApplicationSettingsDto(
                request.SchedulerEnabled,
                request.DefaultScanIntervalMinutes,
                request.ExpireCriticalDays,
                request.ExpireWarningDays,
                request.ExpireAttentionDays,
                request.MaxConcurrentScans));
        }
    }
}
