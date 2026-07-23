using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using CertificateDiscovery.Web.Models;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;

namespace CertificateDiscovery.Web.Controllers;

[Authorize]
public class HomeController(DashboardService dashboard, ILogger<HomeController> logger) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        logger.LogDebug("Rendering dashboard.");
        return View(await dashboard.GetAsync(cancellationToken));
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
