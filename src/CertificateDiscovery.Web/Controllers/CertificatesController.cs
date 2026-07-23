namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public sealed class CertificatesController(CertificateService certificates) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await certificates.ListAsync(cancellationToken));

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var certificate = await certificates.GetAsync(id, cancellationToken);
        return certificate is null ? NotFound() : View(certificate);
    }
}
