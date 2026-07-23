namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/certificates")]
[Authorize]
public sealed class ApiCertificatesController(CertificateService certificates) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<CertificateSummaryDto>>> Get(CancellationToken cancellationToken)
        => await certificates.ListAsync(cancellationToken);

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<CertificateDetailDto>> Get(Guid id, CancellationToken cancellationToken)
    {
        var certificate = await certificates.GetAsync(id, cancellationToken);
        return certificate is null ? NotFound() : certificate;
    }

    [HttpGet("{id:guid}/assets")]
    public async Task<ActionResult<IReadOnlyList<CertificateAssetUsageDto>>> GetAssets(Guid id, CancellationToken cancellationToken)
    {
        var certificate = await certificates.GetAsync(id, cancellationToken);
        return certificate is null ? NotFound() : certificate.Assets.ToList();
    }
}
