namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class IntegrationsController(IntegrationService integrations) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(await integrations.GetIndexAsync(cancellationToken));

    public IActionResult CreateVault() =>
        View(new VaultServerUpsertRequest("", "https://vault.example.com", null, "pki", null, true, false, true));

    [HttpPost]
    public async Task<IActionResult> CreateVault(VaultServerUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await integrations.CreateVaultAsync(request, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    public async Task<IActionResult> EditVault(Guid id, CancellationToken cancellationToken)
    {
        var server = await integrations.GetVaultAsync(id, cancellationToken);
        if (server is null) return NotFound();
        return View(new VaultServerUpsertRequest(server.Name, server.BaseUrl.ToString(), server.Description, server.PkiMountPath, null, server.ScanPublicEndpoint, server.ImportPkiCertificates, server.IsEnabled));
    }

    [HttpPost]
    public async Task<IActionResult> EditVault(Guid id, VaultServerUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var updated = await integrations.UpdateVaultAsync(id, request, cancellationToken);
            return updated ? RedirectToAction(nameof(Index)) : NotFound();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    [HttpPost]
    public async Task<IActionResult> DeleteVault(Guid id, CancellationToken cancellationToken)
    {
        var deleted = await integrations.DeleteVaultAsync(id, cancellationToken);
        return deleted ? RedirectToAction(nameof(Index)) : NotFound();
    }

    [HttpPost]
    public async Task<IActionResult> ScanVaultPublicEndpoint(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var count = await integrations.ScanVaultPublicEndpointAsync(id, cancellationToken);
            if (count is null) return NotFound();
            TempData["IntegrationMessage"] = $"Imported {count} public Vault endpoint certificate(s).";
        }
        catch (Exception ex)
        {
            TempData["IntegrationError"] = ex.Message;
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> ImportVaultPki(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var count = await integrations.ImportVaultPkiAsync(id, cancellationToken);
            if (count is null) return NotFound();
            TempData["IntegrationMessage"] = $"Imported {count} Vault PKI certificate(s).";
        }
        catch (Exception ex)
        {
            TempData["IntegrationError"] = ex.Message;
        }
        return RedirectToAction(nameof(Index));
    }

    public IActionResult CreateAcme() =>
        View(new AcmeProviderUpsertRequest("Let's Encrypt Production", AcmeProviderType.LetsEncrypt, "https://acme-v02.api.letsencrypt.org/directory", "", null, null, false, true, null));

    [HttpPost]
    public async Task<IActionResult> CreateAcme(AcmeProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await integrations.CreateAcmeAsync(request, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    public async Task<IActionResult> EditAcme(Guid id, CancellationToken cancellationToken)
    {
        var provider = await integrations.GetAcmeAsync(id, cancellationToken);
        if (provider is null) return NotFound();
        return View(new AcmeProviderUpsertRequest(provider.Name, provider.ProviderType, provider.DirectoryUrl.ToString(), provider.AccountEmail, null, null, provider.IsStaging, provider.IsEnabled, provider.Notes));
    }

    [HttpPost]
    public async Task<IActionResult> EditAcme(Guid id, AcmeProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var updated = await integrations.UpdateAcmeAsync(id, request, cancellationToken);
            return updated ? RedirectToAction(nameof(Index)) : NotFound();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    [HttpPost]
    public async Task<IActionResult> DeleteAcme(Guid id, CancellationToken cancellationToken)
    {
        var deleted = await integrations.DeleteAcmeAsync(id, cancellationToken);
        return deleted ? RedirectToAction(nameof(Index)) : NotFound();
    }

    public IActionResult CreateDns() =>
        View(new DnsProviderUpsertRequest("Cloudflare", DnsProviderType.Cloudflare, "example.com", null, true, null));

    [HttpPost]
    public async Task<IActionResult> CreateDns(DnsProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await integrations.CreateDnsAsync(request, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    public async Task<IActionResult> EditDns(Guid id, CancellationToken cancellationToken)
    {
        var provider = await integrations.GetDnsAsync(id, cancellationToken);
        if (provider is null) return NotFound();
        return View(new DnsProviderUpsertRequest(provider.Name, provider.ProviderType, provider.ZoneName, null, provider.IsEnabled, provider.Notes));
    }

    [HttpPost]
    public async Task<IActionResult> EditDns(Guid id, DnsProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var updated = await integrations.UpdateDnsAsync(id, request, cancellationToken);
            return updated ? RedirectToAction(nameof(Index)) : NotFound();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    [HttpPost]
    public async Task<IActionResult> DeleteDns(Guid id, CancellationToken cancellationToken)
    {
        var deleted = await integrations.DeleteDnsAsync(id, cancellationToken);
        return deleted ? RedirectToAction(nameof(Index)) : NotFound();
    }
}
