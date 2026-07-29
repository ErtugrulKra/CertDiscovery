namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class IntegrationsController(
    IntegrationService integrations,
    KubernetesDiscoveryService kubernetesDiscovery) : Controller
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

    public IActionResult CreateKubernetes() =>
        View(new KubernetesClusterUpsertRequest(
            "", "https://kubernetes.default.svc", null, "default", null, true));

    [HttpPost]
    public async Task<IActionResult> CreateKubernetes(
        KubernetesClusterUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await kubernetesDiscovery.CreateAsync(request, cancellationToken);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    public async Task<IActionResult> EditKubernetes(Guid id, CancellationToken cancellationToken)
    {
        var cluster = await kubernetesDiscovery.GetAsync(id, cancellationToken);
        if (cluster is null) return NotFound();
        return View(new KubernetesClusterUpsertRequest(
            cluster.Name, cluster.ApiServer.ToString(), cluster.Description,
            cluster.Namespaces, null, cluster.IsEnabled));
    }

    [HttpPost]
    public async Task<IActionResult> EditKubernetes(
        Guid id, KubernetesClusterUpsertRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return await kubernetesDiscovery.UpdateAsync(id, request, cancellationToken)
                ? RedirectToAction(nameof(Index))
                : NotFound();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(request);
        }
    }

    [HttpPost]
    public async Task<IActionResult> DeleteKubernetes(Guid id, CancellationToken cancellationToken) =>
        await kubernetesDiscovery.DeleteAsync(id, cancellationToken)
            ? RedirectToAction(nameof(Index))
            : NotFound();

    [HttpPost]
    public async Task<IActionResult> DiscoverKubernetes(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var count = await kubernetesDiscovery.DiscoverAsync(id, cancellationToken);
            if (count is null) return NotFound();
            TempData["IntegrationMessage"] = $"Discovered {count} Kubernetes TLS Secret certificate(s).";
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
        return View(new AcmeProviderUpsertRequest(
            provider.Name,
            provider.ProviderType,
            provider.DirectoryUrl.ToString(),
            provider.AccountEmail,
            null,
            null,
            provider.IsStaging,
            provider.IsEnabled,
            provider.Notes,
            provider.Organization,
            provider.Department,
            provider.CertificateProfile,
            provider.ProductType,
            provider.AllowedDomainPattern));
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

    [HttpPost]
    public async Task<IActionResult> TestAcmeDirectory(Guid id, CancellationToken cancellationToken) =>
        await RunAcmeActionAsync(id, "ACME directory connection succeeded.", () => integrations.TestAcmeDirectoryAsync(id, cancellationToken));

    [HttpPost]
    public async Task<IActionResult> RegisterAcmeAccount(Guid id, CancellationToken cancellationToken) =>
        await RunAcmeActionAsync(id, "ACME account is registered and ready for reuse.", async () =>
        {
            _ = await integrations.RegisterAcmeAccountAsync(id, cancellationToken);
        });

    [HttpPost]
    public async Task<IActionResult> TestAcmeAccount(Guid id, CancellationToken cancellationToken) =>
        await RunAcmeActionAsync(id, "Stored ACME account test succeeded.", () => integrations.TestAcmeAccountAsync(id, cancellationToken));

    [HttpPost]
    public async Task<IActionResult> DisableAcmeAccount(Guid id, CancellationToken cancellationToken) =>
        await RunAcmeActionAsync(id, "ACME account was disabled.", () => integrations.DisableAcmeAccountAsync(id, cancellationToken));

    [HttpPost]
    public async Task<IActionResult> RotateAcmeAccountKey(Guid id, CancellationToken cancellationToken) =>
        await RunAcmeActionAsync(id, "ACME account key was rotated.", () => integrations.RotateAcmeAccountKeyAsync(id, cancellationToken));

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
        return View(new DnsProviderUpsertRequest(
            provider.Name, provider.ProviderType, provider.ZoneName, null, provider.IsEnabled, provider.Notes,
            provider.HostedZoneId, provider.AwsAuthenticationMode, null, null, null, provider.RoleArn, provider.Region,
            provider.AzureAuthenticationMode, provider.TenantId, provider.SubscriptionId, provider.ResourceGroup,
            provider.ClientId, null, provider.ManagedIdentityClientId, provider.TtlSeconds,
            provider.PropagationTimeoutSeconds, provider.PropagationPollingIntervalSeconds));
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

    [HttpPost]
    public async Task<IActionResult> TestDns(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await integrations.TestDnsAsync(id, cancellationToken);
            TempData["IntegrationMessage"] = "DNS credentials, zone access, TXT publication, propagation and cleanup succeeded.";
        }
        catch (Exception ex)
        {
            TempData["IntegrationError"] = ex.Message;
        }
        return RedirectToAction(nameof(Index));
    }

    private async Task<IActionResult> RunAcmeActionAsync(Guid id, string successMessage, Func<Task> action)
    {
        try
        {
            await action();
            TempData["IntegrationMessage"] = successMessage;
        }
        catch (Exception ex)
        {
            TempData["IntegrationError"] = ex.Message;
        }

        return RedirectToAction(nameof(Index));
    }
}
