namespace CertificateDiscovery.Web.Controllers;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")]
public sealed class CertificateRequestsController(CertificateRequestService requests) : Controller
{
    public async Task<IActionResult> Index(CancellationToken cancellationToken) =>
        View(await requests.ListAsync(cancellationToken));

    public async Task<IActionResult> Create(string? domain, string? subjectAlternativeNames, string? vaultSecretPath, CancellationToken cancellationToken)
    {
        var normalizedDomain = string.IsNullOrWhiteSpace(domain) ? "example.com" : domain.Trim();
        var path = string.IsNullOrWhiteSpace(vaultSecretPath) ? $"secret/certificates/{normalizedDomain}" : vaultSecretPath.Trim();
        return View(new CertificateRequestCreateViewModel(new CertificateRequestCreateRequest(CertificateDiscovery.Domain.CertificateRequestType.Standard, normalizedDomain, subjectAlternativeNames, Guid.Empty, Guid.Empty, null, path, false, 5, "0 0 * * *"), await requests.GetCreateOptionsAsync(cancellationToken)));
    }

    [HttpPost]
    public async Task<IActionResult> Create([Bind(Prefix = "Request")] CertificateRequestCreateRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var id = await requests.CreateAsync(request, cancellationToken);
            return RedirectToAction(nameof(Details), new { id });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(new CertificateRequestCreateViewModel(request, await requests.GetCreateOptionsAsync(cancellationToken)));
        }
    }

    public async Task<IActionResult> Edit(Guid id, CancellationToken cancellationToken)
    {
        var request = await requests.GetEditAsync(id, cancellationToken);
        return request is null ? NotFound() : View(new CertificateRequestCreateViewModel(request, await requests.GetCreateOptionsAsync(cancellationToken)));
    }

    [HttpPost]
    public async Task<IActionResult> Edit(Guid id, [Bind(Prefix = "Request")] CertificateRequestCreateRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var updated = await requests.UpdateAsync(id, request, cancellationToken);
            if (!updated) return NotFound();
            TempData["CertificateRequestMessage"] = "Certificate request was updated.";
            return RedirectToAction(nameof(Details), new { id });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ModelState.AddModelError("", ex.Message);
            return View(new CertificateRequestCreateViewModel(request, await requests.GetCreateOptionsAsync(cancellationToken)));
        }
    }

    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var request = await requests.GetAsync(id, cancellationToken);
        return request is null ? NotFound() : View(request);
    }

    [HttpPost]
    public async Task<IActionResult> StartChallenge(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await requests.StartManualDnsChallengeAsync(id, cancellationToken);
            TempData["CertificateRequestMessage"] = "DNS-01 challenge was created. Add the TXT record, wait for DNS propagation, then validate and issue.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> ValidateIssueAndStore(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await requests.ValidateIssueAndStoreAsync(id, cancellationToken);
            TempData["CertificateRequestMessage"] = "Certificate was issued and stored in Vault.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> PublishDns(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await requests.PublishDnsChallengeAsync(id, cancellationToken);
            TempData["CertificateRequestMessage"] = "DNS TXT records were published to the selected DNS provider.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> CleanupDns(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await requests.CleanupDnsChallengeAsync(id, cancellationToken);
            TempData["CertificateRequestMessage"] = "DNS TXT records were cleaned up.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> RunScheduleCheck(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await requests.RunScheduledCheckAsync(id, cancellationToken);
            TempData["CertificateRequestMessage"] = "Scheduled renewal check was executed.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var deleted = await requests.DeleteAsync(id, cancellationToken);
            if (!deleted) return NotFound();
            TempData["CertificateRequestMessage"] = "Certificate request was deleted. Stored certificates and Vault secrets were not changed.";
        }
        catch (Exception ex)
        {
            TempData["CertificateRequestError"] = ex.Message;
        }

        return RedirectToAction(nameof(Index));
    }
}
