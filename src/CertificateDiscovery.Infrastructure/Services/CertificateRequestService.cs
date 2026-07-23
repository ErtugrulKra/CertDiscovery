namespace CertificateDiscovery.Infrastructure.Services;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Certes;
using Certes.Acme;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class CertificateRequestService(CertificateDiscoveryDbContext db, IHttpClientFactory httpClientFactory)
{
    private static readonly TimeSpan AutomaticDnsPropagationDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan AutomaticRenewalRetryDelay = TimeSpan.FromMinutes(15);

    public async Task<List<CertificateRequestListDto>> ListAsync(CancellationToken cancellationToken) =>
        await db.AcmeCertificateRequests
            .AsNoTracking()
            .Include(x => x.AcmeProvider)
            .Include(x => x.VaultServer)
            .Include(x => x.DnsProvider)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Select(x => ToListDto(x))
            .ToListAsync(cancellationToken);

    public async Task<CertificateRequestCreateOptionsDto> GetCreateOptionsAsync(CancellationToken cancellationToken) =>
        new(
            await db.AcmeProviders.AsNoTracking().Where(x => x.IsEnabled).OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            await db.VaultServers.AsNoTracking().Where(x => x.IsEnabled).OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            await db.DnsProviders.AsNoTracking().Where(x => x.IsEnabled).OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken));

    public async Task<CertificateRequestDetailDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await db.AcmeCertificateRequests
            .AsNoTracking()
            .Include(x => x.AcmeProvider)
            .Include(x => x.VaultServer)
            .Include(x => x.DnsProvider)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return request is null ? null : ToDetailDto(request);
    }

    public async Task<CertificateRequestCreateRequest?> GetEditAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await db.AcmeCertificateRequests.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (request is null) return null;
        var requestType = request.Domain.StartsWith("*.", StringComparison.Ordinal) ? CertificateRequestType.Wildcard : CertificateRequestType.Standard;
        var domain = requestType == CertificateRequestType.Wildcard ? request.Domain.Substring(2) : request.Domain;
        return new CertificateRequestCreateRequest(
            requestType,
            domain,
            request.SubjectAlternativeNames,
            request.AcmeProviderId,
            request.VaultServerId,
            request.DnsProviderId,
            request.VaultSecretPath,
            request.ScheduleCheck,
            request.RenewalThresholdDays,
            request.RenewalCronExpression);
    }

    public async Task<Guid> CreateAsync(CertificateRequestCreateRequest input, CancellationToken cancellationToken)
    {
        ValidateCreate(input);
        var (domain, sans) = NormalizeRequestNames(input);
        await EnsureRequestDependenciesAsync(input, cancellationToken);

        var request = new AcmeCertificateRequest
        {
            Domain = domain,
            SubjectAlternativeNames = sans,
            AcmeProviderId = input.AcmeProviderId,
            VaultServerId = input.VaultServerId,
            DnsProviderId = input.DnsProviderId == Guid.Empty ? null : input.DnsProviderId,
            VaultSecretPath = NormalizeVaultPath(input.VaultSecretPath, domain),
            ChallengeType = AcmeChallengeType.ManualDns01,
            Status = CertificateRequestStatus.Draft,
            ScheduleCheck = input.ScheduleCheck,
            RenewalThresholdDays = input.ScheduleCheck ? input.ThresholdDays : 5,
            RenewalCronExpression = NormalizeCronExpression(input.CronExpression),
            NextScheduleCheckAtUtc = input.ScheduleCheck ? CronSchedule.Parse(input.CronExpression).GetNext(DateTime.UtcNow) : null
        };
        db.AcmeCertificateRequests.Add(request);
        await db.SaveChangesAsync(cancellationToken);
        return request.Id;
    }

    public async Task<bool> UpdateAsync(Guid id, CertificateRequestCreateRequest input, CancellationToken cancellationToken)
    {
        ValidateCreate(input);
        var request = await db.AcmeCertificateRequests.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (request is null) return false;
        if (request.Status == CertificateRequestStatus.Validating)
        {
            throw new InvalidOperationException("A validating certificate request cannot be edited.");
        }

        var (domain, sans) = NormalizeRequestNames(input);
        await EnsureRequestDependenciesAsync(input, cancellationToken);
        var dnsProviderId = input.DnsProviderId == Guid.Empty ? null : input.DnsProviderId;
        var vaultSecretPath = NormalizeVaultPath(input.VaultSecretPath, domain);
        var issuanceSettingsChanged =
            !string.Equals(request.Domain, domain, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(request.SubjectAlternativeNames ?? string.Empty, sans ?? string.Empty, StringComparison.OrdinalIgnoreCase) ||
            request.AcmeProviderId != input.AcmeProviderId ||
            request.VaultServerId != input.VaultServerId ||
            request.DnsProviderId != dnsProviderId ||
            !string.Equals(request.VaultSecretPath, vaultSecretPath, StringComparison.OrdinalIgnoreCase);

        if (issuanceSettingsChanged)
        {
            PrepareForScheduledRenewal(request);
            request.CertificateId = null;
        }

        request.Domain = domain;
        request.SubjectAlternativeNames = sans;
        request.AcmeProviderId = input.AcmeProviderId;
        request.VaultServerId = input.VaultServerId;
        request.DnsProviderId = dnsProviderId;
        request.VaultSecretPath = vaultSecretPath;
        request.ScheduleCheck = input.ScheduleCheck;
        request.RenewalThresholdDays = input.ScheduleCheck ? input.ThresholdDays : 5;
        request.RenewalCronExpression = NormalizeCronExpression(input.CronExpression);
        request.NextScheduleCheckAtUtc = input.ScheduleCheck ? CronSchedule.Parse(input.CronExpression).GetNext(DateTime.UtcNow) : null;
        request.UpdatedAtUtc = DateTime.UtcNow;

        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task StartManualDnsChallengeAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        if (request.Status is not (CertificateRequestStatus.Draft or CertificateRequestStatus.Failed))
        {
            throw new InvalidOperationException("Only draft or failed requests can start a new ACME challenge.");
        }

        var accountKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var acme = new AcmeContext(request.AcmeProvider!.DirectoryUrl, accountKey);
        await acme.NewAccount([ToAcmeContact(request.AcmeProvider.AccountEmail)], true);

        var domains = GetDomains(request).ToList();
        var order = await acme.NewOrder(domains);
        var authorizations = (await order.Authorizations()).ToList();
        var instructions = new List<(string Name, string Value)>();
        foreach (var authorization in authorizations)
        {
            var resource = await GetResourceAsync(authorization);
            var identifier = NormalizeDomain(GetIdentifierValue(resource));
            var challenge = await authorization.Dns();
            instructions.Add((ToDnsTxtName(identifier), acme.AccountKey.DnsTxt(challenge.Token)));
        }

        request.AcmeAccountKeyPem = accountKey.ToPem();
        request.AcmeOrderLocation = GetLocation(order)?.ToString();
        request.DnsTxtName = string.Join('\n', instructions.Select(x => x.Name));
        request.DnsTxtValue = string.Join('\n', instructions.Select(x => x.Value));
        request.Status = CertificateRequestStatus.PendingDns;
        request.ErrorMessage = null;
        request.ChallengeCreatedAtUtc = DateTime.UtcNow;
        request.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ValidateIssueAndStoreAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        if (request.Status is not (CertificateRequestStatus.PendingDns or CertificateRequestStatus.ReadyToValidate or CertificateRequestStatus.Failed))
        {
            throw new InvalidOperationException("Only pending DNS requests can be validated.");
        }

        if (string.IsNullOrWhiteSpace(request.AcmeAccountKeyPem) || string.IsNullOrWhiteSpace(request.AcmeOrderLocation))
        {
            throw new InvalidOperationException("ACME challenge has not been started yet.");
        }

        try
        {
            request.Status = CertificateRequestStatus.Validating;
            request.ErrorMessage = null;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            var accountKey = KeyFactory.FromPem(request.AcmeAccountKeyPem);
            var acme = new AcmeContext(request.AcmeProvider!.DirectoryUrl, accountKey);
            var order = acme.Order(new Uri(request.AcmeOrderLocation));
            var authorizations = (await order.Authorizations()).ToList();
            foreach (var authorization in authorizations)
            {
                var resource = await GetResourceAsync(authorization);
                if (GetStatus(resource) == "Valid") continue;
                var challenge = await authorization.Dns();
                await challenge.Validate();
            }

            await WaitUntilOrderReadyAsync(order, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(15), cancellationToken);

            var certificateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var chain = await order.Generate(new CsrInfo
            {
                CommonName = request.Domain,
                Organization = "Certificate Discovery Platform"
            }, certificateKey, retryCount: 10);

            var certificatePem = chain.Certificate.ToPem();
            var issuerPem = string.Join('\n', chain.Issuers.Select(x => x.ToPem()));
            var fullChainPem = certificatePem + issuerPem;
            var privateKeyPem = certificateKey.ToPem();

            request.CertificatePrivateKeyPem = privateKeyPem;
            request.CertificatePem = certificatePem;
            request.FullChainPem = fullChainPem;
            request.Status = CertificateRequestStatus.Issued;
            request.IssuedAtUtc = DateTime.UtcNow;
            request.UpdatedAtUtc = DateTime.UtcNow;

            var certificate = await UpsertCertificateAsync(request, certificatePem, fullChainPem, cancellationToken);
            request.CertificateId = certificate.Id;
            await StoreInVaultAsync(request, cancellationToken);
            request.Status = CertificateRequestStatus.StoredInVault;
            request.StoredAtUtc = DateTime.UtcNow;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await CleanupDnsChallengeAfterIssueAsync(request, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (TimeoutException ex)
        {
            request.Status = CertificateRequestStatus.ReadyToValidate;
            request.ErrorMessage = ex.Message;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            throw;
        }
        catch (Exception ex)
        {
            request.Status = CertificateRequestStatus.Failed;
            request.ErrorMessage = ex.Message;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            throw;
        }
    }

    public async Task PublishDnsChallengeAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        if (request.DnsProvider is null) throw new InvalidOperationException("DNS provider is not selected for this certificate request.");
        if (string.IsNullOrWhiteSpace(request.DnsTxtName) || string.IsNullOrWhiteSpace(request.DnsTxtValue)) throw new InvalidOperationException("DNS challenge has not been started yet.");

        try
        {
            var records = GetDnsChallengeRecords(request).ToList();
            if (records.Count == 0) throw new InvalidOperationException("No DNS TXT records are available to publish.");

            if (request.DnsProvider.ProviderType != DnsProviderType.Cloudflare)
            {
                throw new InvalidOperationException($"DNS provider type {request.DnsProvider.ProviderType} is not supported yet.");
            }

            await PublishCloudflareRecordsAsync(request.DnsProvider, records, cancellationToken);
            request.DnsPublishedAtUtc = DateTime.UtcNow;
            request.DnsPublishStatus = $"Published {records.Count} TXT record(s)";
            request.DnsPublishError = null;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            request.DnsPublishStatus = "Failed";
            request.DnsPublishError = ex.Message;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            throw;
        }
    }

    public async Task CleanupDnsChallengeAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        await CleanupDnsChallengeAfterIssueAsync(request, cancellationToken);
        request.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        if (!string.IsNullOrWhiteSpace(request.DnsPublishError))
        {
            throw new InvalidOperationException(request.DnsPublishError);
        }
    }

    private async Task PublishCloudflareRecordsAsync(DnsProvider provider, IReadOnlyList<(string Name, string Value)> records, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider.ApiToken)) throw new InvalidOperationException("Cloudflare API token is required.");
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = new Uri("https://api.cloudflare.com/client/v4/");
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", provider.ApiToken);

        var zoneId = await GetCloudflareZoneIdAsync(client, provider.ZoneName, cancellationToken);
        foreach (var record in records)
        {
            var existingId = await GetCloudflareTxtRecordIdAsync(client, zoneId, record.Name, record.Value, cancellationToken);
            var payload = new
            {
                type = "TXT",
                name = record.Name,
                content = record.Value,
                ttl = 120
            };

            using var response = existingId is null
                ? await client.PostAsJsonAsync($"zones/{zoneId}/dns_records", payload, cancellationToken)
                : await client.PutAsJsonAsync($"zones/{zoneId}/dns_records/{existingId}", payload, cancellationToken);
            await EnsureCloudflareSuccessAsync(response, cancellationToken);
        }
    }

    private async Task CleanupDnsChallengeAfterIssueAsync(AcmeCertificateRequest request, CancellationToken cancellationToken)
    {
        if (request.DnsProvider is null || string.IsNullOrWhiteSpace(request.DnsTxtName) || string.IsNullOrWhiteSpace(request.DnsTxtValue))
        {
            request.DnsPublishError = request.DnsProvider is null
                ? "DNS cleanup skipped: no DNS provider is selected for this request."
                : "DNS cleanup skipped: no DNS TXT challenge records are stored on this request.";
            return;
        }

        try
        {
            var records = GetDnsChallengeRecords(request).ToList();
            if (records.Count == 0)
            {
                request.DnsPublishError = "DNS cleanup skipped: no DNS TXT challenge records are stored on this request.";
                return;
            }
            if (request.DnsProvider.ProviderType != DnsProviderType.Cloudflare)
            {
                request.DnsPublishError = $"DNS cleanup is not supported for provider type {request.DnsProvider.ProviderType}.";
                return;
            }

            var deleted = await DeleteCloudflareRecordsAsync(request.DnsProvider, records, cancellationToken);
            var prefix = string.IsNullOrWhiteSpace(request.DnsPublishStatus) ? "DNS challenge" : request.DnsPublishStatus;
            request.DnsPublishStatus = $"{prefix}; cleaned {deleted} TXT record(s)";
            request.DnsPublishError = deleted == 0 ? "DNS cleanup found no matching TXT records at the provider." : null;
        }
        catch (Exception ex)
        {
            request.DnsPublishError = $"DNS cleanup failed: {ex.Message}";
        }
    }

    private async Task CleanupDnsChallengeForRequestAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        await CleanupDnsChallengeAfterIssueAsync(request, cancellationToken);
        request.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<int> DeleteCloudflareRecordsAsync(DnsProvider provider, IReadOnlyList<(string Name, string Value)> records, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider.ApiToken)) throw new InvalidOperationException("Cloudflare API token is required.");
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = new Uri("https://api.cloudflare.com/client/v4/");
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", provider.ApiToken);

        var deleted = 0;
        var zoneId = await GetCloudflareZoneIdAsync(client, provider.ZoneName, cancellationToken);
        foreach (var record in records)
        {
            var existingIds = await GetCloudflareTxtRecordIdsAsync(client, zoneId, record.Name, record.Value, cancellationToken);
            foreach (var existingId in existingIds)
            {
                using var response = await client.DeleteAsync($"zones/{zoneId}/dns_records/{existingId}", cancellationToken);
                await EnsureCloudflareSuccessAsync(response, cancellationToken);
                deleted++;
            }
        }

        return deleted;
    }

    private static async Task<string> GetCloudflareZoneIdAsync(HttpClient client, string zoneName, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"zones?name={Uri.EscapeDataString(zoneName)}&status=active", cancellationToken);
        using var document = await ReadCloudflareResponseAsync(response, cancellationToken);
        var result = document.RootElement.GetProperty("result");
        if (result.GetArrayLength() == 0) throw new InvalidOperationException($"Cloudflare zone '{zoneName}' was not found or is not active.");
        return result[0].GetProperty("id").GetString()!;
    }

    private static async Task<string?> GetCloudflareTxtRecordIdAsync(HttpClient client, string zoneId, string name, string value, CancellationToken cancellationToken)
    {
        var ids = await GetCloudflareTxtRecordIdsAsync(client, zoneId, name, value, cancellationToken);
        return ids.FirstOrDefault();
    }

    private static async Task<List<string>> GetCloudflareTxtRecordIdsAsync(HttpClient client, string zoneId, string name, string value, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"zones/{zoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(name)}", cancellationToken);
        using var document = await ReadCloudflareResponseAsync(response, cancellationToken);
        var ids = new List<string>();
        foreach (var item in document.RootElement.GetProperty("result").EnumerateArray())
        {
            if (string.Equals(item.GetProperty("content").GetString(), value, StringComparison.Ordinal))
            {
                var id = item.GetProperty("id").GetString();
                if (!string.IsNullOrWhiteSpace(id)) ids.Add(id);
            }
        }

        return ids;
    }

    private static async Task<JsonDocument> ReadCloudflareResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = JsonDocument.Parse(content);
        if (!response.IsSuccessStatusCode || !document.RootElement.TryGetProperty("success", out var success) || !success.GetBoolean())
        {
            var message = TryGetCloudflareError(document) ?? response.ReasonPhrase ?? "Cloudflare API request failed.";
            document.Dispose();
            throw new InvalidOperationException(message);
        }

        return document;
    }

    private static async Task EnsureCloudflareSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var document = await ReadCloudflareResponseAsync(response, cancellationToken);
    }

    private static string? TryGetCloudflareError(JsonDocument document)
    {
        if (!document.RootElement.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array || errors.GetArrayLength() == 0) return null;
        var first = errors[0];
        return first.TryGetProperty("message", out var message) ? message.GetString() : first.ToString();
    }

    private static bool IsAcmeDnsValidationFailure(Exception ex)
    {
        var message = ex.Message;
        return message.Contains("ACME order became invalid", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("ACME authorization failed", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("DNS propagation", StringComparison.OrdinalIgnoreCase) ||
               (ex.InnerException is not null && IsAcmeDnsValidationFailure(ex.InnerException));
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await db.AcmeCertificateRequests.FindAsync([id], cancellationToken);
        if (request is null) return false;
        if (request.Status == CertificateRequestStatus.Validating)
        {
            throw new InvalidOperationException("A validating certificate request cannot be deleted.");
        }

        db.AcmeCertificateRequests.Remove(request);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<int> RunDueScheduledChecksAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var ids = await db.AcmeCertificateRequests
            .Where(x => x.ScheduleCheck && x.NextScheduleCheckAtUtc != null && x.NextScheduleCheckAtUtc <= now)
            .OrderBy(x => x.NextScheduleCheckAtUtc)
            .Select(x => x.Id)
            .Take(10)
            .ToListAsync(cancellationToken);

        foreach (var id in ids)
        {
            await RunScheduledCheckAsync(id, cancellationToken);
        }

        return ids.Count;
    }

    public async Task RunScheduledCheckAsync(Guid id, CancellationToken cancellationToken)
    {
        var request = await db.AcmeCertificateRequests
            .Include(x => x.Certificate)
            .Include(x => x.AcmeProvider)
            .Include(x => x.VaultServer)
            .Include(x => x.DnsProvider)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("Certificate request was not found.");

        if (!request.ScheduleCheck)
        {
            throw new InvalidOperationException("Schedule check is not enabled for this certificate request.");
        }

        var now = DateTime.UtcNow;
        var nextCheck = CronSchedule.Parse(request.RenewalCronExpression).GetNext(now);
        try
        {
            if (request.Status == CertificateRequestStatus.Validating)
            {
                UpdateScheduleResult(request, now, DateTime.UtcNow.Add(AutomaticRenewalRetryDelay), "Waiting", "This scheduled request is already validating.");
                await db.SaveChangesAsync(cancellationToken);
                return;
            }

            if (request.Status is CertificateRequestStatus.PendingDns or CertificateRequestStatus.ReadyToValidate)
            {
                await ContinueScheduledDnsRequestAsync(id, now, nextCheck, cancellationToken);
                return;
            }

            var certificate = request.Certificate ?? await FindCurrentCertificateAsync(request, cancellationToken);
            if (certificate is not null && certificate.NotAfterUtc > now.AddDays(request.RenewalThresholdDays))
            {
                var days = Math.Floor((certificate.NotAfterUtc - now).TotalDays);
                UpdateScheduleResult(request, now, nextCheck, "Valid", $"Certificate is valid for {days} more day(s); renewal threshold is {request.RenewalThresholdDays} day(s).");
                await db.SaveChangesAsync(cancellationToken);
                return;
            }

            PrepareForScheduledRenewal(request);
            UpdateScheduleResult(request, now, nextCheck, "StartingRenewal", "Renewal threshold was reached; starting DNS-01 challenge on this request.");
            await db.SaveChangesAsync(cancellationToken);

            await StartManualDnsChallengeAsync(id, cancellationToken);
            if (request.DnsProviderId is null)
            {
                request = await LoadMutableAsync(id, cancellationToken);
                UpdateScheduleResult(request, now, nextCheck, "WaitingForManualDns", "Scheduled request is waiting for manual TXT publication.");
                await db.SaveChangesAsync(cancellationToken);
                return;
            }

            await ContinueScheduledDnsRequestAsync(id, now, nextCheck, cancellationToken);
        }
        catch (Exception ex)
        {
            request = await LoadMutableAsync(id, cancellationToken);
            request.LastScheduleCheckAtUtc = now;
            request.NextScheduleCheckAtUtc = IsAcmeDnsValidationFailure(ex) ? DateTime.UtcNow.Add(AutomaticRenewalRetryDelay) : nextCheck;
            request.LastScheduleCheckStatus = "Failed";
            request.LastScheduleCheckMessage = ex.Message;
            request.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            throw;
        }
    }

    private async Task ContinueScheduledDnsRequestAsync(Guid id, DateTime checkedAtUtc, DateTime nextCheck, CancellationToken cancellationToken)
    {
        var request = await LoadMutableAsync(id, cancellationToken);
        if (request.DnsProviderId is null)
        {
            UpdateScheduleResult(request, checkedAtUtc, nextCheck, "WaitingForManualDns", "Scheduled request is waiting for manual TXT publication.");
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        if (request.Status == CertificateRequestStatus.PendingDns && request.DnsPublishedAtUtc is null)
        {
            await PublishDnsChallengeAsync(id, cancellationToken);
        }

        request = await LoadMutableAsync(id, cancellationToken);
        UpdateScheduleResult(request, checkedAtUtc, DateTime.UtcNow.Add(AutomaticDnsPropagationDelay), "WaitingForDnsPropagation", $"TXT records were published and ACME validation will start after {AutomaticDnsPropagationDelay.TotalMinutes:0} minute(s).");
        await db.SaveChangesAsync(cancellationToken);

        await Task.Delay(AutomaticDnsPropagationDelay, cancellationToken);
        try
        {
            await ValidateIssueAndStoreAsync(id, cancellationToken);
        }
        catch (Exception ex) when (IsAcmeDnsValidationFailure(ex))
        {
            await CleanupDnsChallengeForRequestAsync(id, cancellationToken);
            throw new InvalidOperationException($"{ex.Message} Published TXT records were cleaned up and the scheduled request will retry in {AutomaticRenewalRetryDelay.TotalMinutes:0} minute(s).", ex);
        }

        request = await LoadMutableAsync(id, cancellationToken);
        UpdateScheduleResult(request, checkedAtUtc, nextCheck, request.Status == CertificateRequestStatus.StoredInVault ? "Renewed" : request.Status.ToString(), $"Scheduled request completed with status {request.Status}.");
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<AcmeCertificateRequest> LoadMutableAsync(Guid id, CancellationToken cancellationToken) =>
        await db.AcmeCertificateRequests
            .Include(x => x.AcmeProvider)
            .Include(x => x.VaultServer)
            .Include(x => x.DnsProvider)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
        ?? throw new InvalidOperationException("Certificate request was not found.");

    private async Task<Certificate?> FindCurrentCertificateAsync(AcmeCertificateRequest request, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(request.VaultSecretPath))
        {
            var byPath = await db.Certificates
                .OrderByDescending(x => x.LastSeenAtUtc)
                .FirstOrDefaultAsync(x => x.ExternalReference == request.VaultSecretPath, cancellationToken);
            if (byPath is not null) return byPath;
        }

        var domains = GetDomains(request).ToList();
        return await db.Certificates
            .Where(x => x.CommonName == request.Domain || x.SubjectAlternativeNames.Any(san => domains.Contains(san.Name)))
            .OrderByDescending(x => x.NotAfterUtc)
            .FirstOrDefaultAsync(cancellationToken);
    }

    private static void UpdateScheduleResult(AcmeCertificateRequest request, DateTime checkedAtUtc, DateTime nextCheckAtUtc, string status, string message)
    {
        request.LastScheduleCheckAtUtc = checkedAtUtc;
        request.NextScheduleCheckAtUtc = nextCheckAtUtc;
        request.LastScheduleCheckStatus = status;
        request.LastScheduleCheckMessage = message;
        request.UpdatedAtUtc = DateTime.UtcNow;
    }

    private static void PrepareForScheduledRenewal(AcmeCertificateRequest request)
    {
        request.Status = CertificateRequestStatus.Draft;
        request.DnsTxtName = null;
        request.DnsTxtValue = null;
        request.AcmeAccountKeyPem = null;
        request.AcmeOrderLocation = null;
        request.CertificatePrivateKeyPem = null;
        request.CertificatePem = null;
        request.FullChainPem = null;
        request.ErrorMessage = null;
        request.DnsPublishedAtUtc = null;
        request.DnsPublishStatus = null;
        request.DnsPublishError = null;
        request.ChallengeCreatedAtUtc = null;
        request.IssuedAtUtc = null;
        request.StoredAtUtc = null;
        request.RenewedFromRequestId = null;
        request.LastRenewalRequestId = null;
        request.UpdatedAtUtc = DateTime.UtcNow;
    }

    private async Task StoreInVaultAsync(AcmeCertificateRequest request, CancellationToken cancellationToken)
    {
        if (request.VaultServer is null) throw new InvalidOperationException("Vault server was not loaded.");
        if (string.IsNullOrWhiteSpace(request.VaultServer.Token)) throw new InvalidOperationException("Vault token is required to store certificates.");
        if (string.IsNullOrWhiteSpace(request.CertificatePem) || string.IsNullOrWhiteSpace(request.FullChainPem) || string.IsNullOrWhiteSpace(request.CertificatePrivateKeyPem))
        {
            throw new InvalidOperationException("Issued certificate material is incomplete.");
        }

        var (mount, path) = SplitVaultKvPath(request.VaultSecretPath);
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = request.VaultServer.BaseUrl;
        client.DefaultRequestHeaders.Add("X-Vault-Token", request.VaultServer.Token);

        var payload = new
        {
            data = new
            {
                domain = request.Domain,
                sans = GetDomains(request),
                certificate_pem = request.CertificatePem,
                private_key_pem = request.CertificatePrivateKeyPem,
                fullchain_pem = request.FullChainPem,
                acme_provider = request.AcmeProvider?.Name,
                issued_at_utc = request.IssuedAtUtc,
                certificate_request_id = request.Id
            }
        };

        using var response = await client.PostAsJsonAsync($"/v1/{mount}/data/{path}", payload, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private async Task<Certificate> UpsertCertificateAsync(AcmeCertificateRequest request, string certificatePem, string fullChainPem, CancellationToken cancellationToken)
    {
        var leaf = X509Certificate2.CreateFromPem(certificatePem);
        var chain = ParsePemCertificates(fullChainPem);
        if (chain.Count == 0) chain.Add(leaf);
        var fingerprint = Fingerprint(leaf);
        var certificate = await db.Certificates.FirstOrDefaultAsync(x => x.FingerprintSha256 == fingerprint, cancellationToken);
        if (certificate is null)
        {
            certificate = new Certificate { FingerprintSha256 = fingerprint };
            db.Certificates.Add(certificate);
        }

        certificate.SerialNumber = leaf.SerialNumber;
        certificate.Subject = leaf.Subject;
        certificate.CommonName = leaf.GetNameInfo(X509NameType.SimpleName, false);
        certificate.Issuer = leaf.Issuer;
        certificate.NotBeforeUtc = leaf.NotBefore.ToUniversalTime();
        certificate.NotAfterUtc = leaf.NotAfter.ToUniversalTime();
        certificate.SignatureAlgorithm = leaf.SignatureAlgorithm.FriendlyName;
        certificate.PublicKeyAlgorithm = leaf.PublicKey.Oid.FriendlyName;
        certificate.PublicKeySize = GetPublicKeySize(leaf);
        certificate.Version = leaf.Version;
        certificate.IsSelfSigned = leaf.Subject == leaf.Issuer;
        certificate.Source = CertificateSource.Acme;
        certificate.SourceName = request.AcmeProvider?.Name;
        certificate.ExternalReference = request.VaultSecretPath;
        certificate.PemEncodedCertificate = certificatePem;
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var name in GetDomains(request).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName { CertificateId = certificate.Id, Name = name, Type = CertificateSanType.DNS });
        }

        await db.CertificateChainEntries.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var entry in chain.Select((cert, index) => new { cert, index }))
        {
            db.CertificateChainEntries.Add(new CertificateChainEntry
            {
                CertificateId = certificate.Id,
                Position = entry.index,
                FingerprintSha256 = Fingerprint(entry.cert),
                SerialNumber = entry.cert.SerialNumber,
                Subject = entry.cert.Subject,
                CommonName = entry.cert.GetNameInfo(X509NameType.SimpleName, false),
                Issuer = entry.cert.Issuer,
                NotBeforeUtc = entry.cert.NotBefore.ToUniversalTime(),
                NotAfterUtc = entry.cert.NotAfter.ToUniversalTime(),
                SignatureAlgorithm = entry.cert.SignatureAlgorithm.FriendlyName,
                PublicKeyAlgorithm = entry.cert.PublicKey.Oid.FriendlyName,
                PublicKeySize = GetPublicKeySize(entry.cert),
                Version = entry.cert.Version,
                IsSelfSigned = entry.cert.Subject == entry.cert.Issuer,
                PemEncodedCertificate = PemEncode(entry.cert),
                LastSeenAtUtc = DateTime.UtcNow
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        return certificate;
    }

    private static IReadOnlyList<string> GetDomains(AcmeCertificateRequest request)
    {
        var values = new List<string> { request.Domain };
        if (!string.IsNullOrWhiteSpace(request.SubjectAlternativeNames))
        {
            values.AddRange(request.SubjectAlternativeNames.Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(NormalizeDomain));
        }

        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IReadOnlyList<(string Name, string Value)> GetDnsChallengeRecords(AcmeCertificateRequest request)
    {
        var names = (request.DnsTxtName ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var values = (request.DnsTxtValue ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return names.Select((name, index) => (Name: name, Value: index < values.Length ? values[index] : string.Empty))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name) && !string.IsNullOrWhiteSpace(x.Value))
            .ToList();
    }

    private static List<X509Certificate2> ParsePemCertificates(string pem)
    {
        var certificates = new List<X509Certificate2>();
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var index = 0;
        while (true)
        {
            var start = pem.IndexOf(begin, index, StringComparison.Ordinal);
            if (start < 0) break;
            var finish = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (finish < 0) break;
            finish += end.Length;
            certificates.Add(X509Certificate2.CreateFromPem(pem.Substring(start, finish - start)));
            index = finish;
        }

        return certificates;
    }

    private static Uri? GetLocation(object order)
    {
        var property = order.GetType().GetProperty("Location");
        return property?.GetValue(order) as Uri;
    }

    private static async Task WaitUntilOrderReadyAsync(IOrderContext order, TimeSpan maxWait, TimeSpan interval, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow.Add(maxWait);
        while (DateTime.UtcNow <= deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var orderResource = await GetResourceAsync(order);
            var orderStatus = GetStatus(orderResource);
            if (orderStatus is "Ready" or "Valid") return;
            if (orderStatus == "Invalid")
            {
                throw new InvalidOperationException("ACME order became invalid.");
            }

            var authorizations = (await order.Authorizations()).ToList();
            var authorizationResources = new List<object>();
            foreach (var authorization in authorizations)
            {
                authorizationResources.Add(await GetResourceAsync(authorization));
            }

            if (authorizationResources.Any(x => GetStatus(x) is "Invalid" or "Expired" or "Deactivated" or "Revoked"))
            {
                var failed = authorizationResources.First(x => GetStatus(x) is "Invalid" or "Expired" or "Deactivated" or "Revoked");
                throw new InvalidOperationException($"ACME authorization failed for {GetIdentifierValue(failed)} with status {GetStatus(failed)}.");
            }

            await Task.Delay(interval, cancellationToken);
        }

        throw new TimeoutException("ACME validation is still pending. DNS propagation may not be complete yet; keep the TXT record in place and try validation again in a few minutes.");
    }

    private static async Task<object> GetResourceAsync(object context)
    {
        var method = context.GetType().GetMethod("Resource", BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException("ACME resource status cannot be read.");
        var task = (Task)method.Invoke(context, null)!;
        await task.ConfigureAwait(false);
        return task.GetType().GetProperty("Result")!.GetValue(task)!;
    }

    private static string? GetStatus(object resource) =>
        resource.GetType().GetProperty("Status")?.GetValue(resource)?.ToString();

    private static string GetIdentifierValue(object authorizationResource)
    {
        var identifier = authorizationResource.GetType().GetProperty("Identifier")?.GetValue(authorizationResource);
        return identifier?.GetType().GetProperty("Value")?.GetValue(identifier)?.ToString()
            ?? throw new InvalidOperationException("ACME authorization identifier cannot be read.");
    }

    private static (string Mount, string Path) SplitVaultKvPath(string value)
    {
        var normalized = value.Trim().Trim('/');
        var parts = normalized.Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) throw new InvalidOperationException("Vault secret path must be in '<mount>/<path>' format, for example secret/certificates/example.com.");
        var path = parts[1].StartsWith("data/", StringComparison.OrdinalIgnoreCase) ? parts[1].Substring(5) : parts[1];
        return (parts[0], path);
    }

    private static void ValidateCreate(CertificateRequestCreateRequest input)
    {
        if (string.IsNullOrWhiteSpace(input.Domain)) throw new ArgumentException("Domain is required.");
        if (input.AcmeProviderId == Guid.Empty) throw new ArgumentException("ACME provider is required.");
        if (input.VaultServerId == Guid.Empty) throw new ArgumentException("Vault server is required.");
        if (input.RequestType == CertificateRequestType.Wildcard)
        {
            _ = NormalizeWildcardBaseDomain(input.Domain);
        }
        if (input.ScheduleCheck)
        {
            if (input.ThresholdDays < 1 || input.ThresholdDays > 365) throw new ArgumentException("Threshold must be between 1 and 365 days.");
            _ = CronSchedule.Parse(input.CronExpression);
        }
    }

    private async Task EnsureRequestDependenciesAsync(CertificateRequestCreateRequest input, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.FirstOrDefaultAsync(x => x.Id == input.AcmeProviderId && x.IsEnabled, cancellationToken)
            ?? throw new InvalidOperationException("Enabled ACME provider was not found.");
        if (!string.IsNullOrWhiteSpace(provider.ExternalAccountBindingKeyId) || !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey))
        {
            throw new InvalidOperationException("External Account Binding ACME providers are registered but issuance support for EAB is not implemented yet.");
        }

        _ = await db.VaultServers.FirstOrDefaultAsync(x => x.Id == input.VaultServerId && x.IsEnabled, cancellationToken)
            ?? throw new InvalidOperationException("Enabled Vault server was not found.");
        if (input.DnsProviderId is not null && input.DnsProviderId != Guid.Empty)
        {
            _ = await db.DnsProviders.FirstOrDefaultAsync(x => x.Id == input.DnsProviderId && x.IsEnabled, cancellationToken)
                ?? throw new InvalidOperationException("Enabled DNS provider was not found.");
        }
    }

    private static string NormalizeDomain(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static string NormalizeCronExpression(string value) => string.IsNullOrWhiteSpace(value) ? "0 0 * * *" : CronSchedule.Parse(value).Expression;
    private static (string Domain, string? SubjectAlternativeNames) NormalizeRequestNames(CertificateRequestCreateRequest input)
    {
        var domain = NormalizeDomain(input.Domain);
        var sans = NormalizeSans(input.SubjectAlternativeNames);
        if (input.RequestType == CertificateRequestType.Wildcard)
        {
            var baseDomain = NormalizeWildcardBaseDomain(domain);
            domain = $"*.{baseDomain}";
            sans = MergeSans(baseDomain, sans);
        }

        return (domain, sans);
    }

    private static string? NormalizeSans(string? value) => string.IsNullOrWhiteSpace(value) ? null : string.Join(", ", value.Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(NormalizeDomain).Distinct(StringComparer.OrdinalIgnoreCase));
    private static string NormalizeWildcardBaseDomain(string value)
    {
        var domain = NormalizeDomain(value);
        if (domain.StartsWith("*.", StringComparison.Ordinal)) domain = domain.Substring(2);
        if (domain.Contains('*', StringComparison.Ordinal)) throw new ArgumentException("Wildcard can only be the entire left-most DNS label.");
        if (!domain.Contains('.', StringComparison.Ordinal)) throw new ArgumentException("Wildcard base domain must include a registrable domain, for example example.com.");
        return domain;
    }

    private static string MergeSans(string value, string? existing)
    {
        var names = new List<string> { NormalizeDomain(value) };
        if (!string.IsNullOrWhiteSpace(existing))
        {
            names.AddRange(existing.Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(NormalizeDomain));
        }

        return string.Join(", ", names.Distinct(StringComparer.OrdinalIgnoreCase));
    }
    private static string NormalizeVaultPath(string? value, string domain) => string.IsNullOrWhiteSpace(value) ? $"secret/certificates/{domain}" : value.Trim().Trim('/');
    private static string ToDnsTxtName(string domain) => $"_acme-challenge.{domain.TrimStart('*').TrimStart('.')}";
    private static string ToAcmeContact(string email) => email.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? email.Trim() : $"mailto:{email.Trim()}";
    private static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));
    private static string PemEncode(X509Certificate2 certificate) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    private static int? GetPublicKeySize(X509Certificate2 certificate) => certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize ?? certificate.GetDSAPublicKey()?.KeySize;

    private static CertificateRequestListDto ToListDto(AcmeCertificateRequest request) =>
        new(request.Id, request.Domain, request.SubjectAlternativeNames, request.Status, request.AcmeProvider?.Name ?? "-", request.VaultServer?.Name ?? "-", request.VaultSecretPath, request.DnsProvider?.Name, request.CreatedAtUtc, request.IssuedAtUtc, request.StoredAtUtc, request.ScheduleCheck, request.RenewalThresholdDays, request.RenewalCronExpression, request.NextScheduleCheckAtUtc, request.LastScheduleCheckAtUtc, request.LastScheduleCheckStatus, request.LastScheduleCheckMessage, request.LastRenewalRequestId, request.ErrorMessage);

    private static CertificateRequestDetailDto ToDetailDto(AcmeCertificateRequest request) =>
        new(request.Id, request.Domain, GetDomains(request), request.SubjectAlternativeNames, request.ChallengeType, request.Status, request.AcmeProviderId, request.AcmeProvider?.Name ?? "-", request.AcmeProvider?.DirectoryUrl ?? new Uri("https://example.com"), request.VaultServerId, request.VaultServer?.Name ?? "-", request.DnsProviderId, request.DnsProvider?.Name, request.VaultSecretPath, request.DnsTxtName, request.DnsTxtValue, request.AcmeOrderLocation, request.CertificatePem, request.FullChainPem, request.ErrorMessage, request.DnsPublishedAtUtc, request.DnsPublishStatus, request.DnsPublishError, request.CertificateId, request.CreatedAtUtc, request.ChallengeCreatedAtUtc, request.IssuedAtUtc, request.StoredAtUtc, request.ScheduleCheck, request.RenewalThresholdDays, request.RenewalCronExpression, request.NextScheduleCheckAtUtc, request.LastScheduleCheckAtUtc, request.LastScheduleCheckStatus, request.LastScheduleCheckMessage, request.RenewedFromRequestId, request.LastRenewalRequestId);

    private static VaultServerDto ToDto(VaultServer server) =>
        new(server.Id, server.Name, server.BaseUrl, server.Description, server.PkiMountPath, !string.IsNullOrWhiteSpace(server.Token), server.ScanPublicEndpoint, server.ImportPkiCertificates, server.IsEnabled, server.CreatedAtUtc, server.UpdatedAtUtc, server.LastSyncAtUtc, server.LastSyncStatus, server.LastSyncError);

    private static AcmeProviderDto ToDto(AcmeProvider provider) =>
        new(provider.Id, provider.Name, provider.ProviderType, provider.DirectoryUrl, provider.AccountEmail, !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingKeyId) || !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey), provider.IsStaging, provider.IsEnabled, provider.Notes, provider.CreatedAtUtc, provider.UpdatedAtUtc);

    private static DnsProviderDto ToDto(DnsProvider provider) =>
        new(provider.Id, provider.Name, provider.ProviderType, provider.ZoneName, !string.IsNullOrWhiteSpace(provider.ApiToken), provider.IsEnabled, provider.Notes, provider.CreatedAtUtc, provider.UpdatedAtUtc);

    private sealed class CronSchedule
    {
        private readonly HashSet<int>? minutes;
        private readonly HashSet<int>? hours;
        private readonly HashSet<int>? days;
        private readonly HashSet<int>? months;
        private readonly HashSet<int>? dayOfWeeks;

        private CronSchedule(string expression, HashSet<int>? minutes, HashSet<int>? hours, HashSet<int>? days, HashSet<int>? months, HashSet<int>? dayOfWeeks)
        {
            Expression = expression;
            this.minutes = minutes;
            this.hours = hours;
            this.days = days;
            this.months = months;
            this.dayOfWeeks = dayOfWeeks;
        }

        public string Expression { get; }

        public static CronSchedule Parse(string? expression)
        {
            var normalized = string.IsNullOrWhiteSpace(expression) ? "0 0 * * *" : string.Join(' ', expression.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            var parts = normalized.Split(' ');
            if (parts.Length != 5) throw new ArgumentException("Cron expression must have 5 fields: minute hour day month day-of-week.");

            return new CronSchedule(
                normalized,
                ParseField(parts[0], 0, 59, "minute"),
                ParseField(parts[1], 0, 23, "hour"),
                ParseField(parts[2], 1, 31, "day"),
                ParseField(parts[3], 1, 12, "month"),
                ParseField(parts[4], 0, 7, "day-of-week"));
        }

        public DateTime GetNext(DateTime afterUtc)
        {
            var candidate = new DateTime(afterUtc.Year, afterUtc.Month, afterUtc.Day, afterUtc.Hour, afterUtc.Minute, 0, DateTimeKind.Utc).AddMinutes(1);
            var limit = afterUtc.AddDays(366);
            while (candidate <= limit)
            {
                var dayOfWeek = (int)candidate.DayOfWeek;
                if (Matches(minutes, candidate.Minute) &&
                    Matches(hours, candidate.Hour) &&
                    Matches(days, candidate.Day) &&
                    Matches(months, candidate.Month) &&
                    (Matches(dayOfWeeks, dayOfWeek) || dayOfWeek == 0 && Matches(dayOfWeeks, 7)))
                {
                    return candidate;
                }

                candidate = candidate.AddMinutes(1);
            }

            throw new ArgumentException("Cron expression did not produce a run time within the next year.");
        }

        private static HashSet<int>? ParseField(string value, int min, int max, string name)
        {
            if (value == "*") return null;
            var values = new HashSet<int>();
            foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!int.TryParse(part, out var parsed) || parsed < min || parsed > max)
                {
                    throw new ArgumentException($"Cron {name} field contains an invalid value.");
                }

                values.Add(parsed);
            }

            return values.Count == 0 ? throw new ArgumentException($"Cron {name} field is empty.") : values;
        }

        private static bool Matches(HashSet<int>? values, int value) => values is null || values.Contains(value);
    }
}
