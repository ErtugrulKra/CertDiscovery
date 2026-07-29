namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class IntegrationService(
    CertificateDiscoveryDbContext db,
    VaultCertificateImportService vaultImport,
    ISecretProvider secretProvider,
    IAcmeAccountService acmeAccountService,
    IAcmeCertificateClient acmeClient,
    IDnsChallengeProviderResolver dnsProviderResolver)
{
    public async Task<IntegrationIndexDto> GetIndexAsync(CancellationToken cancellationToken) =>
        new(
            await db.VaultServers.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            (await db.AcmeProviders.AsNoTracking().Include(x => x.Accounts).OrderBy(x => x.Name).ToListAsync(cancellationToken)).Select(ToDto).ToList(),
            await db.DnsProviders.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            await db.KubernetesClusters.AsNoTracking().OrderBy(x => x.Name)
                .Select(x => new KubernetesClusterDto(
                    x.Id, x.Name, x.ApiServer, x.Description, x.Namespaces,
                    x.BearerTokenSecretReference != null, x.IsEnabled, x.CreatedAtUtc,
                    x.UpdatedAtUtc, x.LastSyncAtUtc, x.LastSyncStatus, x.LastSyncError))
                .ToListAsync(cancellationToken));

    public async Task<VaultServerDto?> GetVaultAsync(Guid id, CancellationToken cancellationToken)
    {
        var server = await db.VaultServers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return server is null ? null : ToDto(server);
    }

    public async Task<AcmeProviderDto?> GetAcmeAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.AsNoTracking().Include(x => x.Accounts).FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return provider is null ? null : ToDto(provider);
    }

    public async Task<DnsProviderDto?> GetDnsAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.DnsProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return provider is null ? null : ToDto(provider);
    }

    public async Task CreateVaultAsync(VaultServerUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateVault(request);
        var name = request.Name.Trim();
        if (await db.VaultServers.AnyAsync(x => x.Name == name, cancellationToken)) throw new InvalidOperationException("A Vault server with the same name already exists.");
        db.VaultServers.Add(new VaultServer
        {
            Name = name,
            BaseUrl = new Uri(request.BaseUrl.Trim()),
            Description = Normalize(request.Description),
            PkiMountPath = NormalizePath(request.PkiMountPath),
            Token = Normalize(request.Token),
            ScanPublicEndpoint = request.ScanPublicEndpoint,
            ImportPkiCertificates = request.ImportPkiCertificates,
            IsEnabled = request.IsEnabled
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> UpdateVaultAsync(Guid id, VaultServerUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateVault(request);
        var server = await db.VaultServers.FindAsync([id], cancellationToken);
        if (server is null) return false;
        var name = request.Name.Trim();
        if (await db.VaultServers.AnyAsync(x => x.Id != id && x.Name == name, cancellationToken)) throw new InvalidOperationException("A Vault server with the same name already exists.");

        server.Name = name;
        server.BaseUrl = new Uri(request.BaseUrl.Trim());
        server.Description = Normalize(request.Description);
        server.PkiMountPath = NormalizePath(request.PkiMountPath);
        if (!string.IsNullOrWhiteSpace(request.Token)) server.Token = request.Token.Trim();
        server.ScanPublicEndpoint = request.ScanPublicEndpoint;
        server.ImportPkiCertificates = request.ImportPkiCertificates;
        server.IsEnabled = request.IsEnabled;
        server.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteVaultAsync(Guid id, CancellationToken cancellationToken)
    {
        var server = await db.VaultServers.FindAsync([id], cancellationToken);
        if (server is null) return false;
        db.VaultServers.Remove(server);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<int?> ScanVaultPublicEndpointAsync(Guid id, CancellationToken cancellationToken)
    {
        var server = await db.VaultServers.FindAsync([id], cancellationToken);
        if (server is null) return null;
        return await vaultImport.ImportPublicEndpointAsync(server, cancellationToken);
    }

    public async Task<int?> ImportVaultPkiAsync(Guid id, CancellationToken cancellationToken)
    {
        var server = await db.VaultServers.FindAsync([id], cancellationToken);
        if (server is null) return null;
        return await vaultImport.ImportPkiCertificatesAsync(server, cancellationToken);
    }

    public async Task CreateAcmeAsync(AcmeProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateAcme(request);
        ValidateEabConfiguration(request.ProviderType, request.ExternalAccountBindingKeyId, request.ExternalAccountBindingHmacKey, hasStoredHmac: false);
        var name = request.Name.Trim();
        if (await db.AcmeProviders.AnyAsync(x => x.Name == name, cancellationToken)) throw new InvalidOperationException("An ACME provider with the same name already exists.");
        var provider = new AcmeProvider
        {
            Name = name,
            ProviderType = request.ProviderType,
            DirectoryUrl = new Uri(request.DirectoryUrl.Trim()),
            AccountEmail = request.AccountEmail.Trim(),
            ExternalAccountBindingKeyId = Normalize(request.ExternalAccountBindingKeyId),
            ExternalAccountBindingHmacKey = null,
            IsStaging = request.IsStaging,
            IsEnabled = request.IsEnabled,
            Notes = Normalize(request.Notes),
            Organization = Normalize(request.Organization),
            Department = Normalize(request.Department),
            CertificateProfile = Normalize(request.CertificateProfile),
            ProductType = Normalize(request.ProductType),
            AllowedDomainPattern = Normalize(request.AllowedDomainPattern)
        };
        if (!string.IsNullOrWhiteSpace(request.ExternalAccountBindingHmacKey))
        {
            provider.ExternalAccountBindingHmacSecretReference = await secretProvider.StoreAsync(
                $"acme-eab-hmac:{provider.Id:D}",
                request.ExternalAccountBindingHmacKey.Trim(),
                cancellationToken);
        }
        db.AcmeProviders.Add(provider);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> UpdateAcmeAsync(Guid id, AcmeProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateAcme(request);
        var provider = await db.AcmeProviders.FindAsync([id], cancellationToken);
        if (provider is null) return false;
        ValidateEabConfiguration(
            request.ProviderType,
            request.ExternalAccountBindingKeyId,
            request.ExternalAccountBindingHmacKey,
            !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacSecretReference) || !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey));
        var name = request.Name.Trim();
        if (await db.AcmeProviders.AnyAsync(x => x.Id != id && x.Name == name, cancellationToken)) throw new InvalidOperationException("An ACME provider with the same name already exists.");

        provider.Name = name;
        provider.ProviderType = request.ProviderType;
        provider.DirectoryUrl = new Uri(request.DirectoryUrl.Trim());
        provider.AccountEmail = request.AccountEmail.Trim();
        provider.ExternalAccountBindingKeyId = Normalize(request.ExternalAccountBindingKeyId);
        if (!string.IsNullOrWhiteSpace(request.ExternalAccountBindingHmacKey))
        {
            var previousReference = provider.ExternalAccountBindingHmacSecretReference;
            provider.ExternalAccountBindingHmacSecretReference = await secretProvider.StoreAsync(
                $"acme-eab-hmac:{provider.Id:D}",
                request.ExternalAccountBindingHmacKey.Trim(),
                cancellationToken);
            provider.ExternalAccountBindingHmacKey = null;
            if (!string.IsNullOrWhiteSpace(previousReference))
            {
                await secretProvider.DeleteAsync(previousReference, cancellationToken);
            }
        }
        else if (string.IsNullOrWhiteSpace(request.ExternalAccountBindingKeyId) &&
                 !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacSecretReference))
        {
            await secretProvider.DeleteAsync(provider.ExternalAccountBindingHmacSecretReference, cancellationToken);
            provider.ExternalAccountBindingHmacSecretReference = null;
            provider.ExternalAccountBindingHmacKey = null;
        }
        provider.IsStaging = request.IsStaging;
        provider.IsEnabled = request.IsEnabled;
        provider.Notes = Normalize(request.Notes);
        provider.Organization = Normalize(request.Organization);
        provider.Department = Normalize(request.Department);
        provider.CertificateProfile = Normalize(request.CertificateProfile);
        provider.ProductType = Normalize(request.ProductType);
        provider.AllowedDomainPattern = Normalize(request.AllowedDomainPattern);
        provider.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteAcmeAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.FindAsync([id], cancellationToken);
        if (provider is null) return false;
        db.AcmeProviders.Remove(provider);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task TestAcmeDirectoryAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("ACME provider was not found.");
        await acmeClient.TestDirectoryAsync(provider, cancellationToken);
    }

    public async Task<Guid> RegisterAcmeAccountAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("ACME provider was not found.");
        return (await acmeAccountService.GetOrCreateAsync(provider, cancellationToken)).AccountId;
    }

    public async Task TestAcmeAccountAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("ACME provider was not found.");
        var account = await db.AcmeAccounts.AsNoTracking()
            .FirstOrDefaultAsync(x => x.AcmeProviderId == id && x.Status == AcmeAccountStatus.Active, cancellationToken)
            ?? throw new InvalidOperationException("This provider has no active ACME account.");
        var credentials = await acmeAccountService.GetCredentialsAsync(account.Id, cancellationToken);
        await acmeClient.TestAccountAsync(provider, credentials, cancellationToken);
    }

    public async Task DisableAcmeAccountAsync(Guid id, CancellationToken cancellationToken)
    {
        var account = await db.AcmeAccounts.AsNoTracking()
            .FirstOrDefaultAsync(x => x.AcmeProviderId == id && x.Status == AcmeAccountStatus.Active, cancellationToken)
            ?? throw new InvalidOperationException("This provider has no active ACME account.");
        await acmeAccountService.DisableAsync(account.Id, cancellationToken);
    }

    public async Task RotateAcmeAccountKeyAsync(Guid id, CancellationToken cancellationToken)
    {
        var account = await db.AcmeAccounts.AsNoTracking()
            .FirstOrDefaultAsync(x => x.AcmeProviderId == id && x.Status == AcmeAccountStatus.Active, cancellationToken)
            ?? throw new InvalidOperationException("This provider has no active ACME account.");
        await acmeAccountService.RotateKeyAsync(account.Id, cancellationToken);
    }

    public async Task CreateDnsAsync(DnsProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateDns(request);
        var name = request.Name.Trim();
        if (await db.DnsProviders.AnyAsync(x => x.Name == name, cancellationToken)) throw new InvalidOperationException("A DNS provider with the same name already exists.");
        var provider = new DnsProvider
        {
            Name = name,
            ProviderType = request.ProviderType,
            ZoneName = NormalizeZone(request.ZoneName),
            IsEnabled = request.IsEnabled,
            Notes = Normalize(request.Notes)
        };
        ApplyDnsConfiguration(provider, request);
        provider.ApiTokenSecretReference = await StoreDnsSecretAsync(provider, "cloudflare-token", request.ApiToken, cancellationToken);
        provider.AccessKeySecretReference = await StoreDnsSecretAsync(provider, "aws-access-key", request.AwsAccessKey, cancellationToken);
        provider.SecretKeySecretReference = await StoreDnsSecretAsync(provider, "aws-secret-key", request.AwsSecretKey, cancellationToken);
        provider.SessionTokenSecretReference = await StoreDnsSecretAsync(provider, "aws-session-token", request.AwsSessionToken, cancellationToken);
        provider.ClientSecretReference = await StoreDnsSecretAsync(provider, "azure-client-secret", request.AzureClientSecret, cancellationToken);
        db.DnsProviders.Add(provider);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> UpdateDnsAsync(Guid id, DnsProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateDns(request);
        var provider = await db.DnsProviders.FindAsync([id], cancellationToken);
        if (provider is null) return false;
        var name = request.Name.Trim();
        if (await db.DnsProviders.AnyAsync(x => x.Id != id && x.Name == name, cancellationToken)) throw new InvalidOperationException("A DNS provider with the same name already exists.");

        provider.Name = name;
        provider.ProviderType = request.ProviderType;
        provider.ZoneName = NormalizeZone(request.ZoneName);
        provider.ApiTokenSecretReference = await ReplaceDnsSecretAsync(provider, "cloudflare-token", provider.ApiTokenSecretReference, request.ApiToken, cancellationToken);
        provider.AccessKeySecretReference = await ReplaceDnsSecretAsync(provider, "aws-access-key", provider.AccessKeySecretReference, request.AwsAccessKey, cancellationToken);
        provider.SecretKeySecretReference = await ReplaceDnsSecretAsync(provider, "aws-secret-key", provider.SecretKeySecretReference, request.AwsSecretKey, cancellationToken);
        provider.SessionTokenSecretReference = await ReplaceDnsSecretAsync(provider, "aws-session-token", provider.SessionTokenSecretReference, request.AwsSessionToken, cancellationToken);
        provider.ClientSecretReference = await ReplaceDnsSecretAsync(provider, "azure-client-secret", provider.ClientSecretReference, request.AzureClientSecret, cancellationToken);
        ApplyDnsConfiguration(provider, request);
        provider.IsEnabled = request.IsEnabled;
        provider.Notes = Normalize(request.Notes);
        provider.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteDnsAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.DnsProviders.FindAsync([id], cancellationToken);
        if (provider is null) return false;
        foreach (var reference in new[] { provider.ApiTokenSecretReference, provider.AccessKeySecretReference, provider.SecretKeySecretReference, provider.SessionTokenSecretReference, provider.ClientSecretReference })
        {
            if (!string.IsNullOrWhiteSpace(reference)) await secretProvider.DeleteAsync(reference, cancellationToken);
        }
        db.DnsProviders.Remove(provider);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task TestDnsAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.DnsProviders.FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("DNS provider was not found.");
        var implementation = dnsProviderResolver.Resolve(provider.ProviderType);
        var challenge = new DnsTxtChallenge(
            $"_certdiscovery-health-{Guid.NewGuid():N}.{provider.ZoneName}",
            $"certdiscovery-{Guid.NewGuid():N}");
        try
        {
            await implementation.ValidateConfigurationAsync(provider, cancellationToken);
            await implementation.PublishAsync(provider, [challenge], cancellationToken);
            var propagation = await implementation.WaitForPropagationAsync(provider, [challenge], cancellationToken);
            if (!propagation.IsPropagated) throw new TimeoutException(propagation.Message);
            provider.LastHealthCheckStatus = "Healthy";
            provider.LastHealthCheckError = null;
        }
        catch (Exception ex)
        {
            provider.LastHealthCheckStatus = "Failed";
            provider.LastHealthCheckError = ex.Message;
            throw;
        }
        finally
        {
            try { await implementation.CleanupAsync(provider, [challenge], cancellationToken); }
            catch (Exception cleanupError)
            {
                provider.LastHealthCheckStatus = "CleanupFailed";
                provider.LastHealthCheckError = cleanupError.Message;
            }
            provider.LastHealthCheckAtUtc = DateTime.UtcNow;
            provider.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private static VaultServerDto ToDto(VaultServer server) =>
        new(server.Id, server.Name, server.BaseUrl, server.Description, server.PkiMountPath, !string.IsNullOrWhiteSpace(server.Token), server.ScanPublicEndpoint, server.ImportPkiCertificates, server.IsEnabled, server.CreatedAtUtc, server.UpdatedAtUtc, server.LastSyncAtUtc, server.LastSyncStatus, server.LastSyncError);

    private static AcmeProviderDto ToDto(AcmeProvider provider)
    {
        var account = provider.Accounts.FirstOrDefault(x => x.Status == AcmeAccountStatus.Active);
        return new(
            provider.Id,
            provider.Name,
            provider.ProviderType,
            provider.DirectoryUrl,
            provider.AccountEmail,
            !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingKeyId) &&
            (!string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacSecretReference) || !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey)),
            provider.IsStaging,
            provider.IsEnabled,
            provider.Notes,
            provider.CreatedAtUtc,
            provider.UpdatedAtUtc,
            provider.Organization,
            provider.Department,
            provider.CertificateProfile,
            provider.ProductType,
            provider.AllowedDomainPattern,
            account?.Id,
            account?.Status,
            account?.LastUsedAtUtc);
    }

    private static DnsProviderDto ToDto(DnsProvider provider) =>
        new(provider.Id, provider.Name, provider.ProviderType, provider.ZoneName,
            !string.IsNullOrWhiteSpace(provider.ApiTokenSecretReference) || !string.IsNullOrWhiteSpace(provider.ApiToken),
            provider.IsEnabled, provider.Notes, provider.CreatedAtUtc, provider.UpdatedAtUtc,
            provider.HostedZoneId, provider.AwsAuthenticationMode,
            !string.IsNullOrWhiteSpace(provider.AccessKeySecretReference),
            !string.IsNullOrWhiteSpace(provider.SecretKeySecretReference),
            !string.IsNullOrWhiteSpace(provider.SessionTokenSecretReference),
            provider.RoleArn, provider.Region, provider.AzureAuthenticationMode, provider.TenantId,
            provider.SubscriptionId, provider.ResourceGroup, provider.ClientId,
            !string.IsNullOrWhiteSpace(provider.ClientSecretReference), provider.ManagedIdentityClientId,
            provider.TtlSeconds, provider.PropagationTimeoutSeconds, provider.PropagationPollingIntervalSeconds,
            provider.LastHealthCheckAtUtc, provider.LastHealthCheckStatus, provider.LastHealthCheckError);

    private static void ValidateVault(VaultServerUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Vault name is required.");
        if (!Uri.TryCreate(request.BaseUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) throw new ArgumentException("Vault URL must be an absolute http or https URL.");
    }

    private static void ValidateAcme(AcmeProviderUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("ACME provider name is required.");
        if (string.IsNullOrWhiteSpace(request.AccountEmail)) throw new ArgumentException("Account email is required.");
        if (!Uri.TryCreate(request.DirectoryUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) throw new ArgumentException("Directory URL must be an absolute http or https URL.");
    }

    private static void ValidateEabConfiguration(AcmeProviderType providerType, string? keyId, string? hmac, bool hasStoredHmac)
    {
        var hasKeyId = !string.IsNullOrWhiteSpace(keyId);
        var hasHmac = !string.IsNullOrWhiteSpace(hmac) || hasKeyId && hasStoredHmac;
        if (hasKeyId != hasHmac)
        {
            throw new ArgumentException("EAB Key ID and HMAC key must be configured together.");
        }

        if (providerType == AcmeProviderType.Sectigo && (!hasKeyId || !hasHmac))
        {
            throw new ArgumentException("Sectigo providers require an EAB Key ID and HMAC key.");
        }
    }

    private static void ValidateDns(DnsProviderUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("DNS provider name is required.");
        if (string.IsNullOrWhiteSpace(request.ZoneName)) throw new ArgumentException("DNS zone name is required.");
        if (request.TtlSeconds is < 30 or > 86400) throw new ArgumentException("DNS TTL must be between 30 and 86400 seconds.");
        if (request.PropagationTimeoutSeconds is < 10 or > 3600) throw new ArgumentException("Propagation timeout must be between 10 and 3600 seconds.");
        if (request.PropagationPollingIntervalSeconds is < 1 or > 300) throw new ArgumentException("Propagation polling interval must be between 1 and 300 seconds.");
        if (request.ProviderType == DnsProviderType.Route53 &&
            request.AwsAuthenticationMode == AwsDnsAuthenticationMode.AssumeRole &&
            string.IsNullOrWhiteSpace(request.RoleArn))
            throw new ArgumentException("AWS assume-role authentication requires a role ARN.");
        if (request.ProviderType == DnsProviderType.AzureDns &&
            (string.IsNullOrWhiteSpace(request.SubscriptionId) || string.IsNullOrWhiteSpace(request.ResourceGroup)))
            throw new ArgumentException("Azure DNS requires subscription ID and resource group.");
    }

    private static void ApplyDnsConfiguration(DnsProvider provider, DnsProviderUpsertRequest request)
    {
        provider.HostedZoneId = Normalize(request.HostedZoneId);
        provider.AwsAuthenticationMode = request.AwsAuthenticationMode;
        provider.RoleArn = Normalize(request.RoleArn);
        provider.Region = Normalize(request.Region);
        provider.AzureAuthenticationMode = request.AzureAuthenticationMode;
        provider.TenantId = Normalize(request.TenantId);
        provider.SubscriptionId = Normalize(request.SubscriptionId);
        provider.ResourceGroup = Normalize(request.ResourceGroup);
        provider.ClientId = Normalize(request.ClientId);
        provider.ManagedIdentityClientId = Normalize(request.ManagedIdentityClientId);
        provider.TtlSeconds = request.TtlSeconds;
        provider.PropagationTimeoutSeconds = request.PropagationTimeoutSeconds;
        provider.PropagationPollingIntervalSeconds = request.PropagationPollingIntervalSeconds;
        provider.ApiToken = null;
    }

    private async Task<string?> StoreDnsSecretAsync(DnsProvider provider, string kind, string? value, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : await secretProvider.StoreAsync($"dns-{kind}:{provider.Id:D}", value.Trim(), cancellationToken);

    private async Task<string?> ReplaceDnsSecretAsync(DnsProvider provider, string kind, string? currentReference, string? value, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(value)) return currentReference;
        var replacement = await StoreDnsSecretAsync(provider, kind, value, cancellationToken);
        if (!string.IsNullOrWhiteSpace(currentReference)) await secretProvider.DeleteAsync(currentReference, cancellationToken);
        return replacement;
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    private static string? NormalizePath(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim().Trim('/');
    private static string NormalizeZone(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
}
