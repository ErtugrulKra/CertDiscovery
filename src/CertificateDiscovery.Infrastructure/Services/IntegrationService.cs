namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class IntegrationService(CertificateDiscoveryDbContext db, VaultCertificateImportService vaultImport)
{
    public async Task<IntegrationIndexDto> GetIndexAsync(CancellationToken cancellationToken) =>
        new(
            await db.VaultServers.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            await db.AcmeProviders.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
            await db.DnsProviders.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken));

    public async Task<VaultServerDto?> GetVaultAsync(Guid id, CancellationToken cancellationToken)
    {
        var server = await db.VaultServers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return server is null ? null : ToDto(server);
    }

    public async Task<AcmeProviderDto?> GetAcmeAsync(Guid id, CancellationToken cancellationToken)
    {
        var provider = await db.AcmeProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
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
        var name = request.Name.Trim();
        if (await db.AcmeProviders.AnyAsync(x => x.Name == name, cancellationToken)) throw new InvalidOperationException("An ACME provider with the same name already exists.");
        db.AcmeProviders.Add(new AcmeProvider
        {
            Name = name,
            ProviderType = request.ProviderType,
            DirectoryUrl = new Uri(request.DirectoryUrl.Trim()),
            AccountEmail = request.AccountEmail.Trim(),
            ExternalAccountBindingKeyId = Normalize(request.ExternalAccountBindingKeyId),
            ExternalAccountBindingHmacKey = Normalize(request.ExternalAccountBindingHmacKey),
            IsStaging = request.IsStaging,
            IsEnabled = request.IsEnabled,
            Notes = Normalize(request.Notes)
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> UpdateAcmeAsync(Guid id, AcmeProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateAcme(request);
        var provider = await db.AcmeProviders.FindAsync([id], cancellationToken);
        if (provider is null) return false;
        var name = request.Name.Trim();
        if (await db.AcmeProviders.AnyAsync(x => x.Id != id && x.Name == name, cancellationToken)) throw new InvalidOperationException("An ACME provider with the same name already exists.");

        provider.Name = name;
        provider.ProviderType = request.ProviderType;
        provider.DirectoryUrl = new Uri(request.DirectoryUrl.Trim());
        provider.AccountEmail = request.AccountEmail.Trim();
        provider.ExternalAccountBindingKeyId = Normalize(request.ExternalAccountBindingKeyId);
        if (!string.IsNullOrWhiteSpace(request.ExternalAccountBindingHmacKey)) provider.ExternalAccountBindingHmacKey = request.ExternalAccountBindingHmacKey.Trim();
        provider.IsStaging = request.IsStaging;
        provider.IsEnabled = request.IsEnabled;
        provider.Notes = Normalize(request.Notes);
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

    public async Task CreateDnsAsync(DnsProviderUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateDns(request);
        var name = request.Name.Trim();
        if (await db.DnsProviders.AnyAsync(x => x.Name == name, cancellationToken)) throw new InvalidOperationException("A DNS provider with the same name already exists.");
        db.DnsProviders.Add(new DnsProvider
        {
            Name = name,
            ProviderType = request.ProviderType,
            ZoneName = NormalizeZone(request.ZoneName),
            ApiToken = Normalize(request.ApiToken),
            IsEnabled = request.IsEnabled,
            Notes = Normalize(request.Notes)
        });
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
        if (!string.IsNullOrWhiteSpace(request.ApiToken)) provider.ApiToken = request.ApiToken.Trim();
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
        db.DnsProviders.Remove(provider);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static VaultServerDto ToDto(VaultServer server) =>
        new(server.Id, server.Name, server.BaseUrl, server.Description, server.PkiMountPath, !string.IsNullOrWhiteSpace(server.Token), server.ScanPublicEndpoint, server.ImportPkiCertificates, server.IsEnabled, server.CreatedAtUtc, server.UpdatedAtUtc, server.LastSyncAtUtc, server.LastSyncStatus, server.LastSyncError);

    private static AcmeProviderDto ToDto(AcmeProvider provider) =>
        new(provider.Id, provider.Name, provider.ProviderType, provider.DirectoryUrl, provider.AccountEmail, !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingKeyId) || !string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey), provider.IsStaging, provider.IsEnabled, provider.Notes, provider.CreatedAtUtc, provider.UpdatedAtUtc);

    private static DnsProviderDto ToDto(DnsProvider provider) =>
        new(provider.Id, provider.Name, provider.ProviderType, provider.ZoneName, !string.IsNullOrWhiteSpace(provider.ApiToken), provider.IsEnabled, provider.Notes, provider.CreatedAtUtc, provider.UpdatedAtUtc);

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

    private static void ValidateDns(DnsProviderUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("DNS provider name is required.");
        if (string.IsNullOrWhiteSpace(request.ZoneName)) throw new ArgumentException("DNS zone name is required.");
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    private static string? NormalizePath(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim().Trim('/');
    private static string NormalizeZone(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
}
