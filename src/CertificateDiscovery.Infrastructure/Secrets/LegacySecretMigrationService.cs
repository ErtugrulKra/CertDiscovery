using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Secrets;

public sealed class LegacySecretMigrationService(
    CertificateDiscoveryDbContext db,
    ISecretProvider secretProvider)
{
    public async Task MigrateAsync(CancellationToken cancellationToken)
    {
        var providers = await db.AcmeProviders
            .Where(x => x.ExternalAccountBindingHmacKey != null &&
                        x.ExternalAccountBindingHmacKey != "" &&
                        x.ExternalAccountBindingHmacSecretReference == null)
            .ToListAsync(cancellationToken);
        foreach (var provider in providers)
        {
            provider.ExternalAccountBindingHmacSecretReference = await secretProvider.StoreAsync(
                $"acme-eab-hmac:{provider.Id:D}",
                provider.ExternalAccountBindingHmacKey!,
                cancellationToken);
            provider.ExternalAccountBindingHmacKey = null;
            provider.UpdatedAtUtc = DateTime.UtcNow;
        }

        var dnsProviders = await db.DnsProviders
            .Where(x => x.ApiToken != null && x.ApiToken != "" && x.ApiTokenSecretReference == null)
            .ToListAsync(cancellationToken);
        foreach (var provider in dnsProviders)
        {
            provider.ApiTokenSecretReference = await secretProvider.StoreAsync(
                $"dns-cloudflare-token:{provider.Id:D}",
                provider.ApiToken!,
                cancellationToken);
            provider.ApiToken = null;
            provider.UpdatedAtUtc = DateTime.UtcNow;
        }

        if (providers.Count > 0 || dnsProviders.Count > 0)
        {
            await db.SaveChangesAsync(cancellationToken);
        }
    }
}
