namespace CertificateDiscovery.Infrastructure.Persistence;

using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using Microsoft.EntityFrameworkCore;

public static class DevelopmentSeeder
{
    public static async Task SeedAsync(CertificateDiscoveryDbContext db, CancellationToken cancellationToken)
    {
        if (await db.Assets.AnyAsync(cancellationToken)) return;

        db.Assets.AddRange(
            new Asset { Name = "Google HTTPS", Host = "google.com", Port = 443, Protocol = AssetProtocol.HTTPS, Environment = AssetEnvironment.Production, AssetType = AssetType.WebApplication, Owner = "Platform", NextScanAtUtc = DateTime.UtcNow },
            new Asset { Name = "Cloudflare HTTPS", Host = "cloudflare.com", Port = 443, Protocol = AssetProtocol.HTTPS, Environment = AssetEnvironment.Production, AssetType = AssetType.WebApplication, Owner = "Platform", NextScanAtUtc = DateTime.UtcNow },
            new Asset { Name = "Invalid Local Test", Host = "invalid.local", Port = 443, Protocol = AssetProtocol.HTTPS, Environment = AssetEnvironment.Test, AssetType = AssetType.Other, Owner = "QA", NextScanAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(cancellationToken);
    }
}
